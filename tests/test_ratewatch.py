"""Offline tests: a fake Cloudflare API on localhost. Run: python3 -m unittest discover -s tests"""
import datetime as dt
import ipaddress
import json
import os
import sys
import tempfile
import threading
import unittest
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import cf_ratewatch as rw  # noqa: E402


class FakeCF:
    def __init__(self):
        self.zones = {"example.com": ("Z1", "A1"), "other.org": ("Z2", "A1")}
        self.hits = {}            # zone id -> [(ip, count)]
        self.rules = {}           # scope path -> {id: rule}
        self.graphql_calls = []
        self.writes = []
        self.budget_left = 99
        self.next_id = 1
        self.post_attempts = 0

    def add_rule(self, sp, value, notes, target="ip", mode="block"):
        if target == "ip_range" and ":" in value:  # Cloudflare stores IPv6 ranges fully expanded
            net = ipaddress.ip_network(value, strict=False)
            value = f"{net.network_address.exploded}/{net.prefixlen}"
        rid = f"r{self.next_id}"
        self.next_id += 1
        self.rules.setdefault(sp, {})[rid] = {"id": rid, "mode": mode, "notes": notes,
                                               "configuration": {"target": target, "value": value}}
        return rid


def make_handler(fake):
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _send(self, code, obj):
            body = json.dumps(obj).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _body(self):
            n = int(self.headers.get("Content-Length") or 0)
            return json.loads(self.rfile.read(n) or b"null")

        def do_GET(self):
            u = urllib.parse.urlparse(self.path)
            q = urllib.parse.parse_qs(u.query)
            if u.path == "/zones":
                name = q["name"][0]
                res = [{"id": fake.zones[name][0], "name": name, "account": {"id": fake.zones[name][1]}}] if name in fake.zones else []
                return self._send(200, {"success": True, "result": res})
            if u.path.endswith("/firewall/access_rules/rules"):
                sp = u.path[: -len("/firewall/access_rules/rules")]
                res = list(fake.rules.get(sp, {}).values())
                return self._send(200, {"success": True, "result": res, "result_info": {"total_pages": 1}})
            self._send(404, {"success": False, "errors": [{"code": 7003, "message": "no route"}]})

        def do_POST(self):
            u = urllib.parse.urlparse(self.path)
            body = self._body()
            if u.path == "/graphql":
                fake.graphql_calls.append(body)
                if fake.budget_left <= 0:
                    return self._send(200, {"data": None, "errors": [{"message": "Rate limiter budget depleted. Please try again after 5 minutes."}]})
                fake.budget_left -= 1
                zone = body["variables"]["zone"]
                groups = [{"count": c, "dimensions": {"clientIP": ip}} for ip, c in fake.hits.get(zone, [])]
                return self._send(200, {"data": {"viewer": {"zones": [{"httpRequestsAdaptiveGroups": groups}]}}, "errors": None})
            if u.path.endswith("/firewall/access_rules/rules"):
                fake.post_attempts += 1
                sp = u.path[: -len("/firewall/access_rules/rules")]
                value = body["configuration"]["value"]
                if any(ipaddress.ip_network(r["configuration"]["value"], strict=False) == ipaddress.ip_network(value, strict=False)
                       for r in fake.rules.get(sp, {}).values()):
                    return self._send(400, {"success": False, "errors": [{"code": 10009, "message": "firewallaccessrules.api.duplicate_of_existing"}]})
                rid = fake.add_rule(sp, value, body["notes"], body["configuration"]["target"], body["mode"])
                fake.writes.append(("POST", sp, value))
                return self._send(200, {"success": True, "result": fake.rules[sp][rid]})
            self._send(404, {"success": False, "errors": [{"message": "no route"}]})

        def do_DELETE(self):
            sp, _, rid = self.path.rpartition("/firewall/access_rules/rules/")
            if rid in fake.rules.get(sp, {}):
                value = fake.rules[sp].pop(rid)["configuration"]["value"]
                fake.writes.append(("DELETE", sp, value))
                return self._send(200, {"success": True, "result": {"id": rid}})
            self._send(404, {"success": False, "errors": [{"message": "not found"}]})

    return H


def write_config(text):
    f = tempfile.NamedTemporaryFile("w", suffix=".toml", delete=False)
    f.write(text)
    f.close()
    return f.name


CONFIG = """
[defaults]
threshold = 1000
allow = ["192.0.2.0/24"]

[[zones]]
name = "example.com"
exclude_paths = ["/adm"]
exclude_extensions = ["jpg"]

[[zones]]
name = "other.org"
threshold = 500
scope = "account"
"""


class RatewatchTest(unittest.TestCase):
    def setUp(self):
        self.fake = FakeCF()
        self.srv = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(self.fake))
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        rw.API = f"http://127.0.0.1:{self.srv.server_address[1]}"
        self.conf = rw.load_config(write_config(CONFIG))
        self.cf = rw.Cloudflare("test-token")

    def tearDown(self):
        self.srv.shutdown()
        self.srv.server_close()

    def note(self, hours_from_now):
        return rw.make_note(rw.utcnow() + dt.timedelta(hours=hours_from_now), "example.com", 1, 60)

    def test_bans_over_threshold_skips_allowlisted_and_lifts_expired(self):
        self.fake.hits["Z1"] = [("203.0.113.9", 5000), ("192.0.2.7", 4000), ("198.51.100.4", 900)]
        old = self.fake.add_rule("/zones/Z1", "198.51.100.200", self.note(-1))
        keep = self.fake.add_rule("/zones/Z1", "198.51.100.201", self.note(+5))
        self.fake.add_rule("/zones/Z1", "198.51.100.202", "manual rule, not ours")
        rw.cmd_run(self.cf, self.conf, dry=False)
        values = {r["configuration"]["value"] for r in self.fake.rules["/zones/Z1"].values()}
        self.assertIn("203.0.113.9", values)          # over threshold
        self.assertNotIn("192.0.2.7", values)         # allowlisted
        self.assertNotIn("198.51.100.4", values)      # under threshold
        self.assertNotIn(old, self.fake.rules["/zones/Z1"])   # expired: lifted
        self.assertIn(keep, self.fake.rules["/zones/Z1"])     # still active
        self.assertIn("198.51.100.202", values)       # foreign rule untouched

    def test_filter_shape(self):
        self.fake.hits["Z1"] = []
        rw.cmd_run(self.cf, self.conf, dry=False)
        flt = self.fake.graphql_calls[0]["variables"]["filter"]
        self.assertIn({"cacheStatus_neq": "hit"}, flt["AND"])
        self.assertIn({"clientRequestPath_notlike": "/adm%"}, flt["AND"])
        self.assertIn({"clientRequestPath_notlike": "%.jpg"}, flt["AND"])
        start = dt.datetime.strptime(flt["datetime_geq"], "%Y-%m-%dT%H:%M:%SZ")
        end = dt.datetime.strptime(flt["datetime_lt"], "%Y-%m-%dT%H:%M:%SZ")
        self.assertEqual(end - start, dt.timedelta(minutes=60))

    def test_ipv6_banned_as_64_and_account_scope(self):
        self.fake.hits["Z2"] = [("2001:db8:1:2:3:4:5:6", 800)]
        rw.cmd_run(self.cf, self.conf, dry=False)
        rule = next(iter(self.fake.rules["/accounts/A1"].values()))
        self.assertEqual(rule["configuration"]["target"], "ip_range")
        self.assertEqual(rw.norm(rule["configuration"]["value"]), "2001:db8:1:2::/64")

    def test_expanded_ipv6_range_counts_as_already_banned(self):
        self.fake.hits["Z2"] = [("2001:db8:1:2::99", 800)]
        self.fake.add_rule("/accounts/A1", "2001:db8:1:2::/64", self.note(+3), target="ip_range")
        rw.cmd_run(self.cf, self.conf, dry=False)
        self.assertEqual([w for w in self.fake.writes if w[0] == "POST"], [])
        self.assertEqual(self.fake.post_attempts, 0)

    def test_already_banned_and_duplicate_are_not_errors(self):
        self.fake.hits["Z1"] = [("203.0.113.9", 5000), ("203.0.113.10", 5000)]
        self.fake.add_rule("/zones/Z1", "203.0.113.9", self.note(+3))
        self.fake.add_rule("/zones/Z1", "203.0.113.10", "whitelisted by hand", mode="whitelist")
        rw.cmd_run(self.cf, self.conf, dry=False)
        self.assertEqual([w for w in self.fake.writes if w[0] == "POST"], [])

    def test_dry_run_changes_nothing(self):
        self.fake.hits["Z1"] = [("203.0.113.9", 5000)]
        self.fake.add_rule("/zones/Z1", "198.51.100.200", self.note(-1))
        events = rw.cmd_run(self.cf, self.conf, dry=True)
        self.assertEqual(self.fake.writes, [])
        self.assertEqual(len(events), 2)

    def test_budget_exhaustion_stops_querying(self):
        self.fake.budget_left = 0
        rw.cmd_run(self.cf, self.conf, dry=False)
        self.assertEqual(len(self.fake.graphql_calls), 1)

    def test_max_bans_per_run(self):
        conf = rw.load_config(write_config('[[zones]]\nname = "example.com"\nmax_bans_per_run = 2\n'))
        self.fake.hits["Z1"] = [(f"203.0.113.{i}", 5000) for i in range(1, 6)]
        rw.cmd_run(self.cf, conf, dry=False)
        self.assertEqual(len(self.fake.rules["/zones/Z1"]), 2)

    def test_unban_by_ip_inside_range(self):
        self.fake.add_rule("/zones/Z1", "2001:db8:1:2::/64", self.note(+3), target="ip_range")
        rw.cmd_unban(self.cf, self.conf, "2001:db8:1:2::abcd", dry=False)
        self.assertEqual(self.fake.rules["/zones/Z1"], {})

    def test_config_validation(self):
        with self.assertRaises(rw.ConfigError):
            rw.load_config(write_config('[[zones]]\nname = "x"\ntreshold = 5\n'))
        with self.assertRaises(rw.ConfigError):
            rw.load_config(write_config('[[zones]]\nname = "x"\nmode = "nuke"\n'))
        with self.assertRaises(rw.ConfigError):
            rw.load_config(write_config('[defaults]\nthreshold = 5\n'))


if __name__ == "__main__":
    unittest.main()
