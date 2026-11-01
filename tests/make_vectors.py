"""Regenerate tests/vectors.json from the Python implementation.

The vectors pin the behaviour both implementations must share (cf_ratewatch.py and
worker/src/index.js): analytics filter, rule targets, IP normalisation, notes, config
merging and validation, InfluxDB lines and Prometheus text. Run after an intentional
change, review the diff, commit. Both test suites assert against the committed file.
"""
import datetime as dt
import ipaddress
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import cf_ratewatch as rw  # noqa: E402

NOW = "2026-10-30T18:00:00Z"
now = dt.datetime.strptime(NOW, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=dt.UTC)


def cfg(**over):
    return {**rw.ZONE_DEFAULTS, **over}


def public_cfg(c):
    return {k: v for k, v in c.items() if not k.startswith("_")}


v = {"now": NOW}

v["filter"] = [{"cfg": over, "expect": rw.build_filter(cfg(**over), now)} for over in (
    {},
    {"exclude_cached": False},
    {"window_minutes": 15, "exclude_paths": ["/adm", "/admin%", "/wp-*"], "exclude_extensions": ["jpg", ".css"]},
)]

v["rule_target"] = [{"ip": ip, "prefix": p, "expect": list(rw.rule_target(ip, p))} for ip, p in (
    ("203.0.113.9", 64), ("2001:db8:1:2:3:4:5:6", 64), ("2001:db8:1:2:3:4:5:6", 48),
    ("2001:db8:1:2:3:4:5:6", 32), ("2001:0db8:0000:0000:0001:0000:0000:0001", 128),
    ("2a01:4f9:c010:d5f9::1", 64), ("::ffff:198.51.100.7", 64), ("fe80::1", 128),
)]

v["norm"] = [{"value": x, "expect": rw.norm(x)} for x in (
    "2001:0db8:0000:0000:0000:0000:0000:0000/64", "2001:db8::/64", "192.0.2.1", "192.0.2.0/24",
    "2001:db8::1", "2a01:04f9:c010:d5f9:0000:0000:0000:0000/64", "not-an-ip",
)]

def allowed(ip, allow):
    return rw.is_allowed(ip, [ipaddress.ip_network(a, strict=False) for a in allow])


v["allowed"] = [{"ip": ip, "allow": allow, "expect": allowed(ip, allow)} for ip, allow in (
    ("192.0.2.7", ["192.0.2.0/24"]), ("192.0.3.7", ["192.0.2.0/24"]), ("203.0.113.9", ["203.0.113.9"]),
    ("2001:db8:1:2::99", ["2001:db8:1::/48"]), ("2001:db8:2::1", ["2001:db8:1::/48", "10.0.0.0/8"]),
    ("10.1.2.3", ["2001:db8::/32", "10.0.0.0/8"]), ("192.0.2.1", []),
)]

until = now + dt.timedelta(hours=24)
note = rw.make_note(until, "example.com", 8132, 60)
v["notes"] = {
    "make": {"until": rw.iso(until), "zone": "example.com", "hits": 8132, "window": 60, "expect": note},
    "until": [{"note": n, "expect": (rw.iso(rw.note_until(n)) if rw.note_until(n) else None)} for n in (
        note, "cf-ratewatch until=bogus zone=x", "manual rule", "", "cf-ratewatch zone=x until=2026-01-02T03:04:05Z",
    )],
}

configs = [
    {"zones": [{"name": "a.com"}]},
    {"defaults": {"threshold": 500, "allow": ["192.0.2.0/24"]},
     "zones": [{"name": "a.com", "allow": ["203.0.113.10"], "exclude_paths": ["/adm"]},
               {"id": "abc", "threshold": 1500.0}]},
    {"zones": []},
    {"zones": [{"threshold": 5}]},
    {"zones": [{"name": "a.com", "treshold": 5}]},
    {"defaults": {"mode": "nuke"}, "zones": [{"name": "a.com"}]},
    {"zones": [{"name": "a.com", "scope": "galaxy"}]},
    {"zones": [{"name": "a.com", "ipv6_prefix": 56}]},
    {"zones": [{"name": "a.com", "threshold": 0}]},
    {"zones": [{"name": "a.com", "window_minutes": 2000}]},
    {"zones": [{"name": "a.com", "allow": ["not-a-cidr"]}]},
    # strict types (0.2.2): every one of these used to be accepted or crash later
    {"zones": [{"name": "a.com", "exclude_paths": "/adm"}]},
    {"zones": [{"name": "a.com", "exclude_paths": ["adm"]}]},
    {"zones": [{"name": "a.com", "exclude_paths": ["/"]}]},
    {"zones": [{"name": "a.com", "exclude_paths": ["/%"]}]},
    {"zones": [{"name": "a.com", "exclude_extensions": ["."]}]},
    {"zones": [{"name": "a.com", "exclude_extensions": ["a/b"]}]},
    {"zones": [{"name": "a.com", "exclude_cached": "false"}]},
    {"zones": [{"name": "a.com", "threshold": True}]},
    {"zones": [{"name": "a.com", "top": 2.5}]},
    {"zones": [{"name": "a.com", "allow": "192.0.2.0/24"}]},
    {"defaults": {"allow": "192.0.2.0/24"}, "zones": [{"name": "a.com"}]},
    {"zones": [{"name": 5}]},
    {"zones": {"name": "a.com"}},
    {"settings": None, "zones": [{"name": "a.com"}]},
    {"defaults": [], "zones": [{"name": "a.com"}]},
    {"setting": {}, "zones": [{"name": "a.com"}]},
    {"settings": {"influx_ulr": "http://x"}, "zones": [{"name": "a.com"}]},
    {"settings": {"notify_format": "xml"}, "zones": [{"name": "a.com"}]},
    {"settings": {"notify_url": "ntfy.sh/topic"}, "zones": [{"name": "a.com"}]},
    {"settings": {"influx_top_ips": -1}, "zones": [{"name": "a.com"}]},
    {"settings": {"influx_top_ips": 2.5}, "zones": [{"name": "a.com"}]},
    {"settings": {"api_token_file": 123}, "zones": [{"name": "a.com"}]},
    {"settings": {"api_token_env": ""}, "zones": [{"name": "a.com"}]},
    {"settings": {"metrics_kv": "no"}, "zones": [{"name": "a.com"}]},
    {"settings": {"api_token_env": "T", "api_token_file": "/etc/t", "influx_url": "https://i:8086/write?db=x",
                  "influx_token_env": "I", "influx_token_file": "/t", "influx_top_ips": 0,
                  "metrics_file": "/var/lib/x.prom", "metrics_kv": False, "notify_url": "https://ntfy.sh/t",
                  "notify_format": "plain"},
     "defaults": {"threshold": 1500.5, "top": 20.0, "exclude_paths": ["/adm", "/wp-*"],
                  "exclude_extensions": ["jpg", ".css"], "exclude_cached": False},
     "zones": [{"name": "a.com"}]},
]
v["config"] = []
for raw in configs:
    try:
        c = rw.config_from_dict(raw)
        v["config"].append({"raw": raw, "ok": True, "zones": [
            {"name": z["name"], "id": z["id"], "cfg": public_cfg(z["cfg"])} for z in c["zones"]]})
    except rw.ConfigError:
        v["config"].append({"raw": raw, "ok": False})

stats = {
    "zones": {"example.com": {"ok": 1, "threshold": 1000, "top": 8132, "over": 2, "bans": 2},
              "down.org": {"ok": 0, "threshold": 1500.0, "top": 0, "over": 0, "bans": 0},
              "a b,c=d": {"ok": 1, "threshold": 10, "top": 3, "over": 0, "bans": 0}},
    "top": {"example.com": [["178.20.210.133", 8132], ["136.23.84.96", 1378], ["66.249.67.64", 8]],
            "a b,c=d": [["2001:db8::1", 3]]},
    "bans": [{"zone": "example.com", "mode": "block", "value": "178.20.210.133", "hits": 8132,
              "until": rw.iso(until)},
             {"zone": "example.com", "mode": "managed_challenge", "value": 'odd"value\\x', "hits": 1378,
              "until": rw.iso(until)}],
    "lifted": 3, "errors": 1, "active": {"zone:example.com": 5, "account:A1": 0},
}
prev = ("# TYPE cf_ratewatch_bans_total counter\n"
        'cf_ratewatch_bans_total{zone="example.com"} 40\n'
        "cf_ratewatch_bans_lifted_total 7\n"
        "cf_ratewatch_errors_total 2.0\n"
        'cf_ratewatch_top_requests{zone="example.com"} 99\n')
v["influx"] = {"stats": stats, "duration": 1.5, "top_n": 2, "expect": rw.influx_lines(stats, now, 1.5, 2)}
v["prom"] = {"stats": stats, "duration": 1.2345, "prev": prev, "expect": rw.prom_text(stats, now, 1.2345, prev)}

out = os.path.join(os.path.dirname(__file__), "vectors.json")
with open(out, "w") as f:
    json.dump(v, f, indent=1, ensure_ascii=False)
    f.write("\n")
print("wrote", out)
