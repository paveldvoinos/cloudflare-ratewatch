"""The Python side of the shared vectors; worker/test/vectors.test.js is the other side."""
import datetime as dt
import ipaddress
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import cf_ratewatch as rw  # noqa: E402

with open(os.path.join(os.path.dirname(__file__), "vectors.json")) as f:
    V = json.load(f)
NOW = dt.datetime.strptime(V["now"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=dt.UTC)


class Vectors(unittest.TestCase):
    def test_filter(self):
        for case in V["filter"]:
            self.assertEqual(rw.build_filter({**rw.ZONE_DEFAULTS, **case["cfg"]}, NOW), case["expect"])

    def test_rule_target(self):
        for case in V["rule_target"]:
            self.assertEqual(list(rw.rule_target(case["ip"], case["prefix"])), case["expect"], case)

    def test_norm(self):
        for case in V["norm"]:
            self.assertEqual(rw.norm(case["value"]), case["expect"], case)

    def test_allowed(self):
        for case in V["allowed"]:
            nets = [ipaddress.ip_network(a, strict=False) for a in case["allow"]]
            self.assertEqual(rw.is_allowed(case["ip"], nets), case["expect"], case)

    def test_notes(self):
        m = V["notes"]["make"]
        until = dt.datetime.strptime(m["until"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=dt.UTC)
        self.assertEqual(rw.make_note(until, m["zone"], m["hits"], m["window"]), m["expect"])
        for case in V["notes"]["until"]:
            got = rw.note_until(case["note"])
            self.assertEqual(rw.iso(got) if got else None, case["expect"], case)

    def test_config(self):
        for case in V["config"]:
            if not case["ok"]:
                with self.assertRaises(rw.ConfigError, msg=case["raw"]):
                    rw.config_from_dict(case["raw"])
                continue
            got = rw.config_from_dict(case["raw"])["zones"]
            want = case["zones"]
            self.assertEqual(len(got), len(want))
            for g, w in zip(got, want, strict=True):
                self.assertEqual((g["name"], g["id"]), (w["name"], w["id"]))
                self.assertEqual({k: v for k, v in g["cfg"].items() if not k.startswith("_")}, w["cfg"])

    def test_influx(self):
        c = V["influx"]
        self.assertEqual(rw.influx_lines(c["stats"], NOW, c["duration"], c["top_n"]), c["expect"])

    def test_prom(self):
        c = V["prom"]
        self.assertEqual(rw.prom_text(c["stats"], NOW, c["duration"], c["prev"]), c["expect"])


if __name__ == "__main__":
    unittest.main()
