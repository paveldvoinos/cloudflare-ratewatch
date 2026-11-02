// The Worker side of the shared vectors; tests/test_vectors.py is the Python side.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import {
  ZONE_DEFAULTS, buildFilter, ruleTarget, norm, isAllowed, parseNet, makeNote, noteUntil, iso,
  configFromDict, ConfigError, influxLines, promText,
} from "../src/core.js";

const V = JSON.parse(readFileSync(new URL("../../tests/vectors.json", import.meta.url), "utf8"));
const NOW = new Date(V.now);
const publicCfg = (cfg) => Object.fromEntries(Object.entries(cfg).filter(([k]) => !k.startsWith("_")));

test("filter", () => {
  for (const c of V.filter) assert.deepEqual(buildFilter({ ...ZONE_DEFAULTS, ...c.cfg }, NOW), c.expect);
});

test("rule_target", () => {
  for (const c of V.rule_target) assert.deepEqual(ruleTarget(c.ip, c.prefix), c.expect, JSON.stringify(c));
});

test("norm", () => {
  for (const c of V.norm) assert.equal(norm(c.value), c.expect, c.value);
});

test("allowed", () => {
  for (const c of V.allowed) assert.equal(isAllowed(c.ip, c.allow.map(parseNet)), c.expect, JSON.stringify(c));
});

test("notes", () => {
  const m = V.notes.make;
  assert.equal(makeNote(new Date(m.until), m.zone, m.hits, m.window), m.expect);
  for (const c of V.notes.until) {
    const got = noteUntil(c.note);
    assert.equal(got ? iso(got) : null, c.expect, c.note);
  }
});

test("config", () => {
  for (const c of V.config) {
    if (!c.ok) {
      assert.throws(() => configFromDict(c.raw), ConfigError, JSON.stringify(c.raw));
      continue;
    }
    const got = configFromDict(c.raw).zones;
    assert.equal(got.length, c.zones.length);
    got.forEach((g, i) => {
      assert.equal(g.name, c.zones[i].name);
      assert.equal(g.id, c.zones[i].id);
      assert.deepEqual(publicCfg(g.cfg), c.zones[i].cfg);
    });
  }
});

test("influx", () => {
  const c = V.influx;
  assert.deepEqual(influxLines(c.stats, NOW, c.duration, c.top_n), c.expect);
});

test("prom", () => {
  const c = V.prom;
  assert.equal(promText(c.stats, NOW, c.duration, c.prev), c.expect);
});
