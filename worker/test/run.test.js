// Scenario tests against a fake Cloudflare API and an in-memory KV (mirrors tests/test_ratewatch.py).
import { test } from "node:test";
import assert from "node:assert/strict";
import { Cloudflare, configFromDict, run, main, handleFetch, makeNote, norm, parseNet } from "../src/core.js";

const BASE = "http://cf.test";
const quiet = { log() {}, warn() {}, error() {} };

function expand(value) { // Cloudflare stores IPv6 ranges fully expanded
  const net = parseNet(value);
  if (!net || net.v !== 6) return value;
  return `${net.n.toString(16).padStart(32, "0").match(/.{4}/g).join(":")}/${net.bits}`;
}

function fakeCF() {
  const s = {
    zones: { "example.com": ["Z1", "A1"], "other.org": ["Z2", "A1"] },
    hits: {}, rules: {}, graphql: [], writes: [], posts: [], zoneLookups: 0, postAttempts: 0, budgetLeft: 99, nextId: 1,
  };
  s.addRule = (sp, value, notes, target = "ip", mode = "block") => {
    const id = `r${s.nextId++}`;
    if (target === "ip_range") value = expand(value);
    (s.rules[sp] ||= {})[id] = { id, mode, notes, configuration: { target, value } };
    return id;
  };
  const json = (status, obj) => new Response(JSON.stringify(obj), { status, headers: { "content-type": "application/json" } });
  s.fetch = async (url, init = {}) => {
    const u = new URL(url);
    const method = init.method || "GET";
    if (u.origin !== BASE) {
      s.posts.push({ url: u, headers: init.headers, body: init.body });
      return new Response(null, { status: 204 });
    }
    const body = init.body ? JSON.parse(init.body) : null;
    const path = u.pathname;
    if (path === "/zones" && method === "GET") {
      s.zoneLookups++;
      const name = u.searchParams.get("name");
      const z = s.zones[name];
      return json(200, { success: true, result: z ? [{ id: z[0], name, account: { id: z[1] } }] : [] });
    }
    if (path === "/graphql") {
      s.graphql.push(body);
      if (s.budgetLeft-- <= 0) return json(200, { data: null, errors: [{ message: "Rate limiter budget depleted." }] });
      const groups = (s.hits[body.variables.zone] || []).map(([ip, count]) => ({ count, dimensions: { clientIP: ip } }));
      return json(200, { data: { viewer: { zones: [{ httpRequestsAdaptiveGroups: groups }] } }, errors: null });
    }
    const m = /^(.*)\/firewall\/access_rules\/rules(?:\/(\w+))?$/.exec(path);
    if (m) {
      const [, sp, id] = m;
      const rules = (s.rules[sp] ||= {});
      if (method === "GET") return json(200, { success: true, result: Object.values(rules), result_info: { total_pages: 1 } });
      if (method === "POST") {
        s.postAttempts++;
        const v = body.configuration.value;
        if (Object.values(rules).some((r) => norm(r.configuration.value) === norm(v))) {
          return json(400, { success: false, errors: [{ code: 10009, message: "firewallaccessrules.api.duplicate_of_existing" }] });
        }
        const rid = s.addRule(sp, v, body.notes, body.configuration.target, body.mode);
        s.writes.push(["POST", sp, v]);
        return json(200, { success: true, result: rules[rid] });
      }
      if (method === "DELETE" && rules[id]) {
        s.writes.push(["DELETE", sp, rules[id].configuration.value]);
        delete rules[id];
        return json(200, { success: true, result: { id } });
      }
    }
    return json(404, { success: false, errors: [{ code: 7003, message: "no route" }] });
  };
  return s;
}

function kv() {
  const store = new Map();
  return {
    store,
    async get(k, type) { const v = store.get(k); return v === undefined ? null : type === "json" ? JSON.parse(v) : v; },
    async put(k, v) { store.set(k, v); },
  };
}

const CONFIG = {
  defaults: { threshold: 1000, allow: ["192.0.2.0/24"] },
  zones: [
    { name: "example.com", exclude_paths: ["/adm"], exclude_extensions: ["jpg"] },
    { name: "other.org", threshold: 500, scope: "account" },
  ],
};

const note = (hours) => makeNote(new Date(Date.now() + hours * 3600000), "example.com", 1, 60);
const setup = (opts = {}) => {
  const s = fakeCF();
  const cf = new Cloudflare("t", { base: BASE, fetchImpl: s.fetch, ...opts });
  return { s, cf, conf: configFromDict(CONFIG) };
};
const values = (s, sp) => Object.values(s.rules[sp] || {}).map((r) => r.configuration.value);

test("bans over threshold, skips allowlisted, lifts expired, leaves foreign rules", async () => {
  const { s, cf, conf } = setup();
  s.hits.Z1 = [["203.0.113.9", 5000], ["192.0.2.7", 4000], ["198.51.100.4", 900]];
  const old = s.addRule("/zones/Z1", "198.51.100.200", note(-1));
  const keep = s.addRule("/zones/Z1", "198.51.100.201", note(5));
  s.addRule("/zones/Z1", "198.51.100.202", "manual rule, not ours");
  await run(cf, conf, { log: quiet });
  const v = values(s, "/zones/Z1");
  assert.ok(v.includes("203.0.113.9"));
  assert.ok(!v.includes("192.0.2.7"));
  assert.ok(!v.includes("198.51.100.4"));
  assert.ok(!(old in s.rules["/zones/Z1"]));
  assert.ok(keep in s.rules["/zones/Z1"]);
  assert.ok(v.includes("198.51.100.202"));
});

test("analytics filter shape", async () => {
  const { s, cf, conf } = setup();
  await run(cf, conf, { log: quiet });
  const flt = s.graphql[0].variables.filter;
  assert.deepEqual(flt.AND, [{ cacheStatus_neq: "hit" }, { clientRequestPath_notlike: "/adm%" }, { clientRequestPath_notlike: "%.jpg" }]);
  assert.equal(new Date(flt.datetime_lt) - new Date(flt.datetime_geq), 3600000);
});

test("IPv6 is banned per /64, account scope", async () => {
  const { s, cf, conf } = setup();
  s.hits.Z2 = [["2001:db8:1:2:3:4:5:6", 800]];
  await run(cf, conf, { log: quiet });
  const [rule] = Object.values(s.rules["/accounts/A1"]);
  assert.equal(rule.configuration.target, "ip_range");
  assert.equal(norm(rule.configuration.value), "2001:db8:1:2::/64");
});

test("expanded IPv6 range already banned: no POST at all", async () => {
  const { s, cf, conf } = setup();
  s.hits.Z2 = [["2001:db8:1:2::99", 800]];
  s.addRule("/accounts/A1", "2001:db8:1:2::/64", note(3), "ip_range");
  await run(cf, conf, { log: quiet });
  assert.equal(s.postAttempts, 0);
});

test("already banned and duplicate are not errors", async () => {
  const { s, cf, conf } = setup();
  s.hits.Z1 = [["203.0.113.9", 5000], ["203.0.113.10", 5000]];
  s.addRule("/zones/Z1", "203.0.113.9", note(3));
  s.addRule("/zones/Z1", "203.0.113.10", "whitelisted by hand", "ip", "whitelist");
  const { stats } = await run(cf, conf, { log: quiet });
  assert.deepEqual(s.writes.filter((w) => w[0] === "POST"), []);
  assert.equal(stats.errors, 0);
});

test("dry run changes nothing", async () => {
  const { s, cf, conf } = setup();
  s.hits.Z1 = [["203.0.113.9", 5000]];
  s.addRule("/zones/Z1", "198.51.100.200", note(-1));
  const { events } = await run(cf, conf, { dry: true, log: quiet });
  assert.deepEqual(s.writes, []);
  assert.equal(events.length, 2);
});

test("analytics budget exhaustion stops querying", async () => {
  const { s, cf, conf } = setup();
  s.budgetLeft = 0;
  const { stats } = await run(cf, conf, { log: quiet });
  assert.equal(s.graphql.length, 1);
  assert.equal(stats.errors, 1);
});

test("max_bans_per_run", async () => {
  const { s, cf } = setup();
  s.hits.Z1 = [1, 2, 3, 4, 5].map((i) => [`203.0.113.${i}`, 5000]);
  await run(cf, configFromDict({ zones: [{ name: "example.com", max_bans_per_run: 2 }] }), { log: quiet });
  assert.equal(values(s, "/zones/Z1").length, 2);
});

test("subrequest budget ends the run cleanly", async () => {
  const { s, cf, conf } = setup({ maxSubrequests: 4 }); // 2 zone lookups + 2 rule lists, nothing left for analytics
  s.hits.Z1 = [["203.0.113.9", 5000]];
  const { stats } = await run(cf, conf, { log: quiet });
  assert.equal(cf.used, 4);
  assert.equal(s.graphql.length, 0);
  assert.ok(stats.errors >= 1);
});

test("zone ids are cached in KV", async () => {
  const { s, cf, conf } = setup();
  const store = kv();
  await run(cf, conf, { kv: store, log: quiet });
  assert.equal(s.zoneLookups, 2);
  await run(new Cloudflare("t", { base: BASE, fetchImpl: s.fetch }), conf, { kv: store, log: quiet });
  assert.equal(s.zoneLookups, 2);
});

const env = (s, extra = {}) => ({ CONFIG, CF_API_TOKEN: "t", CF_API_BASE: BASE, STATE: kv(), ...extra });

test("main writes metrics to KV and keeps counters across runs", async () => {
  const s = fakeCF();
  const e = env(s);
  s.hits.Z1 = [["203.0.113.9", 5000]];
  await main(e, new Date(), { fetchImpl: s.fetch, log: quiet });
  s.hits.Z1 = [["203.0.113.10", 7000]];
  await main(e, new Date(), { fetchImpl: s.fetch, log: quiet });
  const text = await e.STATE.get("metrics");
  assert.match(text, /^cf_ratewatch_bans_total\{zone="example.com"\} 2$/m);
  assert.match(text, /^cf_ratewatch_top_requests\{zone="example.com"\} 7000$/m);
  assert.match(text, /^cf_ratewatch_run_success 1$/m);
});

test("main posts InfluxDB lines with token and Access headers", async () => {
  const s = fakeCF();
  s.hits.Z1 = [["203.0.113.9", 5000]];
  const e = env(s, {
    CONFIG: { ...CONFIG, settings: { influx_url: "http://influx.test/api/v2/write?org=o&bucket=b", influx_top_ips: 1 } },
    INFLUX_TOKEN: "itok", CF_ACCESS_CLIENT_ID: "cid", CF_ACCESS_CLIENT_SECRET: "csec",
  });
  await main(e, new Date(), { fetchImpl: s.fetch, log: quiet });
  assert.equal(s.posts.length, 1);
  const p = s.posts[0];
  assert.equal(p.url.searchParams.get("precision"), "s");
  assert.equal(p.url.searchParams.get("bucket"), "b");
  assert.equal(p.headers.Authorization, "Token itok");
  assert.equal(p.headers["CF-Access-Client-Id"], "cid");
  assert.equal(p.headers["CF-Access-Client-Secret"], "csec");
  assert.match(p.body, /^cf_ratewatch_ban,zone=example.com,mode=block,seq=1 ip="203.0.113.9",hits=5000i,/m);
});

test("DRY_RUN env: no bans, no metrics", async () => {
  const s = fakeCF();
  s.hits.Z1 = [["203.0.113.9", 5000]];
  const e = env(s, { DRY_RUN: "true" });
  await main(e, new Date(), { fetchImpl: s.fetch, log: quiet });
  assert.deepEqual(s.writes, []);
  assert.equal(await e.STATE.get("metrics"), null);
});

test("bad config and missing token are reported, not thrown", async () => {
  const s = fakeCF();
  assert.equal(await main(env(s, { CONFIG: "{not json" }), new Date(), { fetchImpl: s.fetch, log: quiet }), null);
  assert.equal(await main(env(s, { CONFIG: { zones: [] } }), new Date(), { fetchImpl: s.fetch, log: quiet }), null);
  assert.equal(await main(env(s, { CF_API_TOKEN: "" }), new Date(), { fetchImpl: s.fetch, log: quiet }), null);
});

test("/metrics endpoint", async () => {
  const STATE = kv();
  await STATE.put("metrics", "cf_ratewatch_run_success 1\n");
  const req = (auth) => new Request("https://w.test/metrics", { headers: auth ? { Authorization: auth } : {} });
  assert.equal((await handleFetch(req("Bearer x"), { STATE })).status, 404); // no METRICS_TOKEN: off
  assert.equal((await handleFetch(req(), { STATE, METRICS_TOKEN: "sekret" })).status, 401);
  assert.equal((await handleFetch(req("Bearer wrong"), { STATE, METRICS_TOKEN: "sekret" })).status, 401);
  const ok = await handleFetch(req("Bearer sekret"), { STATE, METRICS_TOKEN: "sekret" });
  assert.equal(ok.status, 200);
  assert.equal(await ok.text(), "cf_ratewatch_run_success 1\n");
  assert.equal((await handleFetch(new Request("https://w.test/"), { STATE })).status, 404);
});
