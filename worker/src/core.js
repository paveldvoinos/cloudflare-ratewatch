/**
 * cf-ratewatch for Cloudflare Workers.
 *
 * The same logic, config schema and rule notes as cf_ratewatch.py, run by a Cron Trigger.
 * Bans created by one implementation are lifted by the other, so you can move between them.
 * Shared behaviour is pinned by tests/vectors.json in the repository.
 *
 * Everything lives here; index.js holds only the Worker entry point, because the Workers
 * runtime treats every named export of the main module as an entry point.
 */

export const VERSION = "0.3.0";
export const TAG = "cf-ratewatch";
const API = "https://api.cloudflare.com/client/v4";

export const ZONE_DEFAULTS = {
  window_minutes: 60,
  threshold: 1000,
  ban_hours: 24,
  mode: "block",
  scope: "zone",
  exclude_cached: true,
  exclude_paths: [],
  exclude_extensions: [],
  allow: [],
  ipv6_prefix: 64,
  max_bans_per_run: 20,
  top: 25,
};
const MODES = new Set(["block", "managed_challenge", "challenge", "js_challenge"]);
const SCOPES = new Set(["zone", "account"]);
const V6_PREFIXES = new Set([32, 48, 64, 128]);
const SECTIONS = ["settings", "defaults", "zones"];
const SETTINGS = { // key -> kind; same table as SETTINGS in cf_ratewatch.py
  api_token_env: "name",
  api_token_file: "path",
  influx_url: "url",
  influx_token_env: "name",
  influx_token_file: "path",
  influx_top_ips: "count",
  metrics_file: "path",
  metrics_kv: "bool",
  notify_url: "url",
  notify_format: ["json", "plain"],
};
const NUMBER_KEYS = ["threshold", "window_minutes", "ban_hours"];
const INTEGER_KEYS = ["max_bans_per_run", "top"];
const LIST_KEYS = ["exclude_paths", "exclude_extensions", "allow"];

const QUERY = (limit) => `query($zone: string, $filter: ZoneHttpRequestsAdaptiveGroupsFilter_InputObject) {
  viewer { zones(filter: {zoneTag: $zone}) {
    httpRequestsAdaptiveGroups(limit: ${limit}, orderBy: [count_DESC], filter: $filter) {
      count
      dimensions { clientIP }
    }
  } }
}`;

export class ConfigError extends Error {}

export class CFError extends Error {
  constructor(status, errors) {
    const list = errors || [];
    const msgs = list.map((e) => `${e.code ?? ""} ${e.message ?? ""}`.trim()).join("; ");
    super(`HTTP ${status}: ${msgs || "request failed"}`);
    this.status = status;
    this.errors = list;
  }

  has(...needles) {
    const text = this.message.toLowerCase();
    return needles.some((n) => text.includes(n));
  }
}

// ------------------------------------------------------------------ IP addresses

function parseV4(s) {
  const parts = s.split(".");
  if (parts.length !== 4) return null;
  let n = 0n;
  for (const p of parts) {
    if (!/^\d{1,3}$/.test(p) || (p.length > 1 && p[0] === "0") || Number(p) > 255) return null;
    n = (n << 8n) | BigInt(p);
  }
  return n;
}

function parseV6(s) {
  if (s.includes("%")) return null;
  const last = s.lastIndexOf(":");
  if (s.slice(last + 1).includes(".")) {
    const v4 = parseV4(s.slice(last + 1));
    if (v4 === null) return null;
    s = `${s.slice(0, last + 1)}${(v4 >> 16n).toString(16)}:${(v4 & 0xffffn).toString(16)}`;
  }
  const halves = s.split("::");
  if (halves.length > 2) return null;
  const head = halves[0] ? halves[0].split(":") : [];
  let groups = head;
  if (halves.length === 2) {
    const tail = halves[1] ? halves[1].split(":") : [];
    const fill = 8 - head.length - tail.length;
    if (fill < 1) return null;
    groups = [...head, ...Array(fill).fill("0"), ...tail];
  }
  if (groups.length !== 8) return null;
  let n = 0n;
  for (const g of groups) {
    if (!/^[0-9a-fA-F]{1,4}$/.test(g)) return null;
    n = (n << 16n) | BigInt(parseInt(g, 16));
  }
  return n;
}

export function parseIP(value) {
  const s = String(value).trim();
  const n = s.includes(":") ? parseV6(s) : parseV4(s);
  return n === null ? null : { v: s.includes(":") ? 6 : 4, n };
}

const width = (v) => (v === 4 ? 32 : 128);
const maskOf = (v, bits) => (bits === 0 ? 0n : ((1n << BigInt(bits)) - 1n) << BigInt(width(v) - bits));

export function parseNet(value) {
  const parts = String(value).split("/");
  if (parts.length > 2) return null;
  const ip = parseIP(parts[0]);
  if (!ip) return null;
  let bits = width(ip.v);
  if (parts.length === 2) {
    if (!/^\d+$/.test(parts[1]) || Number(parts[1]) > bits) return null;
    bits = Number(parts[1]);
  }
  return { v: ip.v, n: ip.n & maskOf(ip.v, bits), bits };
}

function fmt4(n) {
  return [24n, 16n, 8n, 0n].map((s) => ((n >> s) & 255n).toString()).join(".");
}

function fmt6(n) {
  const g = [];
  for (let i = 7; i >= 0; i--) g.push(Number((n >> BigInt(i * 16)) & 0xffffn));
  let best = -1;
  let bestLen = 0;
  for (let i = 0; i < 8;) {
    if (g[i] !== 0) { i++; continue; }
    let j = i;
    while (j < 8 && g[j] === 0) j++;
    if (j - i > bestLen) { best = i; bestLen = j - i; }
    i = j;
  }
  const hex = g.map((x) => x.toString(16));
  if (bestLen < 2) return hex.join(":"); // RFC 5952: a single zero group is not compressed
  return `${hex.slice(0, best).join(":")}::${hex.slice(best + bestLen).join(":")}`;
}

const fmtNet = (net) => `${net.v === 4 ? fmt4(net.n) : fmt6(net.n)}/${net.bits}`;

export function ruleTarget(ip, v6Prefix) {
  const a = parseIP(ip);
  if (!a) throw new Error(`not an IP address: ${ip}`);
  if (a.v === 4) return ["ip", fmt4(a.n)];
  if (v6Prefix >= 128) return ["ip6", fmt6(a.n)];
  return ["ip_range", fmtNet({ v: 6, n: a.n & maskOf(6, v6Prefix), bits: v6Prefix })];
}

/** Canonical form of an IP or range; Cloudflare stores IPv6 ranges fully expanded. */
export function norm(value) {
  const net = parseNet(value);
  return net ? fmtNet(net) : value;
}

export function isAllowed(ip, nets) {
  const a = parseIP(ip);
  return !!a && nets.some((net) => net.v === a.v && (a.n & maskOf(a.v, net.bits)) === net.n);
}

// ------------------------------------------------------------------ config

const isTable = (v) => v !== null && typeof v === "object" && !Array.isArray(v);
const isNumber = (v) => typeof v === "number" && Number.isFinite(v);
const isInteger = (v) => isNumber(v) && Number.isInteger(v);
const isText = (v) => typeof v === "string" && v.trim() !== "";

function similarity(a, b) { // 1 - edit distance / length, for "did you mean"
  const d = Array.from({ length: a.length + 1 }, (_, i) => [i, ...Array(b.length).fill(0)]);
  for (let j = 1; j <= b.length; j++) d[0][j] = j;
  for (let i = 1; i <= a.length; i++) {
    for (let j = 1; j <= b.length; j++) {
      d[i][j] = Math.min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1));
    }
  }
  return 1 - d[a.length][b.length] / Math.max(a.length, b.length, 1);
}

function checkUnknown(obj, known, where, what = "key") {
  const names = Array.isArray(known) ? known : Object.keys(known);
  for (const key of Object.keys(obj).sort()) {
    if (names.includes(key)) continue;
    const best = names.map((n) => [similarity(key, n), n]).sort((x, y) => y[0] - x[0])[0];
    const hint = best && best[0] >= 0.6 ? ` (did you mean '${best[1]}'?)` : "";
    throw new ConfigError(`${where}: unknown ${what} '${key}'${hint}`);
  }
}

function checkLists(obj, where) {
  for (const key of LIST_KEYS) {
    if (key in obj && (!Array.isArray(obj[key]) || !obj[key].every((x) => typeof x === "string"))) {
      throw new ConfigError(`${where}: ${key} must be a list of strings, e.g. "${key}": ["..."]`);
    }
  }
}

function validateSettings(settings) {
  if (!isTable(settings)) throw new ConfigError("[settings] must be a table");
  checkUnknown(settings, SETTINGS, "[settings]");
  for (const [key, value] of Object.entries(settings)) {
    const kind = SETTINGS[key];
    const where = `[settings] ${key}`;
    if (kind === "name" || kind === "path") {
      if (!isText(value)) throw new ConfigError(`${where} must be a non-empty string`);
    } else if (kind === "url") {
      if (typeof value !== "string" || !/^https?:\/\/[^/\s]+/.test(value)) throw new ConfigError(`${where} must be an http:// or https:// URL`);
    } else if (kind === "count") {
      if (!isInteger(value) || value < 0) throw new ConfigError(`${where} must be a whole number, 0 or more`);
    } else if (kind === "bool") {
      if (typeof value !== "boolean") throw new ConfigError(`${where} must be true or false`);
    } else if (typeof value !== "string" || !kind.includes(value)) {
      throw new ConfigError(`${where} must be one of ${kind.join(", ")}`);
    }
  }
}

function validate(cfg, label) {
  if (typeof cfg.mode !== "string" || !MODES.has(cfg.mode)) throw new ConfigError(`${label}: mode must be one of ${[...MODES].sort()}`);
  if (typeof cfg.scope !== "string" || !SCOPES.has(cfg.scope)) throw new ConfigError(`${label}: scope must be zone or account`);
  if (!isInteger(cfg.ipv6_prefix) || !V6_PREFIXES.has(cfg.ipv6_prefix)) {
    throw new ConfigError(`${label}: ipv6_prefix must be one of 32, 48, 64, 128`);
  }
  for (const key of NUMBER_KEYS) {
    if (!isNumber(cfg[key]) || !(cfg[key] > 0)) throw new ConfigError(`${label}: ${key} must be a positive number`);
  }
  for (const key of INTEGER_KEYS) {
    if (!isInteger(cfg[key]) || !(cfg[key] > 0)) throw new ConfigError(`${label}: ${key} must be a positive whole number`);
  }
  if (cfg.window_minutes > 1440) throw new ConfigError(`${label}: window_minutes can be at most 1440`);
  if (typeof cfg.exclude_cached !== "boolean") throw new ConfigError(`${label}: exclude_cached must be true or false`);
  for (const p of cfg.exclude_paths) {
    if (!p.startsWith("/")) throw new ConfigError(`${label}: exclude_paths entry '${p}' must start with /`);
    if (["", "/"].includes(p.replace(/[%*]+$/, ""))) throw new ConfigError(`${label}: exclude_paths entry '${p}' would exclude every request`);
  }
  for (const e of cfg.exclude_extensions) {
    if (!e.replace(/^\.+/, "") || /[/%* ]/.test(e)) throw new ConfigError(`${label}: exclude_extensions entry '${e}' is not a file extension`);
  }
  cfg._allow = cfg.allow.map((a) => {
    const net = parseNet(a);
    if (!net) throw new ConfigError(`${label}: allow: ${a} is not an IP or CIDR`);
    return net;
  });
}

/** Validate a parsed config (JSON here, TOML on a server) and merge defaults into zones. */
export function configFromDict(raw) {
  if (!isTable(raw)) throw new ConfigError("the config must be a table");
  checkUnknown(raw, SECTIONS, "config", "section");
  const settings = "settings" in raw ? raw.settings : {};
  validateSettings(settings);
  const defaults = "defaults" in raw ? raw.defaults : {};
  if (!isTable(defaults)) throw new ConfigError("[defaults] must be a table");
  checkUnknown(defaults, ZONE_DEFAULTS, "[defaults]");
  checkLists(defaults, "[defaults]");
  const base = { ...ZONE_DEFAULTS, ...defaults };
  const rawZones = "zones" in raw ? raw.zones : [];
  if (!Array.isArray(rawZones) || !rawZones.every(isTable)) throw new ConfigError("zones must be an array of tables: [[zones]]");
  const zones = rawZones.map((z, i) => {
    const where = `[[zones]] #${i + 1}`;
    for (const key of ["name", "id"]) {
      if (key in z && !isText(z[key])) throw new ConfigError(`${where}: ${key} must be a non-empty string`);
    }
    if (!(z.name || z.id)) throw new ConfigError(`${where}: needs name or id`);
    const over = Object.fromEntries(Object.entries(z).filter(([k]) => k !== "name" && k !== "id"));
    checkUnknown(over, ZONE_DEFAULTS, where);
    checkLists(over, where);
    const cfg = { ...base, ...over };
    cfg.allow = "allow" in over ? [...base.allow, ...over.allow] : [...base.allow];
    validate(cfg, z.name || z.id);
    return { name: z.name ?? null, id: z.id ?? null, cfg };
  });
  if (!zones.length) throw new ConfigError("no [[zones]] configured");
  return { settings, zones };
}

// ------------------------------------------------------------------ helpers

export const iso = (t) => new Date(Math.floor(t.getTime() / 1000) * 1000).toISOString().replace(".000Z", "Z");

export function buildFilter(cfg, now) {
  const flt = {
    datetime_geq: iso(new Date(now.getTime() - cfg.window_minutes * 60000)),
    datetime_lt: iso(now),
  };
  const conds = [];
  if (cfg.exclude_cached) conds.push({ cacheStatus_neq: "hit" });
  for (const p of cfg.exclude_paths) conds.push({ clientRequestPath_notlike: `${p.replace(/[%*]+$/, "")}%` });
  for (const e of cfg.exclude_extensions) conds.push({ clientRequestPath_notlike: `%.${e.replace(/^\.+/, "")}` });
  if (conds.length) flt.AND = conds;
  return flt;
}

export const makeNote = (until, zone, hits, window) => `${TAG} until=${iso(until)} zone=${zone} hits=${hits}/${window}m`;

export function noteUntil(note) {
  for (const tok of (note || "").split(/\s+/)) {
    if (!tok.startsWith("until=")) continue;
    const m = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})Z$/.exec(tok.slice(6));
    if (!m) return null;
    const [y, mo, d, h, mi, s] = m.slice(1).map(Number);
    const t = new Date(Date.UTC(y, mo - 1, d, h, mi, s));
    const valid = t.getUTCMonth() === mo - 1 && t.getUTCDate() === d && h < 24 && mi < 60 && s < 60;
    return valid ? t : null;
  }
  return null;
}

const scopePath = (cfg, zoneId, accountId) => (cfg.scope === "account" ? `/accounts/${accountId}` : `/zones/${zoneId}`);

// ------------------------------------------------------------------ API

export class Cloudflare {
  /** maxSubrequests keeps a run inside the Workers Free limit of 50 external subrequests. */
  constructor(token, { base = API, maxSubrequests = 45, fetchImpl = (...a) => fetch(...a) } = {}) {
    this.token = token;
    this.base = base.replace(/\/+$/, "");
    this.max = maxSubrequests;
    this.fetch = fetchImpl;
    this.used = 0;
  }

  async call(method, path, body, query) {
    if (this.used >= this.max) throw new CFError(0, [{ message: `subrequest budget of ${this.max} reached` }]);
    this.used++;
    const url = this.base + path + (query ? `?${new URLSearchParams(query)}` : "");
    let res;
    try {
      res = await this.fetch(url, {
        method,
        headers: {
          Authorization: `Bearer ${this.token}`,
          "Content-Type": "application/json",
          "User-Agent": `${TAG}/${VERSION}`,
        },
        body: body === undefined ? undefined : JSON.stringify(body),
      });
    } catch (e) {
      throw new CFError(0, [{ message: String(e?.message || e) }]);
    }
    try {
      return [res.status, await res.json()];
    } catch {
      throw new CFError(res.status, [{ message: res.statusText || "response is not JSON" }]);
    }
  }

  async rest(method, path, body, query) {
    const [status, payload] = await this.call(method, path, body, query);
    if (!payload.success) throw new CFError(status, payload.errors);
    return payload;
  }

  async graphql(query, variables) {
    const [status, payload] = await this.call("POST", "/graphql", { query, variables });
    if (payload.errors && payload.errors.length) throw new CFError(status, payload.errors);
    return payload.data;
  }
}

async function resolveZone(cf, z, kv) {
  const key = `zone:${z.id || z.name}`;
  const cached = kv ? await kv.get(key, "json") : null;
  if (cached) return cached;
  let info;
  if (z.id) {
    info = (await cf.rest("GET", `/zones/${z.id}`)).result;
  } else {
    const res = (await cf.rest("GET", "/zones", undefined, { name: z.name })).result;
    if (!res.length) throw new CFError(404, [{ message: `zone ${z.name} not found (or token lacks Zone:Read)` }]);
    info = res[0];
  }
  const out = { id: info.id, name: info.name, account: info.account.id };
  if (kv) await kv.put(key, JSON.stringify(out), { expirationTtl: 86400 }); // saves subrequests on later runs
  return out;
}

async function topIps(cf, zoneId, cfg, now) {
  const data = await cf.graphql(QUERY(Math.trunc(cfg.top)), { zone: zoneId, filter: buildFilter(cfg, now) });
  const zones = data.viewer.zones;
  if (!zones.length) return [];
  return zones[0].httpRequestsAdaptiveGroups.map((g) => [g.dimensions.clientIP, Math.trunc(g.count)]);
}

async function listManaged(cf, sp) {
  const rules = [];
  for (let page = 1; ; page++) {
    const p = await cf.rest("GET", `${sp}/firewall/access_rules/rules`, undefined, { per_page: 100, page, notes: TAG });
    rules.push(...p.result.filter((r) => (r.notes || "").startsWith(TAG)));
    if (page >= ((p.result_info || {}).total_pages || 1)) return rules;
  }
}

// ------------------------------------------------------------------ run

export async function run(cf, conf, { kv = null, now = new Date(), dry = false, log = console } = {}) {
  const events = [];
  const managed = new Map();
  const labels = new Map();
  const stats = { zones: {}, top: {}, bans: [], lifted: 0, active: {}, errors: 0 };

  const zones = [];
  for (const z of conf.zones) {
    try {
      const info = await resolveZone(cf, z, kv);
      zones.push({ cfg: z.cfg, ...info });
    } catch (e) {
      log.error(`${z.name || z.id}: ${e.message}`);
      stats.errors++;
    }
  }
  for (const z of zones) {
    labels.set(scopePath(z.cfg, z.id, z.account), z.cfg.scope === "account" ? `account:${z.account}` : `zone:${z.name}`);
    stats.zones[z.name] = { ok: 0, threshold: z.cfg.threshold, top: 0, over: 0, bans: 0 };
  }

  // 1. lift expired bans
  for (const sp of labels.keys()) {
    let rules;
    try {
      rules = await listManaged(cf, sp);
    } catch (e) {
      log.error(`${sp}: cannot list access rules: ${e.message}`);
      managed.set(sp, null);
      stats.errors++;
      continue;
    }
    managed.set(sp, rules);
    for (const r of [...rules]) {
      const until = noteUntil(r.notes);
      if (!until || until > now) continue;
      const value = r.configuration.value;
      if (dry) {
        log.log(`[dry-run] would lift ban on ${value}`);
      } else {
        try {
          await cf.rest("DELETE", `${sp}/firewall/access_rules/rules/${r.id}`);
        } catch (e) {
          log.error(`cannot lift ban on ${value}: ${e.message}`);
          stats.errors++;
          continue;
        }
        log.log(`lifted ban on ${value}`);
        stats.lifted++;
      }
      rules.splice(rules.indexOf(r), 1);
      events.push(`unban ${value}`);
    }
  }

  // 2. find and ban heavy hitters
  for (const z of zones) {
    const { cfg } = z;
    const sp = scopePath(cfg, z.id, z.account);
    const rules = managed.get(sp);
    if (!rules) continue;
    const banned = new Set(rules.map((r) => norm(r.configuration.value)));
    let hits;
    try {
      hits = await topIps(cf, z.id, cfg, now);
    } catch (e) {
      log.error(`${z.name}: analytics query failed: ${e.message}`);
      stats.errors++;
      if (e instanceof CFError && e.has("budget", "rate limit")) {
        log.warn("budget exhausted; skipping the remaining zones this run");
        break;
      }
      continue;
    }
    const zstat = stats.zones[z.name];
    Object.assign(zstat, { ok: 1, top: hits.length ? hits[0][1] : 0, over: hits.filter(([, c]) => c >= cfg.threshold).length });
    stats.top[z.name] = hits;
    log.log(`${z.name}: top ${hits.slice(0, 3).map(([ip, c]) => `${ip}=${c}`).join(" ") || "-"} (threshold ${cfg.threshold}/${cfg.window_minutes}m)`);

    let bans = 0;
    for (const [ip, count] of hits) {
      if (count < cfg.threshold) break; // sorted by count
      if (isAllowed(ip, cfg._allow)) {
        log.log(`${z.name}: ${ip} at ${count} req/${cfg.window_minutes}m is allowlisted`);
        continue;
      }
      const [target, value] = ruleTarget(ip, cfg.ipv6_prefix);
      if (banned.has(norm(value))) continue;
      if (bans >= cfg.max_bans_per_run) {
        log.warn(`${z.name}: max_bans_per_run (${cfg.max_bans_per_run}) reached`);
        break;
      }
      const until = new Date(now.getTime() + cfg.ban_hours * 3600000);
      const msg = `${cfg.mode} ${value} (${count} req/${cfg.window_minutes}m on ${z.name}) until ${iso(until)}`;
      if (dry) {
        log.log(`[dry-run] would ${msg}`);
      } else {
        const body = {
          mode: cfg.mode,
          configuration: { target, value },
          notes: makeNote(until, z.name, count, cfg.window_minutes),
        };
        let res;
        try {
          res = await cf.rest("POST", `${sp}/firewall/access_rules/rules`, body);
        } catch (e) {
          if (e instanceof CFError && e.has("duplicate", "already exists")) {
            log.log(`${z.name}: ${value} already has an access rule, leaving it`);
            banned.add(norm(value));
            continue;
          }
          log.error(`${z.name}: cannot ban ${value}: ${e.message}`);
          stats.errors++;
          continue;
        }
        rules.push(res.result);
        log.log(msg);
        zstat.bans++;
        stats.bans.push({ zone: z.name, value, mode: cfg.mode, hits: count, until: iso(until) });
      }
      banned.add(norm(value));
      bans++;
      events.push(msg);
    }
  }

  for (const [sp, rules] of managed) if (rules) stats.active[labels.get(sp)] = rules.length;
  return { events, stats };
}

// ------------------------------------------------------------------ outputs

const PROM_SAMPLE = /^([a-zA-Z_:][a-zA-Z0-9_:]*)(?:\{(.*)\})?\s+(\S+)/;
const PROM_LABEL = /(\w+)="((?:[^"\\]|\\.)*)"/g;
const byKey = (a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : a[1] < b[1] ? -1 : a[1] > b[1] ? 1 : 0);
const counterKey = (name, pairs) => `${name}${JSON.stringify([...pairs].sort(byKey))}`;

export function parsePromCounters(text) {
  const out = new Map();
  for (const line of (text || "").split(/\r?\n/)) {
    const m = PROM_SAMPLE.exec(line);
    if (!m || !m[1].endsWith("_total")) continue;
    const value = Number(m[3]);
    if (!Number.isNaN(value)) out.set(counterKey(m[1], [...(m[2] || "").matchAll(PROM_LABEL)].map((x) => [x[1], x[2]])), value);
  }
  return out;
}

function promLabels(labels) {
  const entries = Object.entries(labels).sort(byKey);
  if (!entries.length) return "";
  const esc = (v) => String(v).replace(/\\/g, "\\\\").replace(/\n/g, "\\n").replace(/"/g, '\\"');
  return `{${entries.map(([k, v]) => `${k}="${esc(v)}"`).join(",")}}`;
}

export function promText(stats, now, duration, prevText = "") {
  const prev = parsePromCounters(prevText);
  const lines = [];
  const metric = (name, help, type, samples) => {
    lines.push(`# HELP ${name} ${help}`, `# TYPE ${name} ${type}`);
    for (const [labels, v] of samples) {
      const value = type === "counter" ? v + (prev.get(counterKey(name, Object.entries(labels))) ?? 0) : v;
      lines.push(`${name}${promLabels(labels)} ${value}`);
    }
  };
  const zones = Object.entries(stats.zones);
  const ok = zones.filter(([, d]) => d.ok);
  metric("cf_ratewatch_top_requests", "Highest request count from a single IP in the window.", "gauge",
    ok.map(([z, d]) => [{ zone: z }, d.top]));
  metric("cf_ratewatch_threshold", "Configured ban threshold per window.", "gauge", zones.map(([z, d]) => [{ zone: z }, d.threshold]));
  metric("cf_ratewatch_ips_over_threshold", "IPs at or over the threshold in this run.", "gauge",
    ok.map(([z, d]) => [{ zone: z }, d.over]));
  metric("cf_ratewatch_zone_query_success", "1 if the analytics query for the zone succeeded.", "gauge",
    zones.map(([z, d]) => [{ zone: z }, d.ok]));
  metric("cf_ratewatch_active_bans", "IP Access Rules currently managed by cf-ratewatch.", "gauge",
    Object.entries(stats.active).sort(byKey).map(([s, n]) => [{ scope: s }, n]));
  metric("cf_ratewatch_bans_total", "Bans created.", "counter", zones.map(([z, d]) => [{ zone: z }, d.bans]));
  metric("cf_ratewatch_bans_lifted_total", "Expired bans lifted.", "counter", [[{}, stats.lifted]]);
  metric("cf_ratewatch_errors_total", "API errors.", "counter", [[{}, stats.errors]]);
  metric("cf_ratewatch_run_success", "1 if the last run had no errors.", "gauge", [[{}, stats.errors ? 0 : 1]]);
  metric("cf_ratewatch_last_run_timestamp_seconds", "Unix time of the last run.", "gauge",
    [[{}, Math.floor(now.getTime() / 1000)]]);
  metric("cf_ratewatch_run_duration_seconds", "Duration of the last run.", "gauge", [[{}, Number(duration.toFixed(3))]]);
  return `${lines.join("\n")}\n`;
}

const lpTag = (v) => String(v).replace(/,/g, "\\,").replace(/=/g, "\\=").replace(/ /g, "\\ ");
const lpStr = (v) => `"${String(v).replace(/\\/g, "\\\\").replace(/"/g, '\\"')}"`;

export function influxLines(stats, now, duration, topN = 5) {
  const ts = Math.floor(now.getTime() / 1000);
  const lines = [];
  for (const [z, d] of Object.entries(stats.zones)) {
    const fields = [`query_ok=${d.ok ? "true" : "false"}`, `threshold=${Math.trunc(d.threshold)}i`];
    if (d.ok) fields.push(`top_requests=${d.top}i`, `over_threshold=${d.over}i`, `bans=${d.bans}i`);
    lines.push(`cf_ratewatch_zone,zone=${lpTag(z)} ${fields.join(",")} ${ts}`);
  }
  for (const [z, hits] of Object.entries(stats.top)) {
    hits.slice(0, topN).forEach(([ip, count], i) => {
      lines.push(`cf_ratewatch_top,zone=${lpTag(z)},rank=${i + 1} ip=${lpStr(ip)},requests=${count}i ${ts}`);
    });
  }
  stats.bans.forEach((b, i) => { // seq keeps several bans in one run from overwriting each other
    lines.push(`cf_ratewatch_ban,zone=${lpTag(b.zone)},mode=${lpTag(b.mode)},seq=${i + 1} `
      + `ip=${lpStr(b.value)},hits=${b.hits}i,until=${lpStr(b.until)} ${ts}`);
  });
  const active = Object.values(stats.active).reduce((a, b) => a + b, 0);
  lines.push(`cf_ratewatch_run active_bans=${active}i,lifted=${stats.lifted}i,errors=${stats.errors}i,`
    + `duration=${duration.toFixed(3)} ${ts}`);
  return lines;
}

async function post(fetchImpl, url, body, headers) {
  const res = await fetchImpl(url, { method: "POST", body, headers: { "User-Agent": `${TAG}/${VERSION}`, ...headers } });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
}

/** Notifications and metrics are best effort: a failing target never fails the run. */
async function writeOutputs(env, settings, stats, events, now, duration, { fetchImpl, log }) {
  if (settings.notify_url && events.length) {
    const text = `${TAG}:\n${events.join("\n")}`;
    const plain = settings.notify_format === "plain";
    try {
      await post(fetchImpl, settings.notify_url, plain ? text : JSON.stringify({ text, content: text }),
        { "Content-Type": plain ? "text/plain" : "application/json" });
    } catch (e) {
      log.warn(`notify failed: ${e.message}`);
    }
  }
  if (env.STATE && settings.metrics_kv !== false) {
    try {
      const prev = await env.STATE.get("metrics");
      await env.STATE.put("metrics", promText(stats, now, duration, prev || ""));
    } catch (e) {
      log.warn(`metrics: ${e.message}`);
    }
  }
  if (settings.influx_url) {
    try {
      const url = new URL(settings.influx_url);
      url.searchParams.set("precision", "s");
      const headers = { "Content-Type": "text/plain; charset=utf-8" };
      if (env.INFLUX_TOKEN) headers.Authorization = `Token ${env.INFLUX_TOKEN}`;
      if (env.CF_ACCESS_CLIENT_ID) { // Influx behind Cloudflare Access (e.g. through a Tunnel)
        headers["CF-Access-Client-Id"] = env.CF_ACCESS_CLIENT_ID;
        headers["CF-Access-Client-Secret"] = env.CF_ACCESS_CLIENT_SECRET || "";
      }
      const top = Number(settings.influx_top_ips ?? 5);
      await post(fetchImpl, url.toString(), influxLines(stats, now, duration, top).join("\n"), headers);
    } catch (e) {
      log.warn(`influx: ${e.message}`);
    }
  }
}

// ------------------------------------------------------------------ entry points

export function loadConf(env) {
  const raw = typeof env.CONFIG === "string" ? JSON.parse(env.CONFIG) : env.CONFIG || {};
  return configFromDict(raw);
}

export async function main(env, now = new Date(), { fetchImpl = (...a) => fetch(...a), log = console } = {}) {
  let conf;
  try {
    conf = loadConf(env);
  } catch (e) {
    log.error(`config: ${e.message}`);
    return null;
  }
  const token = String(env.CF_API_TOKEN || "").trim();
  if (!token) {
    log.error("config: no API token: set the CF_API_TOKEN secret");
    return null;
  }
  const dry = String(env.DRY_RUN || "").toLowerCase() === "true";
  const cf = new Cloudflare(token, {
    base: env.CF_API_BASE || API,
    maxSubrequests: Number(env.MAX_SUBREQUESTS || 45),
    fetchImpl,
  });
  const started = Date.now();
  const result = await run(cf, conf, { kv: env.STATE || null, now, dry, log });
  if (!dry) {
    await writeOutputs(env, conf.settings, result.stats, result.events, now, (Date.now() - started) / 1000, { fetchImpl, log });
  }
  log.log(`${dry ? "[dry-run] " : ""}run done: ${result.events.length} changes, ${result.stats.errors} errors, `
    + `${cf.used} API subrequests`);
  return result;
}

function sameSecret(a, b) {
  const x = new TextEncoder().encode(a);
  const y = new TextEncoder().encode(b);
  let diff = x.length ^ y.length;
  for (let i = 0; i < Math.max(x.length, y.length); i++) diff |= (x[i] ?? 0) ^ (y[i] ?? 0);
  return diff === 0;
}

export async function handleFetch(request, env) {
  const url = new URL(request.url);
  if (url.pathname !== "/metrics") return new Response("not found\n", { status: 404 });
  if (!env.METRICS_TOKEN) return new Response("metrics endpoint is off: set the METRICS_TOKEN secret\n", { status: 404 });
  if (!sameSecret(request.headers.get("Authorization") || "", `Bearer ${env.METRICS_TOKEN}`)) {
    return new Response("unauthorized\n", { status: 401, headers: { "WWW-Authenticate": "Bearer" } });
  }
  const text = env.STATE ? await env.STATE.get("metrics") : null;
  return new Response(text || "", { headers: { "Content-Type": "text/plain; version=0.0.4; charset=utf-8" } });
}
