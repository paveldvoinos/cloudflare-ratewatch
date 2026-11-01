#!/usr/bin/env python3
"""cf-ratewatch: hour-scale per-IP request limits for Cloudflare zones, Free plan included.

Cloudflare's Free rate limiting counts over 10 s and blocks for 10 s, which slow
scanners (1-3 req/s for hours) never trip. cf-ratewatch counts requests per client
IP over a longer window with the GraphQL Analytics API and blocks heavy hitters
with IP Access Rules, which it removes again when the ban period ends.

Run it from cron or a systemd timer every 5-15 minutes. Python 3.11+, stdlib only.
"""
from __future__ import annotations

import argparse
import datetime as dt
import ipaddress
import json
import logging
import os
import sys
import tomllib
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

__version__ = "0.1.0"
TAG = "cf-ratewatch"
API = os.environ.get("CF_API_BASE", "https://api.cloudflare.com/client/v4").rstrip("/")
log = logging.getLogger(TAG)

ZONE_DEFAULTS = {
    "window_minutes": 60,      # sliding window the requests are counted over
    "threshold": 1000,         # requests per window per IP that trigger a ban
    "ban_hours": 24,           # how long the IP Access Rule stays
    "mode": "block",           # block | managed_challenge | challenge | js_challenge
    "scope": "zone",           # zone: ban on this zone only; account: ban on every zone in the account
    "exclude_cached": True,    # do not count cache hits (static assets a normal browser pulls)
    "exclude_paths": [],       # path prefixes never counted, e.g. ["/admin"]
    "exclude_extensions": [],  # extensions never counted, e.g. ["jpg", "css"]
    "allow": [],               # IPs or CIDRs that are never banned (merged with [defaults].allow)
    "ipv6_prefix": 64,         # ban IPv6 offenders as /64 (or 48, 32; 128 = single address)
    "max_bans_per_run": 20,    # safety cap per zone per run
    "top": 25,                 # how many top IPs to fetch per zone
}
MODES = {"block", "managed_challenge", "challenge", "js_challenge"}
SCOPES = {"zone", "account"}
V6_PREFIXES = {32, 48, 64, 128}

QUERY = """query($zone: string, $filter: ZoneHttpRequestsAdaptiveGroupsFilter_InputObject) {
  viewer { zones(filter: {zoneTag: $zone}) {
    httpRequestsAdaptiveGroups(limit: %d, orderBy: [count_DESC], filter: $filter) {
      count
      dimensions { clientIP }
    }
  } }
}"""


class ConfigError(Exception):
    pass


class CFError(Exception):
    def __init__(self, status, errors):
        self.status, self.errors = status, errors or []
        msgs = "; ".join(f"{e.get('code', '')} {e.get('message', '')}".strip() for e in self.errors)
        super().__init__(f"HTTP {status}: {msgs or 'request failed'}")

    def has(self, *needles):
        text = str(self).lower()
        return any(n in text for n in needles)


class Cloudflare:
    def __init__(self, token):
        self.token = token

    def _call(self, method, path, body=None, query=None):
        url = API + path + ("?" + urllib.parse.urlencode(query) if query else "")
        data = None if body is None else json.dumps(body).encode()
        req = urllib.request.Request(url, data=data, method=method, headers={
            "Authorization": f"Bearer {self.token}",
            "Content-Type": "application/json",
            "User-Agent": f"{TAG}/{__version__}",
        })
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                return resp.status, json.load(resp)
        except urllib.error.HTTPError as e:
            try:
                return e.code, json.load(e)
            except ValueError:
                raise CFError(e.code, [{"message": str(e.reason)}]) from None
        except urllib.error.URLError as e:
            raise CFError(0, [{"message": str(e.reason)}]) from None

    def rest(self, method, path, body=None, query=None):
        status, payload = self._call(method, path, body, query)
        if not payload.get("success"):
            raise CFError(status, payload.get("errors"))
        return payload

    def graphql(self, query, variables):
        status, payload = self._call("POST", "/graphql", {"query": query, "variables": variables})
        if payload.get("errors"):
            raise CFError(status, payload["errors"])
        return payload["data"]


# ---------------------------------------------------------------- config

def load_config(path):
    try:
        with open(path, "rb") as f:
            raw = tomllib.load(f)
    except FileNotFoundError:
        raise ConfigError(f"config not found: {path}") from None
    except tomllib.TOMLDecodeError as e:
        raise ConfigError(f"{path}: {e}") from None

    settings = raw.get("settings", {})
    defaults = raw.get("defaults", {})
    _check_keys(defaults, "[defaults]")
    base = {**ZONE_DEFAULTS, **defaults}

    zones = []
    for i, z in enumerate(raw.get("zones", [])):
        where = f"[[zones]] #{i + 1}"
        if not (z.get("name") or z.get("id")):
            raise ConfigError(f"{where}: needs name or id")
        over = {k: v for k, v in z.items() if k not in ("name", "id")}
        _check_keys(over, where)
        cfg = {**base, **over}
        cfg["allow"] = list(base["allow"]) + list(over.get("allow", [])) if "allow" in over else list(base["allow"])
        _validate(cfg, z.get("name") or z.get("id"))
        zones.append({"name": z.get("name"), "id": z.get("id"), "cfg": cfg})
    if not zones:
        raise ConfigError("no [[zones]] configured")
    return {"settings": settings, "zones": zones}


def _check_keys(d, where):
    unknown = set(d) - set(ZONE_DEFAULTS)
    if unknown:
        raise ConfigError(f"{where}: unknown keys: {', '.join(sorted(unknown))}")


def _validate(cfg, label):
    if cfg["mode"] not in MODES:
        raise ConfigError(f"{label}: mode must be one of {sorted(MODES)}")
    if cfg["scope"] not in SCOPES:
        raise ConfigError(f"{label}: scope must be zone or account")
    if cfg["ipv6_prefix"] not in V6_PREFIXES:
        raise ConfigError(f"{label}: ipv6_prefix must be one of {sorted(V6_PREFIXES)}")
    for key in ("threshold", "window_minutes", "ban_hours", "max_bans_per_run", "top"):
        if not isinstance(cfg[key], (int, float)) or cfg[key] <= 0:
            raise ConfigError(f"{label}: {key} must be a positive number")
    if cfg["window_minutes"] > 1440:
        raise ConfigError(f"{label}: window_minutes can be at most 1440")
    try:
        cfg["_allow"] = [ipaddress.ip_network(a, strict=False) for a in cfg["allow"]]
    except ValueError as e:
        raise ConfigError(f"{label}: allow: {e}") from None


def load_token(settings):
    if settings.get("api_token_file"):
        return Path(settings["api_token_file"]).read_text().strip()
    env = settings.get("api_token_env", "CF_API_TOKEN")
    token = os.environ.get(env, "").strip()
    if not token:
        raise ConfigError(f"no API token: set ${env} or settings.api_token_file")
    return token


# ---------------------------------------------------------------- helpers

def utcnow():
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0)


def iso(t):
    return t.strftime("%Y-%m-%dT%H:%M:%SZ")


def build_filter(cfg, now):
    flt = {"datetime_geq": iso(now - dt.timedelta(minutes=cfg["window_minutes"])), "datetime_lt": iso(now)}
    conds = []
    if cfg["exclude_cached"]:
        conds.append({"cacheStatus_neq": "hit"})
    conds += [{"clientRequestPath_notlike": p.rstrip("%*") + "%"} for p in cfg["exclude_paths"]]
    conds += [{"clientRequestPath_notlike": "%." + e.lstrip(".")} for e in cfg["exclude_extensions"]]
    if conds:
        flt["AND"] = conds
    return flt


def rule_target(ip, v6_prefix):
    addr = ipaddress.ip_address(ip)
    if addr.version == 4:
        return "ip", str(addr)
    if v6_prefix >= 128:
        return "ip6", str(addr)
    return "ip_range", str(ipaddress.ip_network(f"{addr}/{v6_prefix}", strict=False))


def norm(value):
    """Canonical form of an IP or range; Cloudflare stores IPv6 ranges fully expanded."""
    try:
        return str(ipaddress.ip_network(value, strict=False))
    except ValueError:
        return value


def is_allowed(ip, nets):
    addr = ipaddress.ip_address(ip)
    return any(addr in n for n in nets)


def make_note(until, zone, hits, window):
    return f"{TAG} until={iso(until)} zone={zone} hits={hits}/{window}m"


def note_until(note):
    for tok in (note or "").split():
        if tok.startswith("until="):
            try:
                return dt.datetime.strptime(tok[6:], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=dt.timezone.utc)
            except ValueError:
                return None
    return None


def scope_path(cfg, zone_id, account_id):
    return f"/accounts/{account_id}" if cfg["scope"] == "account" else f"/zones/{zone_id}"


# ---------------------------------------------------------------- API ops

def resolve_zone(cf, z):
    if z.get("id"):
        info = cf.rest("GET", f"/zones/{z['id']}")["result"]
    else:
        res = cf.rest("GET", "/zones", query={"name": z["name"]})["result"]
        if not res:
            raise CFError(404, [{"message": f"zone {z['name']} not found (or token lacks Zone:Read)"}])
        info = res[0]
    return info["id"], info["name"], info["account"]["id"]


def top_ips(cf, zone_id, cfg, now):
    data = cf.graphql(QUERY % int(cfg["top"]), {"zone": zone_id, "filter": build_filter(cfg, now)})
    zones = data["viewer"]["zones"]
    if not zones:
        return []
    return [(g["dimensions"]["clientIP"], int(g["count"])) for g in zones[0]["httpRequestsAdaptiveGroups"]]


def list_managed(cf, sp):
    rules, page = [], 1
    while True:
        p = cf.rest("GET", f"{sp}/firewall/access_rules/rules", query={"per_page": 100, "page": page, "notes": TAG})
        rules += [r for r in p["result"] if (r.get("notes") or "").startswith(TAG)]
        if page >= (p.get("result_info") or {}).get("total_pages", 1):
            return rules
        page += 1


def resolve_all(cf, conf):
    out = []
    for z in conf["zones"]:
        try:
            zid, zname, acc = resolve_zone(cf, z)
        except CFError as e:
            log.error("%s: %s", z.get("name") or z.get("id"), e)
            continue
        out.append((z["cfg"], zid, zname, acc))
    return out


def notify(settings, events):
    url = settings.get("notify_url")
    if not url or not events:
        return
    text = f"{TAG}:\n" + "\n".join(events)
    if settings.get("notify_format", "json") == "plain":
        body, ctype = text.encode(), "text/plain"
    else:
        body, ctype = json.dumps({"text": text, "content": text}).encode(), "application/json"
    req = urllib.request.Request(url, data=body, method="POST",
                                 headers={"Content-Type": ctype, "User-Agent": f"{TAG}/{__version__}"})
    try:
        urllib.request.urlopen(req, timeout=15).close()
    except Exception as e:  # notification must never break a run
        log.warning("notify failed: %s", e)


# ---------------------------------------------------------------- commands

def cmd_run(cf, conf, dry):
    now = utcnow()
    zones = resolve_all(cf, conf)
    events, managed = [], {}

    # 1. lift expired bans
    for sp in {scope_path(c, zid, acc) for c, zid, _, acc in zones}:
        try:
            managed[sp] = list_managed(cf, sp)
        except CFError as e:
            log.error("%s: cannot list access rules: %s", sp, e)
            managed[sp] = None
            continue
        for r in list(managed[sp]):
            until = note_until(r.get("notes"))
            if until is None or until > now:
                continue
            value = r["configuration"]["value"]
            if dry:
                log.info("[dry-run] would lift ban on %s", value)
            else:
                try:
                    cf.rest("DELETE", f"{sp}/firewall/access_rules/rules/{r['id']}")
                except CFError as e:
                    log.error("cannot lift ban on %s: %s", value, e)
                    continue
                log.info("lifted ban on %s", value)
            managed[sp].remove(r)
            events.append(f"unban {value}")

    # 2. find and ban heavy hitters
    for cfg, zid, zname, acc in zones:
        sp = scope_path(cfg, zid, acc)
        if managed.get(sp) is None:
            continue
        banned = {norm(r["configuration"]["value"]) for r in managed[sp]}
        try:
            hits = top_ips(cf, zid, cfg, now)
        except CFError as e:
            log.error("%s: analytics query failed: %s", zname, e)
            if e.has("budget", "rate limit"):
                log.warning("analytics budget exhausted; skipping the remaining zones this run")
                break
            continue
        log.debug("%s: top %s", zname, hits[:5])
        bans = 0
        for ip, count in hits:
            if count < cfg["threshold"]:
                break  # results are sorted by count
            if is_allowed(ip, cfg["_allow"]):
                log.info("%s: %s at %d req/%dm is allowlisted", zname, ip, count, cfg["window_minutes"])
                continue
            target, value = rule_target(ip, cfg["ipv6_prefix"])
            if norm(value) in banned:
                continue
            if bans >= cfg["max_bans_per_run"]:
                log.warning("%s: max_bans_per_run (%d) reached", zname, cfg["max_bans_per_run"])
                break
            until = now + dt.timedelta(hours=cfg["ban_hours"])
            msg = f"{cfg['mode']} {value} ({count} req/{cfg['window_minutes']}m on {zname}) until {iso(until)}"
            if dry:
                log.info("[dry-run] would %s", msg)
            else:
                body = {"mode": cfg["mode"], "configuration": {"target": target, "value": value},
                        "notes": make_note(until, zname, count, cfg["window_minutes"])}
                try:
                    res = cf.rest("POST", f"{sp}/firewall/access_rules/rules", body)
                except CFError as e:
                    if e.has("duplicate", "already exists"):
                        log.info("%s: %s already has an access rule, leaving it", zname, value)
                        banned.add(norm(value))
                        continue
                    log.error("%s: cannot ban %s: %s", zname, value, e)
                    continue
                managed[sp].append(res["result"])
                log.info(msg)
            banned.add(norm(value))
            bans += 1
            events.append(msg)

    if not dry:
        notify(conf["settings"], events)
    return events


def cmd_report(cf, conf):
    now = utcnow()
    for cfg, zid, zname, _ in resolve_all(cf, conf):
        try:
            hits = top_ips(cf, zid, cfg, now)
        except CFError as e:
            print(f"== {zname}: {e}")
            if e.has("budget", "rate limit"):
                return
            continue
        print(f"== {zname}  (last {cfg['window_minutes']}m, threshold {cfg['threshold']})")
        for ip, count in hits[:10]:
            flag = ""
            if count >= cfg["threshold"]:
                flag = "  allowlisted" if is_allowed(ip, cfg["_allow"]) else "  OVER"
            print(f"{count:>9}  {ip}{flag}")


def cmd_list(cf, conf):
    zones = resolve_all(cf, conf)
    for sp in sorted({scope_path(c, zid, acc) for c, zid, _, acc in zones}):
        for r in list_managed(cf, sp):
            print(f"{r['configuration']['value']:<45} {r['mode']:<18} {sp}  {r.get('notes', '')}")


def cmd_unban(cf, conf, ip, dry):
    addr = ipaddress.ip_address(ip)
    zones = resolve_all(cf, conf)
    found = False
    for sp in {scope_path(c, zid, acc) for c, zid, _, acc in zones}:
        for r in list_managed(cf, sp):
            value = r["configuration"]["value"]
            if addr not in ipaddress.ip_network(value, strict=False):
                continue
            found = True
            if dry:
                log.info("[dry-run] would lift ban on %s in %s", value, sp)
            else:
                cf.rest("DELETE", f"{sp}/firewall/access_rules/rules/{r['id']}")
                log.info("lifted ban on %s in %s", value, sp)
    if not found:
        log.info("no %s ban covers %s", TAG, ip)


def default_config_path():
    env = os.environ.get("CF_RATEWATCH_CONFIG")
    if env:
        return env
    etc = Path("/etc/cf-ratewatch/config.toml")
    return str(etc) if etc.exists() else "config.toml"


def main(argv=None):
    ap = argparse.ArgumentParser(prog=TAG, description="Hour-scale per-IP limits for Cloudflare zones.")
    ap.add_argument("-c", "--config", default=default_config_path(), help="path to config.toml")
    ap.add_argument("-n", "--dry-run", action="store_true", help="log what would change, change nothing")
    ap.add_argument("-v", "--verbose", action="store_true")
    ap.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = ap.add_subparsers(dest="cmd")
    sub.add_parser("run", help="lift expired bans, ban heavy hitters (default)")
    sub.add_parser("report", help="show top IPs per zone, change nothing")
    sub.add_parser("list", help="list bans managed by this tool")
    un = sub.add_parser("unban", help="lift the ban covering an IP")
    un.add_argument("ip")
    args = ap.parse_args(argv)

    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="%(asctime)s %(levelname)s %(message)s", datefmt="%Y-%m-%dT%H:%M:%S")
    try:
        conf = load_config(args.config)
        cf = Cloudflare(load_token(conf["settings"]))
        cmd = args.cmd or "run"
        if cmd == "run":
            cmd_run(cf, conf, args.dry_run)
        elif cmd == "report":
            cmd_report(cf, conf)
        elif cmd == "list":
            cmd_list(cf, conf)
        elif cmd == "unban":
            cmd_unban(cf, conf, args.ip, args.dry_run)
    except ConfigError as e:
        log.error("config: %s", e)
        return 2
    except CFError as e:
        log.error("%s", e)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
