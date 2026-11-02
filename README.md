# cf-ratewatch

[![CI](https://github.com/paveldvoinos/cloudflare-ratewatch/actions/workflows/ci.yml/badge.svg)](https://github.com/paveldvoinos/cloudflare-ratewatch/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/paveldvoinos/cloudflare-ratewatch?include_prereleases)](https://github.com/paveldvoinos/cloudflare-ratewatch/releases)

Hour-scale per-IP request limits for Cloudflare zones, **Free plan included**.

Cloudflare's Free rate limiting counts requests over 10 seconds and blocks for 10 seconds,
with one rule per zone. That stops floods, but not the common slow attacker: a vulnerability
scanner doing 1–3 requests per second for hours stays under any 10-second limit a human
visitor could live with.

cf-ratewatch counts requests per client IP over a longer window (default: 60 minutes) using the
GraphQL Analytics API, and blocks IPs over a threshold with **IP Access Rules**. The rules
expire on their own after a ban period. Run it either way:

- **on your server**: a single Python file with no dependencies, from a systemd timer or cron
  (a `.deb` is attached to every release);
- **on Cloudflare Workers**: a Cron Trigger on the Workers Free plan, no server at all.

Both use the same configuration schema and the same rule notes, so you can move between them.

### Real example

A small PrestaShop shop on the Free plan. A VPS ran an automated SQL-injection scanner against it
for 14 hours: ~80,000 requests, half of them POSTs to every form, at about 1.6 requests per second.
The zone's 120-requests-per-10-seconds rule fired 72 times and never stopped it. In the scanner's
busiest hour this tool's query showed:

```
8132  <scanner IP>
 378  <another scanner>
   8  66.249.67.64   (Googlebot)
```

With a threshold of 1000 per hour the scanner would have been blocked about 25 minutes after it
started.

## How it works

Each run:

1. Lifts expired bans. Every rule it creates carries a note like
   `cf-ratewatch until=2026-11-01T10:00:00Z zone=example.com hits=8132/60m`. Rules it did not
   create are never touched.
2. Asks the Analytics API for the top client IPs of each zone over the window. This is one query
   per zone. Cache hits and paths you exclude are not counted.
3. Creates an IP Access Rule (`block`, or a challenge) for every IP at or over the threshold,
   except allowlisted ones, up to `max_bans_per_run` per zone.
4. Writes metrics for Prometheus and/or InfluxDB, if configured (see [Metrics](#metrics-and-grafana)).

IP Access Rules do not use up your custom rule slots (Free: 5), and you can have up to 50,000 of
them. They can apply to one zone or, with `scope = "account"`, to every zone in the account, so an
IP caught scanning one site is blocked on all of them.

## Install

The server version needs Python 3.11+ (Debian 12, Ubuntu 24.04, Proxmox VE 8 and newer); the
Worker needs only a Cloudflare account.

### Debian / Ubuntu package

Download the `.deb` from the [latest release](https://github.com/paveldvoinos/cloudflare-ratewatch/releases/latest),
then:

```sh
sudo apt install ./cf-ratewatch_*_all.deb
sudoedit /etc/cf-ratewatch/config.toml                       # zones and thresholds
sudo install -m 600 /dev/stdin /etc/cf-ratewatch/token       # paste the API token, Ctrl-D
sudo cf-ratewatch report                                     # top IPs per zone, changes nothing
sudo systemctl enable --now cf-ratewatch.timer               # every 10 minutes
journalctl -u cf-ratewatch -f
```

The package installs `/usr/bin/cf-ratewatch`, the systemd service and timer, a `cf-ratewatch`
system user, and `/etc/cf-ratewatch/config.toml` as a conffile, so your edits survive upgrades.
It does not enable the timer by itself. `apt purge` removes the config and the token; bans already
in Cloudflare stay until they expire (or `cf-ratewatch unban` them first).

### Cloudflare Workers

[![Deploy to Cloudflare](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/paveldvoinos/cloudflare-ratewatch/tree/main/worker)

The button copies [`worker/`](worker) into a repository of yours, creates the KV namespace and
asks for the secrets. Or deploy by hand:

```sh
cd worker
npm install
$EDITOR wrangler.jsonc                         # CONFIG: zones and thresholds (JSON, same schema as config.example.toml)
npx wrangler secret put CF_API_TOKEN           # same token permissions as below
npx wrangler secret put METRICS_TOKEN          # optional, enables GET /metrics
npx wrangler deploy
npx wrangler tail                              # watch a run (every 10 minutes)
```

The Worker starts with `DRY_RUN = "true"`: it logs the top IPs and what it would ban, and changes
nothing. When the logs look right, set `DRY_RUN` to `"false"` and deploy again.

It fits the Workers Free plan:

- **CPU**: a run is network waits plus a few small JSON documents, far below the 10 ms limit.
- **Subrequests** (50 per run on Free): one analytics query per zone, one rule listing per scope,
  one call per ban or lifted ban. Zone ids are cached in KV for a day. `scope = "account"` needs a
  single rule listing for all zones, so a few dozen zones fit. A run stops cleanly at 45 API calls
  (`MAX_SUBREQUESTS`) and picks up on the next run.
- **KV**: one write per run for the metrics. Keep the cron at every 2 minutes or slower (Free allows
  1,000 writes a day), or set `"metrics_kv": false` under `settings`.

Differences from the Python version: the configuration is the `CONFIG` variable (JSON) instead of
TOML, the token is the `CF_API_TOKEN` secret, and `metrics_file` is replaced by the `/metrics`
endpoint below. Run one of the two at a time; bans created by either are lifted by the other.

### From source

```sh
sudo git clone https://github.com/paveldvoinos/cloudflare-ratewatch /opt/cf-ratewatch
sudo useradd --system --user-group --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin cf-ratewatch
sudo install -d -m 750 -g cf-ratewatch /etc/cf-ratewatch
sudo install -m 644 /opt/cf-ratewatch/config.example.toml /etc/cf-ratewatch/config.toml
sudoedit /etc/cf-ratewatch/config.toml
sudo install -m 600 /dev/stdin /etc/cf-ratewatch/token       # paste the API token, Ctrl-D
sudo cp /opt/cf-ratewatch/contrib/cf-ratewatch.{service,timer} /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now cf-ratewatch.timer
```

or with cron instead of systemd:

```cron
*/10 * * * * CF_API_TOKEN=... /usr/bin/python3 /opt/cf-ratewatch/cf_ratewatch.py -c /etc/cf-ratewatch/config.toml run
```

### API token

Create a token at *My Profile → API Tokens → Create Token → Custom token* with:

| Permission | Why |
| --- | --- |
| Zone · Zone · Read | resolve zone names |
| Zone · Analytics · Read | count requests per IP |
| Zone · Firewall Services · Edit | create and delete zone IP Access Rules |
| Account · Account Firewall Access Rules · Edit | only if you use `scope = "account"` |

Limit the zone resources to the zones you configure.

The token is read from the first of: the systemd credential `cf_api_token` (the unit loads
`/etc/cf-ratewatch/token`, so the service user never needs to read that file),
`settings.api_token_file`, then the environment variable `settings.api_token_env`
(default `CF_API_TOKEN`).

### Before enabling it

Run `report` for a few days to see what normal peaks look like on your zones, then set the
thresholds well above them. `--dry-run run` shows what would be banned without banning.

## Configuration

See [`config.example.toml`](config.example.toml). Everything under `[defaults]` can be overridden
per zone. `allow` is merged: the zone's own list is added to the default one.

| Key | Default | Meaning |
| --- | --- | --- |
| `window_minutes` | 60 | Count requests over the last N minutes (max 1440) |
| `threshold` | 1000 | Requests in the window that trigger a ban |
| `ban_hours` | 24 | Ban duration |
| `mode` | `block` | `block`, `managed_challenge`, `challenge`, `js_challenge` |
| `scope` | `zone` | `zone` or `account` |
| `exclude_cached` | true | Don't count cache hits |
| `exclude_paths` | [] | Path prefixes that never count (admin panels, webhooks) |
| `exclude_extensions` | [] | File extensions that never count |
| `allow` | [] | IPs/CIDRs that are never banned |
| `ipv6_prefix` | 64 | IPv6 ban granularity: 32, 48, 64 or 128 |
| `max_bans_per_run` | 20 | Safety cap per zone per run |
| `top` | 25 | How many top IPs to fetch per zone |

`[settings]` (all optional):

| Key | Type | Meaning |
| --- | --- | --- |
| `api_token_file` | path | Cloudflare API token file (after the systemd credential) |
| `api_token_env` | name | Environment variable with the token (default `CF_API_TOKEN`) |
| `notify_url` | URL | Webhook called after a run that banned or lifted something |
| `notify_format` | `json` or `plain` | `json`: `{"text", "content"}` (Slack, Discord); `plain`: raw text (ntfy) |
| `metrics_file` | path | Prometheus text file, see [Metrics](#metrics-and-grafana) |
| `influx_url` | URL | InfluxDB write endpoint |
| `influx_token_file`, `influx_token_env` | path, name | InfluxDB token |
| `influx_top_ips` | whole number | Top IPs per zone written to InfluxDB (default 5) |
| `metrics_kv` | true/false | Workers only: keep metrics in KV for `/metrics` (default true) |

The config is checked strictly before anything runs: an unknown key or section, or a value of the
wrong type (`exclude_paths = "/adm"` instead of `["/adm"]`, `threshold = true`) stops with exit
code 2 and says what is wrong, with a suggestion for misspelled keys.

## Metrics and Grafana

Optional, and either or both. Metrics are written after every run (not in `--dry-run`); a failing
metrics target is logged and never fails the run.

The most useful panel is **top single-IP requests per window vs threshold** per zone: it shows how
close normal traffic gets to the threshold, which is what you need to tune it.

### Prometheus

```toml
[settings]
metrics_file = "/var/lib/cf-ratewatch/cf_ratewatch.prom"
```

The file is for node_exporter's
[textfile collector](https://github.com/prometheus/node_exporter#textfile-collector):
run node_exporter with `--collector.textfile.directory=/var/lib/cf-ratewatch`, or symlink the file
into the directory you already use. The systemd unit creates `/var/lib/cf-ratewatch` via
`StateDirectory`. Counters (`*_total`) are carried over from the previous file, so they keep growing
across runs and `increase()` works.

| Metric | Type | Labels |
| --- | --- | --- |
| `cf_ratewatch_top_requests` | gauge | zone |
| `cf_ratewatch_threshold` | gauge | zone |
| `cf_ratewatch_ips_over_threshold` | gauge | zone |
| `cf_ratewatch_zone_query_success` | gauge | zone |
| `cf_ratewatch_active_bans` | gauge | scope (`zone:<name>` or `account:<id>`) |
| `cf_ratewatch_bans_total` | counter | zone |
| `cf_ratewatch_bans_lifted_total` | counter | |
| `cf_ratewatch_errors_total` | counter | |
| `cf_ratewatch_run_success` | gauge | |
| `cf_ratewatch_last_run_timestamp_seconds` | gauge | |
| `cf_ratewatch_run_duration_seconds` | gauge | |

IPs are never used as labels. A useful alert: `time() - cf_ratewatch_last_run_timestamp_seconds > 1800`.

On Cloudflare Workers the same metrics are served at `GET /metrics` on the Worker's `workers.dev`
address, protected by the `METRICS_TOKEN` secret (the endpoint is off without it):

```yaml
scrape_configs:
  - job_name: cf-ratewatch
    scheme: https
    authorization:
      credentials: <METRICS_TOKEN>
    static_configs:
      - targets: ["cf-ratewatch.<your-subdomain>.workers.dev"]
```

### InfluxDB

```toml
[settings]
influx_url = "http://influx:8086/api/v2/write?org=home&bucket=cloudflare"   # v1: /write?db=cloudflare
influx_token_env = "INFLUX_TOKEN"
```

One point per measurement per run, timestamped at the run:

| Measurement | Tags | Fields |
| --- | --- | --- |
| `cf_ratewatch_zone` | zone | `top_requests`, `threshold`, `over_threshold`, `bans`, `query_ok` |
| `cf_ratewatch_top` | zone, rank | `ip`, `requests` (top `influx_top_ips` IPs, default 5) |
| `cf_ratewatch_ban` | zone, mode, seq | `ip`, `hits`, `until` (one point per ban) |
| `cf_ratewatch_run` | | `active_bans`, `lifted`, `errors`, `duration` |

IPs are fields, not tags, so they don't grow series cardinality.

On Cloudflare Workers, set `influx_url` in `CONFIG` and the token as the `INFLUX_TOKEN` secret.
InfluxDB has to be reachable from the internet; if it sits behind Cloudflare Access (for example
through a Tunnel), add an Access service token as the `CF_ACCESS_CLIENT_ID` and
`CF_ACCESS_CLIENT_SECRET` secrets.

### Dashboards

Import [`contrib/grafana/prometheus.json`](contrib/grafana/prometheus.json) or
[`contrib/grafana/influxdb.json`](contrib/grafana/influxdb.json) (*Dashboards → New → Import*) and
pick your data source. The InfluxDB dashboard uses InfluxQL, which InfluxDB 1.x speaks natively;
on 2.x add a DBRP mapping for the bucket, or use an InfluxQL data source on 3.x.

## Commands

```
cf_ratewatch.py [-c config.toml] [--dry-run] [-v] run      # default
cf_ratewatch.py report                                     # top IPs, no changes
cf_ratewatch.py list                                       # bans managed by cf-ratewatch
cf_ratewatch.py unban 203.0.113.9                          # lift the ban covering an IP
```

Config path: `-c`, else `$CF_RATEWATCH_CONFIG`, else `/etc/cf-ratewatch/config.toml`, else
`./config.toml`.

## Things to know

- **Analytics lag and sampling.** Cloudflare analytics arrive a few minutes late, and the counts
  are sampled estimates. This tool is for hour-scale abuse, not for stopping a burst. Keep
  Cloudflare's own rate limiting rule for that.
- **Analytics budget.** The GraphQL API has a query budget, and on Free zones it is small. One
  query per zone per run is cheap, but heavy ad-hoc querying from the dashboard or other tools
  shares the same budget. When it is exhausted the run logs a warning and skips the remaining
  zones; the next run continues normally.
- **Shared addresses.** Offices, campuses and mobile carriers (CGNAT) put many people behind one
  IP. Allowlist known ones, or use `mode = "managed_challenge"` so real people can still get in.
- **Bots.** Free-plan analytics can't tell verified bots apart, so set thresholds well above what
  search engines and your monitoring do (usually tens per hour), or allowlist them.
- **Repeat offenders.** Blocked requests still count, so an IP that keeps hammering during its ban
  is banned again right after the ban expires.

## Development

```sh
python3 -m unittest discover -s tests        # fake Cloudflare API on localhost, no token or network
ruff check .
packaging/build-deb.sh                       # dist/cf-ratewatch_<version>_all.deb
cd worker && npm test                        # Worker, same fake-API scenarios
cd worker && npm run dev                     # local workerd; trigger a run: curl "localhost:8787/__scheduled"
```

The two implementations share [`tests/vectors.json`](tests/vectors.json): analytics filters, rule
targets, IP normalisation, config merging and validation, InfluxDB lines and Prometheus text, which
both test suites check. After an intentional change, regenerate it with
`python3 tests/make_vectors.py` and review the diff.

CI runs the Python tests (3.11–3.13), the Worker tests and a `wrangler deploy --dry-run`, and the
linters (ruff, shellcheck, actionlint, `systemd-analyze verify`) on every push and pull request.

To release, set the version in `cf_ratewatch.py`, `worker/src/core.js` and `worker/package.json`,
commit, and push a matching tag:

```sh
git tag v0.3.0 && git push origin v0.3.0      # v0.3.0-rc1 makes a pre-release
```

The release workflow runs CI again, builds the `.deb`, checks it with lintian, installs and purges
it on a clean runner, then creates the GitHub release with the package and `SHA256SUMS` attached.

## License

MIT
