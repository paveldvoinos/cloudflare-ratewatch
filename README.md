# cf-ratewatch

Hour-scale per-IP request limits for Cloudflare zones, **Free plan included**.

Cloudflare's Free rate limiting counts requests over 10 seconds and blocks for 10 seconds,
with one rule per zone. That stops floods, but not the common slow attacker: a vulnerability
scanner doing 1–3 requests per second for hours stays under any 10-second limit a human
visitor could live with.

cf-ratewatch counts requests per client IP over a longer window (default: 60 minutes) using the
GraphQL Analytics API, and blocks IPs over a threshold with **IP Access Rules**. The rules
expire on their own after a ban period. It is a single Python file with no dependencies, run from
cron or a systemd timer.

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

IP Access Rules do not use up your custom rule slots (Free: 5), and you can have up to 50,000 of
them. They can apply to one zone or, with `scope = "account"`, to every zone in the account, so an
IP caught scanning one site is blocked on all of them.

## Install

Requires Python 3.11+.

```sh
sudo git clone https://github.com/paveldvoinos/cloudflare-ratewatch /opt/cf-ratewatch
sudo mkdir -p /etc/cf-ratewatch
sudo cp /opt/cf-ratewatch/config.example.toml /etc/cf-ratewatch/config.toml
sudoedit /etc/cf-ratewatch/config.toml
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

### Try it

```sh
export CF_API_TOKEN=...
python3 /opt/cf-ratewatch/cf_ratewatch.py report         # top IPs per zone, changes nothing
python3 /opt/cf-ratewatch/cf_ratewatch.py --dry-run run  # what it would ban
```

Start with `report` for a few days to see what normal peaks look like on your zones, then set the
thresholds well above them.

### Schedule

systemd (the token is passed as a credential):

```sh
sudo install -m 600 /dev/stdin /etc/cf-ratewatch/token <<< "your-token"
# in config.toml: api_token_file = "/run/credentials/cf-ratewatch.service/cf_api_token"
sudo cp /opt/cf-ratewatch/contrib/cf-ratewatch.{service,timer} /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now cf-ratewatch.timer
journalctl -u cf-ratewatch -f
```

or cron:

```cron
*/10 * * * * CF_API_TOKEN=... /usr/bin/python3 /opt/cf-ratewatch/cf_ratewatch.py -c /etc/cf-ratewatch/config.toml run
```

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

## Tests

```sh
python3 -m unittest discover -s tests
```

The tests run against a fake Cloudflare API on localhost; no token or network needed.

## License

MIT
