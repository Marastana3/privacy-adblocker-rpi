# privacy-adblocker-rpi

Privacy-Preserving Network Ad-Blocking and Tracking Prevention System on Raspberry Pi.

A DNS-level ad and tracker blocker designed to run on a Raspberry Pi as your
network's DNS resolver. Blocked domains are sinkholed; everything else is
forwarded to an upstream resolver. Query logging is governed by configurable
**privacy modes**, so the device can run without ever recording the sites you
visit.

## How it works

The Pi runs a DNS server on the local network. When a device asks it to resolve
a domain:

1. **Whitelisted?** → forward upstream (explicit allow wins over any blocklist).
2. **On a blocklist?** → sinkhole it: `A` queries return the configured sinkhole
   IP (e.g. `0.0.0.0`), other record types (e.g. `AAAA`) return NODATA, so the
   domain can't resolve over IPv4 or IPv6.
3. **Otherwise** → forward to the upstream resolver (default Cloudflare `1.1.1.1`).
   If the upstream is unreachable the query degrades to `SERVFAIL` rather than
   crashing.

## Project layout

```
dns_engine/
  resolver.py          # DNS server + request handling (dnslib-based)
  forwarder.py         # forwards allowed queries to the upstream resolver
  block_engine.py      # decides blocked / whitelisted (suffix-set matching)
  blocklist_loader.py  # loads categorized blocklists from disk
  blocklists/          # ads.txt, trackers.txt, telemetry.txt, whitelist.txt
privacy/
  privacy_modes.py     # strict / balanced / debug logging + retention policy
config.yaml            # runtime configuration
tests/                 # unit tests (stdlib unittest)
```

## Configuration (`config.yaml`)

```yaml
dns:
  listen_host: "0.0.0.0"   # 127.0.0.1 for local dev; 0.0.0.0 to serve the LAN
  listen_port: 5300        # 5300 for dev (no root); 53 on the Pi
  upstream_dns: "1.1.1.1"
  upstream_port: 53
  sinkhole_ip: "0.0.0.0"
blocking:
  blocklists_dir: "dns_engine/blocklists"
privacy:
  mode: "strict"           # strict | balanced | debug
  logging_enabled: false
  retention_days: 7
```

### Privacy modes

| Mode     | Console logs | Stores raw queries | Stored client IP        |
|----------|:------------:|:------------------:|:------------------------|
| strict   | no           | no                 | none                    |
| balanced | yes (redacted domains) | no       | truncated prefix (/24, /48) |
| debug    | yes (full)   | yes                | full IP                 |

Query events are persisted to SQLite (`privacy.db_path`), but every write is
filtered through the active mode first: in strict mode rows keep only the
aggregate facts (blocked yes/no, category, timestamp) — never the domain or the
client IP. Events older than `retention_days` are pruned on startup and hourly.
Aggregate stats and top-blocked domains are available via `QueryStore.stats()`
and `QueryStore.top_blocked_domains()` (the latter is empty unless the mode
stored raw domains).

## Requirements

- Python 3.9+
- `dnslib`, `PyYAML` (see `requirements.txt`)

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Run locally (on your Mac, no root)

With `listen_port: 5300` in `config.yaml`:

```bash
python3 -m dns_engine.resolver
```

Test it from another terminal (add `dnslib` to path or use `dig`):

```bash
dig @127.0.0.1 -p 5300 example.com        # resolves normally
dig @127.0.0.1 -p 5300 doubleclick.net    # returns 0.0.0.0 (blocked)
```

Point a different config file with `PAB_CONFIG=/path/to/config.yaml`.

## Running on the Raspberry Pi

Use port `53` (needs root) and set `listen_host: "0.0.0.0"`. Port 53 is usually
held by `systemd-resolved` — free it first. See
[`pi-boot-and-first-dns-milestone.md`](pi-boot-and-first-dns-milestone.md) for
the full headless-Pi + port-53 walkthrough.

## Tests

```bash
python3 -m unittest discover -s tests -v
```

## Roadmap

See [`ROADMAP.md`](ROADMAP.md) for the full plan through the privacy layer,
FastAPI backend, React dashboard, Pi deployment, and evaluation.
