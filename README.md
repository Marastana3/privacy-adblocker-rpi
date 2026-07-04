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

## Policy controls

**Category toggles.** Each blocklist file is a category (`ads`, `trackers`,
`telemetry`, `custom`, …). Disable one to keep its list loaded but stop enforcing
it — set `blocking.disabled_categories: ["telemetry"]` in config, or flip it at
runtime with `BlockEngine.set_category_enabled("telemetry", False)`.

**Runtime allow/block.** `ListManager` (`dns_engine/list_manager.py`) adds or
removes domains from the whitelist or a `custom` blocklist, writing through to the
files *and* the live engine so changes persist and take effect immediately.

**Remote blocklists.** `RemoteBlocklistUpdater` (`dns_engine/updater.py`) fetches
public lists (hosts or plain-domain format), parses and de-dupes them, and merges
with your local entries. Configure sources under `blocking.remote_sources`.

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

## HTTP API (dashboard backend)

A FastAPI app exposes the engine, stats, and policy controls for the dashboard.

```bash
pip install -r requirements.txt
uvicorn app.api:app --host 0.0.0.0 --port 8000
# require an API key on write endpoints:
PAB_API_KEY=your-secret uvicorn app.api:app
```

| Method & path                 | Purpose                                  |
|-------------------------------|------------------------------------------|
| `GET /health`                 | liveness check                           |
| `GET /stats`                  | total / blocked / allowed / by-category  |
| `GET /stats/top-blocked`      | most-blocked domains (if mode stores them) |
| `GET /privacy`                | active mode + retention disclosure       |
| `GET /categories`             | categories and their enabled state       |
| `POST /categories/{name}`     | enable/disable a category                |
| `GET/POST /lists/whitelist`   | list / add allowed domains               |
| `DELETE /lists/whitelist/{d}` | remove an allowed domain                 |
| `GET/POST /lists/block`       | list / add blocked domains               |
| `DELETE /lists/block/{d}`     | remove a blocked domain                  |
| `POST /blocklists/update`     | fetch + merge configured remote sources  |

Write endpoints require the `X-API-Key` header when `PAB_API_KEY` is set. Logic
lives in `app/service.py` (framework-agnostic, unit-tested); `app/api.py` is a
thin wrapper.

## Dashboard (React)

A Vite + React dashboard in `frontend/` shows activity and manages categories,
the whitelist, and a custom blocklist.

```bash
cd frontend
npm install
cp .env.example .env      # point VITE_API_BASE at the backend (default :8000)
npm run dev               # http://localhost:5173
```

For a single-process deploy on the Pi, build it and let FastAPI serve it:

```bash
cd frontend && npm run build      # outputs frontend/dist
uvicorn app.api:app --host 0.0.0.0 --port 8000   # serves the dashboard at /
```

If the API is started with `PAB_API_KEY`, enter that key in the dashboard header
so write actions (toggles, add/remove) are authorized.

## Tests

```bash
python3 -m unittest discover -s tests -v
```

## Roadmap

See [`ROADMAP.md`](ROADMAP.md) for the full plan through the privacy layer,
FastAPI backend, React dashboard, Pi deployment, and evaluation.
