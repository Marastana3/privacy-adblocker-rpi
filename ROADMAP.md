# privacy-adblocker-rpi — Roadmap to Completion

Status legend: ✅ done · 🔨 in progress · ⬜ not started

This is the full path from the current DNS MVP to a finished thesis project (working system + evaluation). Phases are ordered so each builds on the last. Phase 0 is pure code and can be finished on your Mac now; the Pi is only needed from Phase 5.

---

## Phase 0 — Harden the DNS core  🔨
The resolver works but needs to be robust and tested before building on top of it.

- ✅ Fix `main()` startup crash (privacy_mode used before assignment + constructor mismatch)
- ✅ Wire privacy mode into logging (strict = silent, debug = verbose, redact unless `store_raw_queries`)
- ✅ Block IPv6 too (blocked `AAAA` returns NODATA instead of forwarding)
- ⬜ Rename `dns_engine/forwader.py` → `forwarder.py` (fix typo before it spreads)
- ⬜ Make upstream forwarding fault-tolerant (return SERVFAIL on network/timeout instead of throwing)
- ⬜ Blocklist performance: replace per-query O(n) scan with suffix-set lookup (scales to 100k+ domains)
- ⬜ Unit tests: block engine, blocklist loader, privacy modes, resolver decisions
- ⬜ README with setup + run instructions

## Phase 1 — Privacy layer  ✅
The privacy modes now drive exactly what gets persisted. This is the thesis's core contribution.

- ✅ Storage backend (SQLite) for query events + aggregated stats (`privacy/storage.py`)
- ✅ Anonymizer: per-mode client-IP handling — drop / truncate (IPv4 /24, IPv6 /48) / raw (`privacy/anonymizer.py`)
- ✅ Aggregator: counts (total, blocked, per-category) + top-blocked, without storing raw domains in strict/balanced
- ✅ Retention enforcement: honor `retention_days`, prune on startup + hourly background thread
- ✅ Tests proving strict persists no domain/IP, balanced truncates IP, debug stores both (verified live end-to-end)

## Phase 2 — Policy & consent layer  ✅
- ✅ Per-category blocking toggles — enable/disable ads/trackers/telemetry/custom
  independently, at config load or runtime (`BlockEngine.set_category_enabled`)
- ✅ Whitelist/blacklist management at runtime, persisted to the list files and
  applied to the live engine (`dns_engine/list_manager.py`)
- ✅ Remote blocklist sources: fetch + parse public hosts/plain lists, merge with
  local entries (`dns_engine/updater.py`; fetcher injectable, parser tested offline)
- ✅ Consent/transparency: startup disclosure of exactly what the active mode
  retains (`describe_retention`)

## Phase 3 — FastAPI backend  ⬜
- ⬜ REST API: stats, block history (privacy-filtered), config, privacy-mode control
- ⬜ Blocklist/whitelist management endpoints
- ⬜ Wire API to the DNS engine + storage
- ⬜ Basic auth for the dashboard
- ⬜ API tests

## Phase 4 — React dashboard  ⬜
- ⬜ Overview: queries over time, block rate, top blocked categories
- ⬜ Controls: toggle categories, switch privacy mode, manage whitelist
- ⬜ Consume the FastAPI backend
- ⬜ (the `frontend/` folder already exists as a placeholder)

## Phase 5 — Deployment on the Raspberry Pi  ⬜
- ⬜ Headless Pi boot + SSH access (see `pi-boot-and-first-dns-milestone.md`)
- ⬜ Free port 53 (disable `systemd-resolved` stub) + run resolver on 53
- ⬜ Run as a `systemd` service (survives reboot)
- ⬜ Fill in `docker-compose.yml` (currently empty) for containerized deploy
- ⬜ Point a real client at the Pi and confirm end-to-end blocking

## Phase 6 — Testing & evaluation (thesis)  ⬜
- ⬜ Integration tests (full query → block/forward path)
- ⬜ Evaluation: block effectiveness (% ads/trackers stopped), DNS latency, Pi CPU/RAM
- ⬜ Privacy evaluation: demonstrate what each mode does/doesn't retain
- ⬜ Write-up: architecture, methodology, results

---

**Working now (Phase 0):** rename fix → fault-tolerant forwarding → blocklist performance → tests → README.
Everything through Phase 4 is doable on your MacBook; the Pi comes in at Phase 5.
