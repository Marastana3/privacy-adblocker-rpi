#!/usr/bin/env python3
"""Run the DNS resolver and the HTTP API together in one process.

Both share the same BlockEngine, ListManager, and QueryStore, so a category
toggle or list edit made in the dashboard takes effect on live DNS resolution
immediately (no restart, no file round-trip).

    python run.py                 # uses config.yaml (or $PAB_CONFIG)
    PAB_API_KEY=secret python run.py

The DNS server needs port 53 in production (run as root / via systemd). The HTTP
API listens on api.host:api.port from config (default 0.0.0.0:8000).
"""
from __future__ import annotations

import os

from dns_engine.resolver import (
    PrivacyAdblockResolver,
    _start_retention_pruner,
    build_dns_server,
    load_config,
    resolve_db_path,
)
from privacy.privacy_modes import describe_retention, get_mode
from privacy.storage import QueryStore
from app.service import AdblockService
from app.api import create_app


def build():
    here = os.path.dirname(os.path.abspath(__file__))
    cfg_path = os.environ.get("PAB_CONFIG", os.path.join(here, "config.yaml"))
    cfg = load_config(cfg_path)

    privacy_mode = get_mode(cfg.privacy_mode)
    store = QueryStore(resolve_db_path(cfg, here), privacy_mode)
    store.prune(cfg.retention_days)
    _start_retention_pruner(store, cfg.retention_days)

    resolver = PrivacyAdblockResolver(cfg, privacy_mode, store)

    # The API service shares the resolver's live engine + list manager + store.
    service = AdblockService(
        engine=resolver.block_engine,
        list_manager=resolver.list_manager,
        store=store,
        privacy_mode=privacy_mode,
        blocklists_dir=cfg.blocklists_dir,
        remote_sources=getattr(cfg, "remote_sources", None),
    )
    app = create_app(service, api_key=os.environ.get("PAB_API_KEY"))
    return cfg, privacy_mode, resolver, store, app


def main():
    import uvicorn

    cfg, privacy_mode, resolver, store, app = build()

    print(f"[PRIVACY] Mode: {privacy_mode.name}")
    print(f"[PRIVACY] Retention: {describe_retention(privacy_mode)}")

    server = build_dns_server(cfg, resolver, privacy_mode)
    server.start_thread()
    print(f"[DNS] Listening on {cfg.listen_host}:{cfg.listen_port} (upstream {cfg.upstream_dns})")
    print(f"[API] Listening on {cfg.api_host}:{cfg.api_port}")

    try:
        uvicorn.run(app, host=cfg.api_host, port=cfg.api_port)
    finally:
        store.close()


if __name__ == "__main__":
    main()
