from __future__ import annotations
from privacy.privacy_modes import PrivacyMode, describe_retention, get_mode

import os
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

import yaml
from dnslib import A, DNSHeader, DNSRecord, QTYPE, RCODE, RR
from dnslib.server import BaseResolver, DNSLogger, DNSServer

from dns_engine.block_engine import BlockEngine
from dns_engine.blocklist_loader import load_blocklists
from dns_engine.forwarder import DNSForwarder
from dns_engine.list_manager import ListManager
from privacy.storage import QueryStore


@dataclass
class AppConfig:
    listen_host: str
    listen_port: int
    upstream_dns: str
    upstream_port: int
    sinkhole_ip: str
    blocklists_dir: str
    privacy_mode: str
    db_path: str
    retention_days: int
    disabled_categories: List[str] = field(default_factory=list)
    api_host: str = "0.0.0.0"
    api_port: int = 8000


def load_config(path: str) -> AppConfig:
    with open(path, "r", encoding="utf-8") as f:
        raw: Dict[str, Any] = yaml.safe_load(f) or {}

    dns = raw.get("dns", {})
    blocking = raw.get("blocking", {})
    privacy = raw.get("privacy", {})
    api = raw.get("api", {})

    return AppConfig(
        listen_host=str(dns.get("listen_host", "0.0.0.0")),
        listen_port=int(dns.get("listen_port", 5300)),
        upstream_dns=str(dns.get("upstream_dns", "1.1.1.1")),
        upstream_port=int(dns.get("upstream_port", 53)),
        sinkhole_ip=str(dns.get("sinkhole_ip", "0.0.0.0")),
        blocklists_dir=str(blocking.get("blocklists_dir", "dns_engine/blocklists")),
        privacy_mode=str(privacy.get("mode", "strict")),
        db_path=str(privacy.get("db_path", "adblocker.db")),
        retention_days=int(privacy.get("retention_days", 7)),
        disabled_categories=list(blocking.get("disabled_categories", []) or []),
        api_host=str(api.get("host", "0.0.0.0")),
        api_port=int(api.get("port", 8000)),
    )


def build_dns_server(
    cfg: AppConfig, resolver: "PrivacyAdblockResolver", privacy_mode: PrivacyMode
) -> DNSServer:
    """Construct a DNSServer with a privacy-aware logger.

    dnslib's default logger prints every request/reply (including the queried
    domain), which would leak data in strict mode, so request/reply logging is
    only enabled when the mode permits storing raw queries.
    """
    if privacy_mode.store_raw_queries:
        dns_logger = DNSLogger("request,reply,truncated,error", prefix=False)
    else:
        dns_logger = DNSLogger("truncated,error", prefix=False)
    return DNSServer(
        resolver,
        logger=dns_logger,
        port=cfg.listen_port,
        address=cfg.listen_host,
        tcp=False,
    )


def resolve_db_path(cfg: AppConfig, repo_root: str) -> str:
    db_path = cfg.db_path
    if not os.path.isabs(db_path):
        db_path = os.path.join(repo_root, db_path)
    return db_path


class PrivacyAdblockResolver(BaseResolver):
    def __init__(
        self,
        cfg: AppConfig,
        privacy_mode: PrivacyMode,
        store: Optional[QueryStore] = None,
    ):
        categorized_blocklists = load_blocklists(cfg.blocklists_dir)
        self.block_engine = BlockEngine(
            categorized_blocklists, disabled_categories=cfg.disabled_categories
        )
        self.list_manager = ListManager(cfg.blocklists_dir, self.block_engine)
        self.forwarder = DNSForwarder(cfg.upstream_dns, cfg.upstream_port)
        self.sinkhole_ip = cfg.sinkhole_ip
        self.privacy = privacy_mode
        self.store = store

    def _log(self, tag: str, domain: str, qtype: str, extra: str = "") -> None:
        """Console logging that respects the active privacy mode.

        In strict mode (log_to_console=False) nothing is printed. When console
        logging is on but raw queries are not stored, the domain is redacted so
        we never write the actual sites someone visited to the terminal.
        """
        if not self.privacy.log_to_console:
            return
        shown = domain if self.privacy.store_raw_queries else "<redacted>"
        line = f"[{tag}] domain={shown} type={qtype}"
        if extra:
            line += f" {extra}"
        print(line)

    def _forward(self, request: DNSRecord, qname: str, qtype: str) -> DNSRecord:
        """Forward upstream, degrading to SERVFAIL if the upstream is
        unreachable so a network blip never crashes the request handler."""
        try:
            return self.forwarder.forward(request)
        except Exception as exc:  # noqa: BLE001 - any socket/parse error -> SERVFAIL
            self._log("SERVFAIL", qname, qtype, f"upstream_error={exc!r}")
            reply = request.reply()
            reply.header.rcode = RCODE.SERVFAIL
            return reply

    def _record(self, qname: str, qtype: str, decision, handler) -> None:
        """Persist the query event. The store itself applies the privacy
        policy (domain/IP redaction), so we hand it the raw values."""
        if self.store is None:
            return
        client_ip = None
        if handler is not None and getattr(handler, "client_address", None):
            client_ip = handler.client_address[0]
        self.store.record(
            blocked=decision.blocked,
            category=decision.category,
            qtype=qtype,
            domain=qname.rstrip("."),
            client_ip=client_ip,
        )

    def resolve(self, request: DNSRecord, handler):
        qname = str(request.q.qname)
        qtype = QTYPE[request.q.qtype]

        decision = self.block_engine.is_blocked(qname)
        self._record(qname, qtype, decision, handler)

        if decision.category == "whitelist":
            self._log("WHITELISTED", qname, qtype, f"reason={decision.reason}")
            return self._forward(request, qname, qtype)

        if decision.blocked:
            self._log(
                "BLOCKED", qname, qtype,
                f"category={decision.category} reason={decision.reason}",
            )
            reply = DNSRecord(
                DNSHeader(id=request.header.id, qr=1, aa=1, ra=1),
                q=request.q,
            )
            # Sinkhole A queries to the configured IP. For any other record
            # type (AAAA, etc.) we return NOERROR with no answer (NODATA) so the
            # domain still cannot resolve -- otherwise a blocked tracker would
            # remain reachable over IPv6.
            if qtype == "A":
                reply.add_answer(
                    RR(
                        rname=request.q.qname,
                        rtype=QTYPE.A,
                        rclass=1,
                        ttl=60,
                        rdata=A(self.sinkhole_ip),
                    )
                )
            return reply

        self._log("ALLOWED", qname, qtype)
        return self._forward(request, qname, qtype)


def _start_retention_pruner(
    store: QueryStore,
    retention_days: int,
    interval_seconds: int = 3600,
) -> None:
    """Background thread that enforces the retention window periodically."""
    def loop() -> None:
        while True:
            time.sleep(interval_seconds)
            try:
                store.prune(retention_days)
            except Exception:  # noqa: BLE001 - never let the pruner kill the process
                pass

    thread = threading.Thread(target=loop, name="retention-pruner", daemon=True)
    thread.start()


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    repo_root = os.path.abspath(os.path.join(here, ".."))
    cfg_path = os.environ.get("PAB_CONFIG", os.path.join(repo_root, "config.yaml"))

    cfg = load_config(cfg_path)

    privacy_mode = get_mode(cfg.privacy_mode)
    print(f"[PRIVACY] Mode: {privacy_mode.name}")
    print(f"[PRIVACY] Retention: {describe_retention(privacy_mode)}")

    db_path = resolve_db_path(cfg, repo_root)
    store = QueryStore(db_path, privacy_mode)
    removed = store.prune(cfg.retention_days)  # enforce retention on startup
    print(f"[PRIVACY] Store: {db_path} (retention {cfg.retention_days}d, pruned {removed})")
    _start_retention_pruner(store, cfg.retention_days)

    resolver = PrivacyAdblockResolver(cfg, privacy_mode, store)
    server = build_dns_server(cfg, resolver, privacy_mode)
    server.start_thread()

    print(f"[DNS] Listening on {cfg.listen_host}:{cfg.listen_port}")
    print(f"[DNS] Upstream {cfg.upstream_dns}:{cfg.upstream_port}")
    print(f"[DNS] Blocklists dir: {cfg.blocklists_dir}")
    print(f"[DNS] Sinkhole IP: {cfg.sinkhole_ip}")
    enabled = sorted(resolver.block_engine.enabled_categories())
    print(f"[DNS] Active categories: {', '.join(enabled) or '(none)'}")
    if cfg.disabled_categories:
        print(f"[DNS] Disabled categories: {', '.join(cfg.disabled_categories)}")
    print("[DNS] Press Ctrl+C to stop.")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[DNS] Stopped.")
    finally:
        store.close()


if __name__ == "__main__":
    main()