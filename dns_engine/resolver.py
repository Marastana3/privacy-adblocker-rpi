from __future__ import annotations
from privacy.privacy_modes import PrivacyMode, get_mode

import os
import time
from dataclasses import dataclass
from typing import Any, Dict

import yaml
from dnslib import A, DNSHeader, DNSRecord, QTYPE, RCODE, RR
from dnslib.server import BaseResolver, DNSLogger, DNSServer

from dns_engine.block_engine import BlockEngine
from dns_engine.blocklist_loader import load_blocklists
from dns_engine.forwarder import DNSForwarder


@dataclass
class AppConfig:
    listen_host: str
    listen_port: int
    upstream_dns: str
    upstream_port: int
    sinkhole_ip: str
    blocklists_dir: str
    privacy_mode: str


def load_config(path: str) -> AppConfig:
    with open(path, "r", encoding="utf-8") as f:
        raw: Dict[str, Any] = yaml.safe_load(f) or {}

    dns = raw.get("dns", {})
    blocking = raw.get("blocking", {})

    return AppConfig(
    listen_host=str(dns.get("listen_host", "0.0.0.0")),
    listen_port=int(dns.get("listen_port", 5300)),
    upstream_dns=str(dns.get("upstream_dns", "1.1.1.1")),
    upstream_port=int(dns.get("upstream_port", 53)),
    sinkhole_ip=str(dns.get("sinkhole_ip", "0.0.0.0")),
    blocklists_dir=str(blocking.get("blocklists_dir", "dns_engine/blocklists")),
    privacy_mode=str(raw.get("privacy", {}).get("mode", "strict")),
)


class PrivacyAdblockResolver(BaseResolver):
    def __init__(self, cfg: AppConfig, privacy_mode: PrivacyMode):
        categorized_blocklists = load_blocklists(cfg.blocklists_dir)
        self.block_engine = BlockEngine(categorized_blocklists)
        self.forwarder = DNSForwarder(cfg.upstream_dns, cfg.upstream_port)
        self.sinkhole_ip = cfg.sinkhole_ip
        self.privacy = privacy_mode

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

    def resolve(self, request: DNSRecord, handler):
        qname = str(request.q.qname)
        qtype = QTYPE[request.q.qtype]

        decision = self.block_engine.is_blocked(qname)

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


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    repo_root = os.path.abspath(os.path.join(here, ".."))
    cfg_path = os.environ.get("PAB_CONFIG", os.path.join(repo_root, "config.yaml"))

    cfg = load_config(cfg_path)

    privacy_mode = get_mode(cfg.privacy_mode)
    print(f"[PRIVACY] Mode: {privacy_mode.name}")

    resolver = PrivacyAdblockResolver(cfg, privacy_mode)

    # dnslib's DNSServer has its own logger that prints every request/reply
    # (including the queried domain) by default. That would leak query data even
    # in strict mode, so only enable its request/reply logging when the privacy
    # mode allows storing raw queries; otherwise log errors only.
    if privacy_mode.store_raw_queries:
        dns_logger = DNSLogger("request,reply,truncated,error", prefix=False)
    else:
        dns_logger = DNSLogger("truncated,error", prefix=False)

    server = DNSServer(
        resolver,
        logger=dns_logger,
        port=cfg.listen_port,
        address=cfg.listen_host,
        tcp=False,
    )
    server.start_thread()

    print(f"[DNS] Listening on {cfg.listen_host}:{cfg.listen_port}")
    print(f"[DNS] Upstream {cfg.upstream_dns}:{cfg.upstream_port}")
    print(f"[DNS] Blocklists dir: {cfg.blocklists_dir}")
    print(f"[DNS] Sinkhole IP: {cfg.sinkhole_ip}")
    print("[DNS] Press Ctrl+C to stop.")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[DNS] Stopped.")


if __name__ == "__main__":
    main()