from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any, Dict

import yaml
from dnslib import A, DNSHeader, DNSRecord, QTYPE, RR
from dnslib.server import BaseResolver, DNSServer

from dns_engine.block_engine import BlockEngine
from dns_engine.forwader import DNSForwarder


@dataclass
class AppConfig:
    listen_host: str
    listen_port: int
    upstream_dns: str
    upstream_port: int
    sinkhole_ip: str
    block_domains: list[str]


def load_config(path: str) -> AppConfig:
    with open(path, "r", encoding="utf-8") as f:
        raw: Dict[str, Any] = yaml.safe_load(f) or {}

    dns = raw.get("dns", {})
    blocking = raw.get("blocking", {})

    return AppConfig(
        listen_host=str(dns.get("listen_host", "0.0.0.0")),
        listen_port=int(dns.get("listen_port", 5353)),
        upstream_dns=str(dns.get("upstream_dns", "1.1.1.1")),
        upstream_port=int(dns.get("upstream_port", 53)),
        sinkhole_ip=str(dns.get("sinkhole_ip", "0.0.0.0")),
        block_domains=list(blocking.get("block_domains", ["ads.example.com"])),
    )


class PrivacyAdblockResolver(BaseResolver):
    def __init__(self, cfg: AppConfig):
        self.block_engine = BlockEngine(set(cfg.block_domains))
        self.forwarder = DNSForwarder(cfg.upstream_dns, cfg.upstream_port)
        self.sinkhole_ip = cfg.sinkhole_ip

    def resolve(self, request: DNSRecord, handler):  # dnslib signature
        qname = str(request.q.qname)
        qtype = QTYPE[request.q.qtype]

        decision = self.block_engine.is_blocked(qname)

        # Block only A queries in MVP (simple + predictable)
        if decision.blocked and qtype == "A":
            reply = DNSRecord(DNSHeader(id=request.header.id, qr=1, aa=1, ra=1), q=request.q)
            reply.add_answer(RR(rname=request.q.qname, rtype=QTYPE.A, rclass=1, ttl=60, rdata=A(self.sinkhole_ip)))
            return reply

        # Otherwise forward upstream
        return self.forwarder.forward(request)


def main():
    # Default to repo-root config.yaml (one level up from dns-engine)
    here = os.path.dirname(os.path.abspath(__file__))
    repo_root = os.path.abspath(os.path.join(here, ".."))
    cfg_path = os.environ.get("PAB_CONFIG", os.path.join(repo_root, "config.yaml"))

    cfg = load_config(cfg_path)
    resolver = PrivacyAdblockResolver(cfg)

    server = DNSServer(resolver, port=cfg.listen_port, address=cfg.listen_host, tcp=False)
    server.start_thread()

    print(f"[DNS] Listening on {cfg.listen_host}:{cfg.listen_port}")
    print(f"[DNS] Upstream {cfg.upstream_dns}:{cfg.upstream_port}")
    print(f"[DNS] Blocking: {cfg.block_domains} -> sinkhole {cfg.sinkhole_ip}")
    print("[DNS] Press Ctrl+C to stop.")

    try:
        while True:
            pass
    except KeyboardInterrupt:
        print("\n[DNS] Stopped.")


if __name__ == "__main__":
    main()