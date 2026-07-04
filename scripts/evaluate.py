#!/usr/bin/env python3
"""Evaluate a running privacy-adblocker-rpi resolver.

Measures two things the thesis cares about:
  1. Block effectiveness - of known-blocked domains, how many are actually
     sinkholed (A -> sinkhole IP) or NODATA.
  2. Latency - per-query response time distribution.

Blocked domains are answered locally (no upstream needed), so this runs against
a resolver even without internet. 'Allowed' domains need a reachable upstream;
if there isn't one they show up as errors/timeouts, which the report notes.

Usage:
    python scripts/evaluate.py --host 127.0.0.1 --port 5300 --samples 200
"""
from __future__ import annotations

import argparse
import os
import statistics
import sys
import time
from typing import List, Tuple

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from dnslib import DNSRecord, QTYPE, RCODE  # noqa: E402
from dns_engine.blocklist_loader import load_blocklists  # noqa: E402


def _sample_blocked_domains(blocklists_dir: str, limit: int) -> List[str]:
    categorized = load_blocklists(blocklists_dir)
    domains: List[str] = []
    for category, items in categorized.items():
        if category == "whitelist":
            continue
        domains.extend(sorted(items))
    return domains[:limit]


def _query(host: str, port: int, name: str, timeout: float) -> Tuple[bool, float, str]:
    """Return (sinkholed, elapsed_ms, rcode_name). Raises on timeout."""
    q = DNSRecord.question(name, "A")
    start = time.perf_counter()
    reply = DNSRecord.parse(q.send(host, port, timeout=timeout))
    elapsed_ms = (time.perf_counter() - start) * 1000
    rcode = RCODE[reply.header.get_rcode()]
    sinkholed = any(
        QTYPE[rr.rtype] == "A" and str(rr.rdata) in ("0.0.0.0", "::")
        for rr in reply.rr
    )
    nodata = rcode == "NOERROR" and len(reply.rr) == 0
    return (sinkholed or nodata, elapsed_ms, rcode)


def evaluate(host: str, port: int, samples: int, timeout: float) -> dict:
    here = os.path.dirname(os.path.abspath(__file__))
    blocklists_dir = os.path.join(here, "..", "dns_engine", "blocklists")
    blocked_domains = _sample_blocked_domains(blocklists_dir, samples)

    latencies: List[float] = []
    correctly_blocked = 0
    errors = 0

    for name in blocked_domains:
        try:
            sinkholed, ms, _rcode = _query(host, port, name, timeout)
            latencies.append(ms)
            if sinkholed:
                correctly_blocked += 1
        except Exception:
            errors += 1

    total = len(blocked_domains)
    result = {
        "blocked_sampled": total,
        "correctly_blocked": correctly_blocked,
        "effectiveness_pct": round(100 * correctly_blocked / total, 1) if total else 0.0,
        "errors": errors,
    }
    if latencies:
        result["latency_ms"] = {
            "min": round(min(latencies), 3),
            "mean": round(statistics.mean(latencies), 3),
            "median": round(statistics.median(latencies), 3),
            "p95": round(sorted(latencies)[int(len(latencies) * 0.95) - 1], 3),
            "max": round(max(latencies), 3),
        }
    return result


def _print_report(r: dict) -> None:
    print("=== privacy-adblocker-rpi evaluation ===")
    print(f"Blocked domains sampled : {r['blocked_sampled']}")
    print(f"Correctly blocked       : {r['correctly_blocked']}")
    print(f"Block effectiveness     : {r['effectiveness_pct']}%")
    print(f"Query errors            : {r['errors']}")
    lat = r.get("latency_ms")
    if lat:
        print("Latency (ms):")
        for k in ("min", "mean", "median", "p95", "max"):
            print(f"  {k:7}: {lat[k]}")


def main() -> None:
    ap = argparse.ArgumentParser(description="Evaluate a running resolver.")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=5300)
    ap.add_argument("--samples", type=int, default=200)
    ap.add_argument("--timeout", type=float, default=3.0)
    args = ap.parse_args()
    _print_report(evaluate(args.host, args.port, args.samples, args.timeout))


if __name__ == "__main__":
    main()
