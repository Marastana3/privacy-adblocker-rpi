import os
import unittest

from dnslib import DNSRecord, QTYPE, RCODE

from dns_engine.resolver import AppConfig, PrivacyAdblockResolver
from privacy.privacy_modes import get_mode

BLOCKLISTS_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "dns_engine",
    "blocklists",
)


def make_resolver(mode="strict"):
    cfg = AppConfig(
        listen_host="127.0.0.1",
        listen_port=5300,
        upstream_dns="192.0.2.1",  # TEST-NET-1, guaranteed unreachable
        upstream_port=53,
        sinkhole_ip="0.0.0.0",
        blocklists_dir=BLOCKLISTS_DIR,
        privacy_mode=mode,
        db_path=":memory:",
        retention_days=7,
    )
    return PrivacyAdblockResolver(cfg, get_mode(mode))


class ResolverTests(unittest.TestCase):
    def setUp(self):
        self.resolver = make_resolver()

    def _resolve(self, name, qtype):
        return self.resolver.resolve(DNSRecord.question(name, qtype), handler=None)

    def test_blocked_a_returns_sinkhole(self):
        reply = self._resolve("doubleclick.net", "A")
        self.assertEqual(reply.header.get_rcode(), RCODE.NOERROR)
        self.assertEqual(len(reply.rr), 1)
        self.assertEqual(QTYPE[reply.rr[0].rtype], "A")
        self.assertEqual(str(reply.rr[0].rdata), "0.0.0.0")

    def test_blocked_aaaa_returns_nodata(self):
        # blocked domain over IPv6 must not resolve and must not be forwarded
        reply = self._resolve("doubleclick.net", "AAAA")
        self.assertEqual(reply.header.get_rcode(), RCODE.NOERROR)
        self.assertEqual(len(reply.rr), 0)

    def test_allowed_domain_is_forwarded(self):
        calls = {}

        def fake_forward(request):
            calls["forwarded"] = str(request.q.qname)
            return request.reply()

        self.resolver.forwarder.forward = fake_forward
        self._resolve("example.org", "A")
        self.assertEqual(calls.get("forwarded"), "example.org.")

    def test_upstream_failure_returns_servfail(self):
        def boom(request):
            raise OSError("network is unreachable")

        self.resolver.forwarder.forward = boom
        reply = self._resolve("example.org", "A")
        self.assertEqual(reply.header.get_rcode(), RCODE.SERVFAIL)


if __name__ == "__main__":
    unittest.main()
