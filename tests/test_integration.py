"""End-to-end tests: a real DNSServer running in-process, queried over UDP.

The upstream is set to an unreachable TEST-NET address, so 'allowed' queries
deterministically return SERVFAIL (there is no network in CI). The point of
these tests is the full path: socket -> handler -> block engine -> reply, plus
storage and live category toggles.
"""
import os
import time
import unittest

from dnslib import DNSRecord, QTYPE, RCODE
from dnslib.server import DNSLogger, DNSServer

from dns_engine.resolver import AppConfig, PrivacyAdblockResolver
from privacy.privacy_modes import get_mode
from privacy.storage import QueryStore

BLOCKLISTS_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "dns_engine",
    "blocklists",
)


def _free_port() -> int:
    import socket

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class IntegrationTests(unittest.TestCase):
    def setUp(self):
        self.port = _free_port()
        self.mode = get_mode("debug")  # store domains so we can assert on them
        self.store = QueryStore(":memory:", self.mode)
        cfg = AppConfig(
            listen_host="127.0.0.1",
            listen_port=self.port,
            upstream_dns="192.0.2.1",  # unreachable on purpose
            upstream_port=53,
            sinkhole_ip="0.0.0.0",
            blocklists_dir=BLOCKLISTS_DIR,
            privacy_mode="debug",
            db_path=":memory:",
            retention_days=7,
            disabled_categories=[],
        )
        self.resolver = PrivacyAdblockResolver(cfg, self.mode, self.store)
        self.server = DNSServer(
            self.resolver,
            port=self.port,
            address="127.0.0.1",
            tcp=False,
            logger=DNSLogger("", prefix=False),
        )
        self.server.start_thread()
        time.sleep(0.3)

    def tearDown(self):
        self.server.stop()
        self.store.close()

    def _q(self, name, qtype="A"):
        data = DNSRecord.question(name, qtype).send("127.0.0.1", self.port, timeout=3)
        return DNSRecord.parse(data)

    def test_blocked_domain_sinkholed(self):
        r = self._q("doubleclick.net")
        self.assertEqual(r.header.get_rcode(), RCODE.NOERROR)
        self.assertEqual(str(r.rr[0].rdata), "0.0.0.0")

    def test_blocked_subdomain_sinkholed(self):
        r = self._q("ads.tracking.doubleclick.net")
        self.assertEqual(str(r.rr[0].rdata), "0.0.0.0")

    def test_blocked_aaaa_is_nodata(self):
        r = self._q("doubleclick.net", "AAAA")
        self.assertEqual(r.header.get_rcode(), RCODE.NOERROR)
        self.assertEqual(len(r.rr), 0)

    def test_allowed_domain_servfails_without_upstream(self):
        r = self._q("example.org")
        self.assertEqual(r.header.get_rcode(), RCODE.SERVFAIL)

    def test_queries_are_recorded(self):
        self._q("doubleclick.net")
        self._q("example.org")
        time.sleep(0.2)
        stats = self.store.stats()
        self.assertGreaterEqual(stats["total"], 2)
        self.assertGreaterEqual(stats["blocked"], 1)

    def test_live_category_toggle(self):
        # telemetry domain blocked by default...
        self.assertEqual(str(self._q("app-measurement.com").rr[0].rdata), "0.0.0.0")
        # ...disable the category on the live engine, and it stops being blocked
        self.resolver.block_engine.set_category_enabled("telemetry", False)
        self.assertEqual(self._q("app-measurement.com").header.get_rcode(), RCODE.SERVFAIL)


if __name__ == "__main__":
    unittest.main()
