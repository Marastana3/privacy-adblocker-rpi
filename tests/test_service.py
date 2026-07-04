import tempfile
import unittest
from pathlib import Path

from app.service import AdblockService, _valid_domain
from dns_engine.block_engine import BlockEngine
from dns_engine.list_manager import ListManager
from privacy.privacy_modes import get_mode
from privacy.storage import QueryStore


class ServiceTestCase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self._tmp.name)
        (self.dir / "ads.txt").write_text("doubleclick.net\n")
        (self.dir / "telemetry.txt").write_text("app-measurement.com\n")
        (self.dir / "whitelist.txt").write_text("safe.example.com\n")

        from dns_engine.blocklist_loader import load_blocklists
        engine = BlockEngine(load_blocklists(str(self.dir)))
        list_manager = ListManager(str(self.dir), engine)
        mode = get_mode("debug")  # so top_blocked can store domains
        store = QueryStore(":memory:", mode)
        self.svc = AdblockService(
            engine=engine, list_manager=list_manager, store=store,
            privacy_mode=mode, blocklists_dir=str(self.dir),
            remote_sources={"ads": ["http://list"]},
        )

    def tearDown(self):
        self._tmp.cleanup()


class CategoryAndListTests(ServiceTestCase):
    def test_categories_listing(self):
        names = {c["name"] for c in self.svc.categories()}
        self.assertEqual(names, {"ads", "telemetry"})
        self.assertTrue(all(c["enabled"] for c in self.svc.categories()))

    def test_set_category_toggles_blocking(self):
        self.svc.set_category("telemetry", False)
        self.assertFalse(self.svc.engine.is_blocked("app-measurement.com").blocked)

    def test_set_unknown_category_raises(self):
        with self.assertRaises(KeyError):
            self.svc.set_category("nope", False)

    def test_add_and_remove_allow(self):
        self.svc.add_allow("ok.example.net")
        self.assertIn("ok.example.net", self.svc.whitelist())
        self.assertTrue(self.svc.remove_allow("ok.example.net"))
        self.assertNotIn("ok.example.net", self.svc.whitelist())

    def test_add_and_remove_block(self):
        self.svc.add_block("tracker.test")
        self.assertIn("tracker.test", self.svc.blocklist().get("custom", []))
        self.assertTrue(self.svc.engine.is_blocked("tracker.test").blocked)
        self.svc.remove_block("tracker.test")
        self.assertFalse(self.svc.engine.is_blocked("tracker.test").blocked)

    def test_invalid_domain_rejected(self):
        with self.assertRaises(ValueError):
            self.svc.add_block("not a domain")


class StatsPrivacyRemoteTests(ServiceTestCase):
    def test_stats_and_top_blocked(self):
        self.svc.store.record(blocked=True, category="ads", domain="doubleclick.net")
        self.svc.store.record(blocked=False)
        stats = self.svc.stats()
        self.assertEqual(stats["total"], 2)
        self.assertEqual(stats["blocked"], 1)
        top = self.svc.top_blocked()
        self.assertEqual(top[0], {"domain": "doubleclick.net", "count": 1})

    def test_privacy_reports_mode(self):
        self.assertEqual(self.svc.privacy()["mode"], "debug")

    def test_update_remote_merges_and_reloads(self):
        written = self.svc.update_remote(fetcher=lambda u: "0.0.0.0 new-ad.example.com\n")
        self.assertIn("ads", written)
        # engine reloaded from disk now blocks the fetched domain
        self.assertTrue(self.svc.engine.is_blocked("new-ad.example.com").blocked)


class ValidDomainTests(unittest.TestCase):
    def test_normalizes(self):
        self.assertEqual(_valid_domain("Example.COM."), "example.com")

    def test_rejects_bad(self):
        for bad in ["", "localhost", "a b.com", "x/y.com"]:
            with self.assertRaises(ValueError):
                _valid_domain(bad)


if __name__ == "__main__":
    unittest.main()
