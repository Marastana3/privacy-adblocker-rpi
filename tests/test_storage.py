import sqlite3
import tempfile
import time
import unittest
from pathlib import Path

from privacy.privacy_modes import PrivacyMode, get_mode
from privacy.storage import QueryStore


class StorageTestCase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.db_path = str(Path(self._tmp.name) / "test.db")

    def tearDown(self):
        self._tmp.cleanup()

    def store(self, mode_name):
        return QueryStore(self.db_path, get_mode(mode_name))

    def rows(self):
        conn = sqlite3.connect(self.db_path)
        try:
            return conn.execute(
                "SELECT domain, client_ip, blocked, category FROM query_events"
            ).fetchall()
        finally:
            conn.close()


class PrivacyEnforcementTests(StorageTestCase):
    def test_strict_stores_no_domain_and_no_ip(self):
        s = self.store("strict")
        s.record(blocked=True, category="ads", qtype="A",
                 domain="doubleclick.net", client_ip="192.168.1.57")
        (domain, client_ip, blocked, category), = self.rows()
        self.assertIsNone(domain)          # raw query not persisted
        self.assertIsNone(client_ip)       # client IP not persisted
        self.assertEqual(blocked, 1)       # but the aggregate fact is kept
        self.assertEqual(category, "ads")

    def test_balanced_truncates_ip_and_drops_domain(self):
        s = self.store("balanced")
        s.record(blocked=True, category="ads", qtype="A",
                 domain="doubleclick.net", client_ip="192.168.1.57")
        (domain, client_ip, _blocked, _cat), = self.rows()
        self.assertIsNone(domain)
        self.assertEqual(client_ip, "192.168.1.0")   # network prefix only

    def test_debug_stores_domain_and_full_ip(self):
        s = self.store("debug")
        s.record(blocked=True, category="ads", qtype="A",
                 domain="doubleclick.net", client_ip="192.168.1.57")
        (domain, client_ip, _blocked, _cat), = self.rows()
        self.assertEqual(domain, "doubleclick.net")
        self.assertEqual(client_ip, "192.168.1.57")

    def test_mode_that_persists_nothing_writes_no_rows(self):
        quiet = PrivacyMode(
            name="quiet", store_raw_queries=False, store_client_ip=False,
            aggregate_stats=False, log_to_console=False,
        )
        s = QueryStore(self.db_path, quiet)
        s.record(blocked=True, category="ads", domain="x.com", client_ip="1.2.3.4")
        self.assertEqual(self.rows(), [])


class AggregationAndRetentionTests(StorageTestCase):
    def test_stats_counts(self):
        s = self.store("strict")
        s.record(blocked=True, category="ads")
        s.record(blocked=True, category="trackers")
        s.record(blocked=False)
        stats = s.stats()
        self.assertEqual(stats["total"], 3)
        self.assertEqual(stats["blocked"], 2)
        self.assertEqual(stats["allowed"], 1)
        self.assertEqual(stats["by_category"], {"ads": 1, "trackers": 1})

    def test_top_blocked_empty_in_strict(self):
        s = self.store("strict")
        s.record(blocked=True, category="ads", domain="doubleclick.net")
        self.assertEqual(s.top_blocked_domains(), [])   # no domains stored

    def test_top_blocked_populated_in_debug(self):
        s = self.store("debug")
        for _ in range(3):
            s.record(blocked=True, category="ads", domain="doubleclick.net")
        s.record(blocked=True, category="ads", domain="ads.example.com")
        top = s.top_blocked_domains()
        self.assertEqual(top[0], ("doubleclick.net", 3))

    def test_prune_removes_old_events(self):
        s = self.store("strict")
        old_ts = int(time.time()) - 10 * 86400   # 10 days ago
        s.record(blocked=True, category="ads", ts=old_ts)
        s.record(blocked=False)                   # now
        removed = s.prune(retention_days=7)
        self.assertEqual(removed, 1)
        self.assertEqual(s.stats()["total"], 1)


if __name__ == "__main__":
    unittest.main()
