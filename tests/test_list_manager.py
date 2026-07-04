import tempfile
import unittest
from pathlib import Path

from dns_engine.block_engine import BlockEngine
from dns_engine.list_manager import ListManager


class ListManagerTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self._tmp.name)
        (self.dir / "ads.txt").write_text("doubleclick.net\n")
        (self.dir / "whitelist.txt").write_text("safe.example.com\n")
        self.engine = BlockEngine(
            {"ads": {"doubleclick.net"}, "whitelist": {"safe.example.com"}}
        )
        self.mgr = ListManager(str(self.dir), self.engine)

    def tearDown(self):
        self._tmp.cleanup()

    def _lines(self, name):
        return (self.dir / name).read_text().split()

    def test_add_block_persists_and_applies(self):
        self.mgr.add_block("tracker.test")
        self.assertIn("tracker.test", self._lines("custom.txt"))       # persisted
        self.assertTrue(self.engine.is_blocked("tracker.test").blocked)  # live

    def test_add_block_is_idempotent(self):
        self.mgr.add_block("tracker.test")
        self.mgr.add_block("tracker.test")
        self.assertEqual(self._lines("custom.txt").count("tracker.test"), 1)

    def test_remove_block_persists_and_applies(self):
        self.mgr.remove_block("doubleclick.net")
        self.assertNotIn("doubleclick.net", self._lines("ads.txt"))
        self.assertFalse(self.engine.is_blocked("doubleclick.net").blocked)

    def test_add_allow_persists_and_applies(self):
        # block, then allow a subdomain -> whitelist wins
        self.mgr.add_block("ads.corp.test", category="ads")
        self.mgr.add_allow("ok.corp.test")
        self.assertIn("ok.corp.test", self._lines("whitelist.txt"))
        self.assertFalse(self.engine.is_blocked("ok.corp.test").blocked)

    def test_remove_allow(self):
        self.mgr.remove_allow("safe.example.com")
        self.assertNotIn("safe.example.com", self._lines("whitelist.txt"))
        self.assertFalse(self.engine.is_whitelisted("safe.example.com"))


if __name__ == "__main__":
    unittest.main()
