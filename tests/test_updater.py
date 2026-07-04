import tempfile
import unittest
from pathlib import Path

from dns_engine.updater import RemoteBlocklistUpdater, parse_blocklist_text


class ParseTests(unittest.TestCase):
    def test_parses_hosts_format(self):
        text = (
            "# comment\n"
            "0.0.0.0 ads.example.com\n"
            "127.0.0.1 tracker.example.com\n"
            "\n"
        )
        self.assertEqual(
            parse_blocklist_text(text),
            {"ads.example.com", "tracker.example.com"},
        )

    def test_parses_plain_domains_and_inline_comments(self):
        text = "ads.example.com   # an ad server\nplain.example.org\n! adblock-style comment\n"
        self.assertEqual(
            parse_blocklist_text(text),
            {"ads.example.com", "plain.example.org"},
        )

    def test_ignores_localhost_and_non_domains(self):
        text = "0.0.0.0 localhost\nnotadomain\n0.0.0.0 0.0.0.0\n"
        # 'localhost' has no dot, 'notadomain' has no dot, '0.0.0.0' is the sinkhole
        self.assertEqual(parse_blocklist_text(text), set())


class UpdaterTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()

    def test_update_category_writes_merged_file(self):
        responses = {
            "http://list-a": "0.0.0.0 a.example.com\n0.0.0.0 b.example.com\n",
            "http://list-b": "b.example.com\nc.example.com\n",
        }
        updater = RemoteBlocklistUpdater(str(self.dir), fetcher=lambda u: responses[u])

        count = updater.update_category("ads", ["http://list-a", "http://list-b"])

        self.assertEqual(count, 3)  # a, b, c (b deduped)
        written = (self.dir / "ads.txt").read_text()
        for d in ("a.example.com", "b.example.com", "c.example.com"):
            self.assertIn(d, written)

    def test_update_preserves_existing_local_entries(self):
        (self.dir / "ads.txt").write_text("local.example.com\n")
        updater = RemoteBlocklistUpdater(
            str(self.dir), fetcher=lambda u: "0.0.0.0 remote.example.com\n"
        )
        updater.update_category("ads", ["http://list"])
        written = (self.dir / "ads.txt").read_text()
        self.assertIn("local.example.com", written)
        self.assertIn("remote.example.com", written)


if __name__ == "__main__":
    unittest.main()
