import tempfile
import unittest
from pathlib import Path

from dns_engine.blocklist_loader import load_blocklists


class BlocklistLoaderTests(unittest.TestCase):
    def test_loads_categories_from_filenames(self):
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "ads.txt").write_text(
                "# a comment\n"
                "doubleclick.net\n"
                "\n"                       # blank line ignored
                "  Ads.Example.com  \n"    # whitespace + case normalized
            )
            (Path(tmp) / "whitelist.txt").write_text("safe.example.com\n")

            result = load_blocklists(tmp)

            self.assertEqual(set(result.keys()), {"ads", "whitelist"})
            self.assertEqual(result["ads"], {"doubleclick.net", "ads.example.com"})
            self.assertEqual(result["whitelist"], {"safe.example.com"})

    def test_missing_directory_returns_empty(self):
        self.assertEqual(load_blocklists("/no/such/dir/here"), {})


if __name__ == "__main__":
    unittest.main()
