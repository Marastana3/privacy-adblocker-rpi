import unittest

from dns_engine.block_engine import BlockEngine


def make_engine():
    return BlockEngine(
        {
            "ads": {"doubleclick.net", "ads.example.com"},
            "trackers": {"google-analytics.com"},
            "whitelist": {"allowed.doubleclick.net"},
        }
    )


class BlockEngineTests(unittest.TestCase):
    def setUp(self):
        self.engine = make_engine()

    def test_exact_domain_blocked(self):
        d = self.engine.is_blocked("doubleclick.net")
        self.assertTrue(d.blocked)
        self.assertEqual(d.category, "ads")

    def test_subdomain_blocked(self):
        d = self.engine.is_blocked("ads.tracking.doubleclick.net")
        self.assertTrue(d.blocked)
        self.assertEqual(d.category, "ads")

    def test_whitelist_overrides_block(self):
        # allowed.doubleclick.net is whitelisted even though doubleclick.net is blocked
        d = self.engine.is_blocked("allowed.doubleclick.net")
        self.assertFalse(d.blocked)
        self.assertEqual(d.category, "whitelist")

    def test_whitelist_subdomain_overrides(self):
        d = self.engine.is_blocked("cdn.allowed.doubleclick.net")
        self.assertFalse(d.blocked)
        self.assertEqual(d.category, "whitelist")

    def test_unlisted_domain_allowed(self):
        d = self.engine.is_blocked("example.org")
        self.assertFalse(d.blocked)
        self.assertEqual(d.category, "")

    def test_case_and_trailing_dot_normalized(self):
        d = self.engine.is_blocked("DoubleClick.NET.")
        self.assertTrue(d.blocked)

    def test_partial_label_not_matched(self):
        # "notdoubleclick.net" must NOT match "doubleclick.net"
        d = self.engine.is_blocked("notdoubleclick.net")
        self.assertFalse(d.blocked)


if __name__ == "__main__":
    unittest.main()
