import unittest

from privacy.privacy_modes import describe_retention, get_mode


class DescribeRetentionTests(unittest.TestCase):
    def test_strict_discloses_no_domains_no_ip(self):
        text = describe_retention(get_mode("strict"))
        self.assertIn("no domains", text)
        self.assertIn("no client IP", text)

    def test_balanced_discloses_truncated_ip(self):
        text = describe_retention(get_mode("balanced"))
        self.assertIn("no domains", text)
        self.assertIn("truncated client IP", text)

    def test_debug_discloses_full_data(self):
        text = describe_retention(get_mode("debug"))
        self.assertIn("raw domains", text)
        self.assertIn("full client IP", text)


if __name__ == "__main__":
    unittest.main()
