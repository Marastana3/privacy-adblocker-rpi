import unittest

from privacy.privacy_modes import get_mode


class PrivacyModeTests(unittest.TestCase):
    def test_strict_stores_nothing_and_is_silent(self):
        m = get_mode("strict")
        self.assertFalse(m.store_raw_queries)
        self.assertFalse(m.store_client_ip)
        self.assertFalse(m.log_to_console)

    def test_debug_stores_everything(self):
        m = get_mode("debug")
        self.assertTrue(m.store_raw_queries)
        self.assertTrue(m.store_client_ip)
        self.assertTrue(m.log_to_console)

    def test_balanced_logs_but_does_not_store_raw(self):
        m = get_mode("balanced")
        self.assertTrue(m.log_to_console)
        self.assertFalse(m.store_raw_queries)

    def test_unknown_mode_defaults_to_strict(self):
        self.assertEqual(get_mode("nonsense").name, "strict")

    def test_mode_name_is_case_insensitive(self):
        self.assertEqual(get_mode("DEBUG").name, "debug")


if __name__ == "__main__":
    unittest.main()
