import unittest

from dns_engine.block_engine import BlockEngine


def make_engine(disabled=None):
    return BlockEngine(
        {
            "ads": {"doubleclick.net"},
            "telemetry": {"app-measurement.com"},
        },
        disabled_categories=disabled,
    )


class CategoryToggleTests(unittest.TestCase):
    def test_all_categories_enabled_by_default(self):
        e = make_engine()
        self.assertTrue(e.is_blocked("doubleclick.net").blocked)
        self.assertTrue(e.is_blocked("app-measurement.com").blocked)

    def test_disabled_category_not_blocked(self):
        e = make_engine(disabled=["telemetry"])
        self.assertTrue(e.is_blocked("doubleclick.net").blocked)     # ads still on
        self.assertFalse(e.is_blocked("app-measurement.com").blocked)  # telemetry off

    def test_toggle_at_runtime(self):
        e = make_engine()
        e.set_category_enabled("ads", False)
        self.assertFalse(e.is_blocked("doubleclick.net").blocked)
        e.set_category_enabled("ads", True)
        self.assertTrue(e.is_blocked("doubleclick.net").blocked)

    def test_enabled_categories_reflects_state(self):
        e = make_engine(disabled=["telemetry"])
        self.assertEqual(e.enabled_categories(), {"ads"})


if __name__ == "__main__":
    unittest.main()
