import unittest

from privacy.anonymizer import apply_ip_policy, redact_domain, truncate_ip
from privacy.privacy_modes import (
    IP_POLICY_NONE,
    IP_POLICY_RAW,
    IP_POLICY_TRUNCATE,
)


class TruncateIpTests(unittest.TestCase):
    def test_ipv4_drops_host_octet(self):
        self.assertEqual(truncate_ip("192.168.1.57"), "192.168.1.0")

    def test_ipv6_keeps_only_prefix(self):
        # /48 zeroes everything after the third hextet
        self.assertEqual(truncate_ip("2001:db8:abcd:1234::1"), "2001:db8:abcd::")

    def test_invalid_ip_returns_none(self):
        self.assertIsNone(truncate_ip("not-an-ip"))


class ApplyIpPolicyTests(unittest.TestCase):
    def test_none_policy_drops_ip(self):
        self.assertIsNone(apply_ip_policy("192.168.1.57", IP_POLICY_NONE))

    def test_truncate_policy(self):
        self.assertEqual(apply_ip_policy("192.168.1.57", IP_POLICY_TRUNCATE), "192.168.1.0")

    def test_raw_policy_passthrough(self):
        self.assertEqual(apply_ip_policy("192.168.1.57", IP_POLICY_RAW), "192.168.1.57")

    def test_none_input_is_none(self):
        self.assertIsNone(apply_ip_policy(None, IP_POLICY_RAW))


class RedactDomainTests(unittest.TestCase):
    def test_dropped_when_not_storing_raw(self):
        self.assertIsNone(redact_domain("example.com", store_raw_queries=False))

    def test_kept_and_normalized_when_storing_raw(self):
        self.assertEqual(redact_domain("Example.COM.", store_raw_queries=True), "example.com")


if __name__ == "__main__":
    unittest.main()
