"""Anonymization helpers applied before any data is persisted.

The goal is that identifying data (the full client IP, and in strict mode the
queried domain) never reaches storage. All persistence paths route through
these functions so the privacy guarantee lives in one place.
"""
from __future__ import annotations

import ipaddress
from typing import Optional

from privacy.privacy_modes import (
    IP_POLICY_NONE,
    IP_POLICY_RAW,
    IP_POLICY_TRUNCATE,
)

# Prefix lengths kept when truncating. /24 drops the IPv4 host octet; /48 keeps
# only the routing prefix of an IPv6 address (well above a single household).
IPV4_KEEP_PREFIX = 24
IPV6_KEEP_PREFIX = 48


def truncate_ip(ip: str) -> Optional[str]:
    """Return the network prefix of an IP, zeroing host bits. None if unparsable."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    prefix = IPV4_KEEP_PREFIX if addr.version == 4 else IPV6_KEEP_PREFIX
    network = ipaddress.ip_network(f"{addr}/{prefix}", strict=False)
    return str(network.network_address)


def apply_ip_policy(ip: Optional[str], policy: str) -> Optional[str]:
    """Transform a client IP according to the active privacy policy."""
    if ip is None:
        return None
    if policy == IP_POLICY_RAW:
        return ip
    if policy == IP_POLICY_TRUNCATE:
        return truncate_ip(ip)
    # IP_POLICY_NONE or anything unrecognized -> store nothing.
    return None


def redact_domain(domain: Optional[str], store_raw_queries: bool) -> Optional[str]:
    """Keep the domain only when the mode permits storing raw queries."""
    if not store_raw_queries or domain is None:
        return None
    return domain.strip().lower().rstrip(".")
