from dataclasses import dataclass

# How a client's IP address is handled before anything is persisted:
#   "none"     -> never store an IP
#   "truncate" -> store only the network prefix (IPv4 /24, IPv6 /48), GDPR-style
#   "raw"      -> store the full IP (debugging only)
IP_POLICY_NONE = "none"
IP_POLICY_TRUNCATE = "truncate"
IP_POLICY_RAW = "raw"


@dataclass(frozen=True)
class PrivacyMode:
    name: str
    store_raw_queries: bool
    store_client_ip: bool
    aggregate_stats: bool
    log_to_console: bool
    client_ip_policy: str = IP_POLICY_NONE


STRICT = PrivacyMode(
    name="strict",
    store_raw_queries=False,
    store_client_ip=False,
    aggregate_stats=True,
    log_to_console=False,
    client_ip_policy=IP_POLICY_NONE,
)

BALANCED = PrivacyMode(
    name="balanced",
    store_raw_queries=False,
    store_client_ip=True,           # only the truncated network prefix, never the full IP
    aggregate_stats=True,
    log_to_console=True,
    client_ip_policy=IP_POLICY_TRUNCATE,
)

DEBUG = PrivacyMode(
    name="debug",
    store_raw_queries=True,
    store_client_ip=True,
    aggregate_stats=True,
    log_to_console=True,
    client_ip_policy=IP_POLICY_RAW,
)


MODES = {
    "strict": STRICT,
    "balanced": BALANCED,
    "debug": DEBUG,
}


def get_mode(name: str) -> PrivacyMode:
    return MODES.get(name.lower(), STRICT)


def describe_retention(mode: PrivacyMode) -> str:
    """A one-line, plain-language statement of what this mode persists.

    Printed at startup so the operator has an explicit, informed view of what
    the device will store about their network's DNS activity.
    """
    domains = "raw domains" if mode.store_raw_queries else "no domains"
    ip_text = {
        IP_POLICY_NONE: "no client IP",
        IP_POLICY_TRUNCATE: "truncated client IP (network prefix only)",
        IP_POLICY_RAW: "full client IP",
    }.get(mode.client_ip_policy, "no client IP")
    if not (mode.aggregate_stats or mode.store_raw_queries):
        return f"mode '{mode.name}': persists nothing"
    return f"mode '{mode.name}': stores {domains}, {ip_text}; aggregate stats on"
