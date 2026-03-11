from dataclasses import dataclass


@dataclass(frozen=True)
class PrivacyMode:
    name: str
    store_raw_queries: bool
    store_client_ip: bool
    aggregate_stats: bool
    log_to_console: bool


STRICT = PrivacyMode(
    name="strict",
    store_raw_queries=False,
    store_client_ip=False,
    aggregate_stats=True,
    log_to_console=False,
)

BALANCED = PrivacyMode(
    name="balanced",
    store_raw_queries=False,
    store_client_ip=False,
    aggregate_stats=True,
    log_to_console=True,
)

DEBUG = PrivacyMode(
    name="debug",
    store_raw_queries=True,
    store_client_ip=True,
    aggregate_stats=True,
    log_to_console=True,
)


MODES = {
    "strict": STRICT,
    "balanced": BALANCED,
    "debug": DEBUG,
}


def get_mode(name: str) -> PrivacyMode:
    return MODES.get(name.lower(), STRICT)