from __future__ import annotations

from dataclasses import dataclass
from typing import Set


def _normalize(domain: str) -> str:
    # DNS queries may include a trailing dot; normalize for matching
    return domain.strip().lower().rstrip(".")


@dataclass
class BlockDecision:
    blocked: bool
    reason: str = ""


class BlockEngine:
    def __init__(self, blocked_domains: Set[str]):
        self._blocked = {_normalize(d) for d in blocked_domains}

    def is_blocked(self, domain: str) -> BlockDecision:
        q = _normalize(domain)

        # MVP: exact match only (later: suffix/subdomain matching)
        if q in self._blocked:
            return BlockDecision(True, reason=f"matched:{q}")

        return BlockDecision(False)