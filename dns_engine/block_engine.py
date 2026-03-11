from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Set


def _normalize(domain: str) -> str:
    return domain.strip().lower().rstrip(".")


@dataclass
class BlockDecision:
    blocked: bool
    category: str = ""
    reason: str = ""


class BlockEngine:
    def __init__(self, categorized_blocklists: Dict[str, Set[str]]):
        self.blocklists: Dict[str, Set[str]] = {
            category: {_normalize(domain) for domain in domains}
            for category, domains in categorized_blocklists.items()
        }

    def is_blocked(self, domain: str) -> BlockDecision:
        q = _normalize(domain)

        for category, domains in self.blocklists.items():
            for blocked_domain in domains:
                if q == blocked_domain or q.endswith("." + blocked_domain):
                    return BlockDecision(
                        blocked=True,
                        category=category,
                        reason=f"matched:{blocked_domain}",
                    )

        return BlockDecision(blocked=False)