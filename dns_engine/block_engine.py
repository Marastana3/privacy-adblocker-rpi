from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Set


def _normalize(domain: str) -> str:
    return domain.strip().lower().rstrip(".")


def _matches(domain: str, rule: str) -> bool:
    return domain == rule or domain.endswith("." + rule)


@dataclass
class BlockDecision:
    blocked: bool
    category: str = ""
    reason: str = ""


class BlockEngine:
    def __init__(self, categorized_blocklists: Dict[str, Set[str]]):
        self.whitelist: Set[str] = {
            _normalize(domain)
            for domain in categorized_blocklists.get("whitelist", set())
        }

        self.blocklists: Dict[str, Set[str]] = {
            category: {_normalize(domain) for domain in domains}
            for category, domains in categorized_blocklists.items()
            if category != "whitelist"
        }

    def is_whitelisted(self, domain: str) -> bool:
        q = _normalize(domain)
        return any(_matches(q, allowed) for allowed in self.whitelist)

    def is_blocked(self, domain: str) -> BlockDecision:
        q = _normalize(domain)

        if self.is_whitelisted(q):
            return BlockDecision(
                blocked=False,
                category="whitelist",
                reason="matched whitelist",
            )

        for category, domains in self.blocklists.items():
            for blocked_domain in domains:
                if _matches(q, blocked_domain):
                    return BlockDecision(
                        blocked=True,
                        category=category,
                        reason=f"matched:{blocked_domain}",
                    )

        return BlockDecision(blocked=False)