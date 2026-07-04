from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Optional, Set


def _normalize(domain: str) -> str:
    return domain.strip().lower().rstrip(".")


def _parent_domains(domain: str):
    """Yield the domain and each of its parent suffixes.

    'a.b.example.com' -> 'a.b.example.com', 'b.example.com', 'example.com', 'com'
    This lets us decide whether a domain (or any parent) is listed with a
    constant-per-label set lookup instead of scanning the whole blocklist.
    """
    labels = domain.split(".")
    for i in range(len(labels)):
        yield ".".join(labels[i:])


@dataclass
class BlockDecision:
    blocked: bool
    category: str = ""
    reason: str = ""


class BlockEngine:
    """Decides whether a domain is blocked.

    Matching is done with set membership over the query's parent domains, so a
    lookup costs O(number of labels in the query) regardless of how many
    domains are on the blocklists -- this scales to the 100k+ entry public
    lists without slowing down every DNS request.
    """

    def __init__(self, categorized_blocklists: Dict[str, Set[str]]):
        self.whitelist: Set[str] = {
            _normalize(domain)
            for domain in categorized_blocklists.get("whitelist", set())
        }

        # domain -> category, for every blocked domain across all categories.
        self.blocked: Dict[str, str] = {}
        for category, domains in categorized_blocklists.items():
            if category == "whitelist":
                continue
            for domain in domains:
                self.blocked[_normalize(domain)] = category

    def _match(self, domain: str, rules: Set[str]) -> Optional[str]:
        """Return the first parent of `domain` present in `rules`, else None."""
        for candidate in _parent_domains(domain):
            if candidate in rules:
                return candidate
        return None

    def is_whitelisted(self, domain: str) -> bool:
        return self._match(_normalize(domain), self.whitelist) is not None

    def is_blocked(self, domain: str) -> BlockDecision:
        q = _normalize(domain)

        allow_match = self._match(q, self.whitelist)
        if allow_match is not None:
            return BlockDecision(
                blocked=False,
                category="whitelist",
                reason=f"matched:{allow_match}",
            )

        for candidate in _parent_domains(q):
            category = self.blocked.get(candidate)
            if category is not None:
                return BlockDecision(
                    blocked=True,
                    category=category,
                    reason=f"matched:{candidate}",
                )

        return BlockDecision(blocked=False)
