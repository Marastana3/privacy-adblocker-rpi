from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Iterable, Optional, Set


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

    Categories can be toggled off at runtime (e.g. keep ads blocked but allow
    telemetry) without reloading the lists, and the whitelist/blocklist can be
    edited in place; see ListManager for the persistent side of that.
    """

    def __init__(
        self,
        categorized_blocklists: Dict[str, Set[str]],
        disabled_categories: Optional[Iterable[str]] = None,
    ):
        self._disabled: Set[str] = {c.lower() for c in (disabled_categories or ())}
        self.load(categorized_blocklists)

    def load(self, categorized_blocklists: Dict[str, Set[str]]) -> None:
        """(Re)build the in-memory rules from a categorized blocklist mapping.

        Category enable/disable state is preserved across reloads.
        """
        self.whitelist: Set[str] = {
            _normalize(domain)
            for domain in categorized_blocklists.get("whitelist", set())
        }

        # domain -> category, for every blocked domain across all categories.
        self.blocked: Dict[str, str] = {}
        self.categories: Set[str] = set()
        for category, domains in categorized_blocklists.items():
            if category == "whitelist":
                continue
            self.categories.add(category)
            for domain in domains:
                self.blocked[_normalize(domain)] = category

    # -- category toggles ---------------------------------------------------

    def set_category_enabled(self, category: str, enabled: bool) -> None:
        category = category.lower()
        if enabled:
            self._disabled.discard(category)
        else:
            self._disabled.add(category)

    def is_category_enabled(self, category: str) -> bool:
        return category.lower() not in self._disabled

    def enabled_categories(self) -> Set[str]:
        return {c for c in self.categories if c not in self._disabled}

    # -- runtime list edits (in-memory; ListManager persists to disk) -------

    def add_blocked(self, domain: str, category: str = "custom") -> None:
        self.blocked[_normalize(domain)] = category
        self.categories.add(category)

    def remove_blocked(self, domain: str) -> None:
        self.blocked.pop(_normalize(domain), None)

    def add_whitelisted(self, domain: str) -> None:
        self.whitelist.add(_normalize(domain))

    def remove_whitelisted(self, domain: str) -> None:
        self.whitelist.discard(_normalize(domain))

    # -- read accessors (for the API / dashboard) ---------------------------

    def whitelisted_domains(self) -> list:
        return sorted(self.whitelist)

    def blocked_by_category(self) -> Dict[str, list]:
        grouped: Dict[str, list] = {}
        for domain, category in self.blocked.items():
            grouped.setdefault(category, []).append(domain)
        return {cat: sorted(domains) for cat, domains in grouped.items()}

    # -- matching -----------------------------------------------------------

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

        # Walk parent domains; skip matches whose category is disabled so a
        # longer parent in an enabled category can still block.
        for candidate in _parent_domains(q):
            category = self.blocked.get(candidate)
            if category is not None and category not in self._disabled:
                return BlockDecision(
                    blocked=True,
                    category=category,
                    reason=f"matched:{candidate}",
                )

        return BlockDecision(blocked=False)
