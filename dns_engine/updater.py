"""Fetch and parse public blocklists into the local category files.

Supports the two formats public lists ship in:
  * hosts format:   `0.0.0.0 ads.example.com`  /  `127.0.0.1 tracker.example.com`
  * plain domains:  `ads.example.com`

The HTTP fetcher is injectable so parsing/merging can be tested without network
access, and so the caller controls the (restricted) network policy.
"""
from __future__ import annotations

import ipaddress
from pathlib import Path
from typing import Callable, Dict, Iterable, List, Set
from urllib.request import urlopen

Fetcher = Callable[[str], str]

# Addresses that appear on the left of a hosts-format line; the real domain is
# the token after them.
_HOSTS_SINKHOLES = {"0.0.0.0", "127.0.0.1", "::", "::1"}


def _default_fetcher(url: str, timeout: float = 15.0) -> str:
    with urlopen(url, timeout=timeout) as resp:  # noqa: S310 - caller supplies trusted list URLs
        return resp.read().decode("utf-8", errors="replace")


def parse_blocklist_text(text: str) -> Set[str]:
    """Extract normalized domains from hosts-format or plain-domain content."""
    domains: Set[str] = set()
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or line.startswith("!"):
            continue
        # strip inline comments
        line = line.split("#", 1)[0].strip()
        if not line:
            continue

        tokens = line.split()
        if len(tokens) >= 2 and tokens[0] in _HOSTS_SINKHOLES:
            candidate = tokens[1]
        else:
            candidate = tokens[0]

        candidate = candidate.strip().lower().rstrip(".")
        if not candidate or "." not in candidate or "/" in candidate:
            continue
        if _is_ip(candidate):
            continue
        domains.add(candidate)
    return domains


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


class RemoteBlocklistUpdater:
    def __init__(self, blocklists_dir: str, fetcher: Fetcher = _default_fetcher):
        self.dir = Path(blocklists_dir)
        self.fetcher = fetcher

    def _file(self, category: str) -> Path:
        return self.dir / f"{category}.txt"

    def update_category(self, category: str, urls: Iterable[str]) -> int:
        """Fetch each URL, union all domains, and write the category file.

        Returns the number of domains written. Existing local entries in the
        file are preserved (merged), so manual additions aren't lost.
        """
        merged: Set[str] = set()

        path = self._file(category)
        if path.exists():
            merged |= parse_blocklist_text(path.read_text(encoding="utf-8"))

        for url in urls:
            merged |= parse_blocklist_text(self.fetcher(url))

        self.dir.mkdir(parents=True, exist_ok=True)
        header = f"# {category} blocklist - auto-generated, do not edit by hand\n"
        path.write_text(header + "\n".join(sorted(merged)) + "\n", encoding="utf-8")
        return len(merged)

    def update_all(self, sources: Dict[str, List[str]]) -> Dict[str, int]:
        """Update every category in a {category: [urls]} mapping."""
        return {
            category: self.update_category(category, urls)
            for category, urls in sources.items()
        }
