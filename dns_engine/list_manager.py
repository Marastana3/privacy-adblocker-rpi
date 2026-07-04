"""Persistent runtime management of the whitelist and blocklists.

Edits are written to the category files on disk *and* applied to the live
BlockEngine, so changes take effect immediately and survive a restart. User
additions go to `custom.txt` (category "custom") by default; the whitelist lives
in `whitelist.txt`, matching the loader's filename-as-category convention.
"""
from __future__ import annotations

from pathlib import Path
from typing import List

from dns_engine.block_engine import BlockEngine, _normalize

WHITELIST_CATEGORY = "whitelist"
DEFAULT_BLOCK_CATEGORY = "custom"


class ListManager:
    def __init__(self, blocklists_dir: str, engine: BlockEngine):
        self.dir = Path(blocklists_dir)
        self.engine = engine

    def _file(self, category: str) -> Path:
        return self.dir / f"{category}.txt"

    def _read(self, path: Path) -> List[str]:
        if not path.exists():
            return []
        lines = []
        for line in path.read_text(encoding="utf-8").splitlines():
            stripped = line.strip()
            if stripped and not stripped.startswith("#"):
                lines.append(_normalize(stripped))
        return lines

    def _append_unique(self, path: Path, domain: str) -> None:
        domain = _normalize(domain)
        existing = set(self._read(path))
        if domain in existing:
            return
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as f:
            # ensure we start on a fresh line even if the file lacked a trailing newline
            if path.stat().st_size > 0 and not path.read_text(encoding="utf-8").endswith("\n"):
                f.write("\n")
            f.write(domain + "\n")

    def _remove_line(self, path: Path, domain: str) -> bool:
        domain = _normalize(domain)
        if not path.exists():
            return False
        kept, removed = [], False
        for line in path.read_text(encoding="utf-8").splitlines():
            if _normalize(line) == domain and not line.strip().startswith("#"):
                removed = True
                continue
            kept.append(line)
        if removed:
            path.write_text("\n".join(kept) + ("\n" if kept else ""), encoding="utf-8")
        return removed

    # -- blocklist ----------------------------------------------------------

    def add_block(self, domain: str, category: str = DEFAULT_BLOCK_CATEGORY) -> None:
        self._append_unique(self._file(category), domain)
        self.engine.add_blocked(domain, category)

    def remove_block(self, domain: str) -> bool:
        """Remove a domain from every non-whitelist category file it appears in."""
        removed_any = False
        for path in sorted(self.dir.glob("*.txt")):
            if path.stem.lower() == WHITELIST_CATEGORY:
                continue
            if self._remove_line(path, domain):
                removed_any = True
        self.engine.remove_blocked(domain)
        return removed_any

    # -- whitelist ----------------------------------------------------------

    def add_allow(self, domain: str) -> None:
        self._append_unique(self._file(WHITELIST_CATEGORY), domain)
        self.engine.add_whitelisted(domain)

    def remove_allow(self, domain: str) -> bool:
        removed = self._remove_line(self._file(WHITELIST_CATEGORY), domain)
        self.engine.remove_whitelisted(domain)
        return removed
