from __future__ import annotations

from pathlib import Path
from typing import Dict, Set


def _normalize(domain: str) -> str:
    return domain.strip().lower().rstrip(".")


def load_blocklists(blocklists_dir: str) -> Dict[str, Set[str]]:
    result: Dict[str, Set[str]] = {}
    directory = Path(blocklists_dir)

    if not directory.exists():
        return result

    for file_path in directory.glob("*.txt"):
        category = file_path.stem.lower()
        domains: Set[str] = set()

        with file_path.open("r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()

                if not line or line.startswith("#"):
                    continue

                domains.add(_normalize(line))

        result[category] = domains

    return result