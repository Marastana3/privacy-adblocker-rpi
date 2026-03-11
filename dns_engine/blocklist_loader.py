from __future__ import annotations

from pathlib import Path
from typing import Dict, Set


def load_blocklists(blocklists_dir: str) -> Dict[str, Set[str]]:
    """
    Load domain blocklists from text files inside the given directory.

    Returns:
        {
            "ads": {"doubleclick.net", ...},
            "trackers": {...},
            "telemetry": {...}
        }
    """
    result: Dict[str, Set[str]] = {}
    directory = Path(blocklists_dir)

    if not directory.exists():
        return result

    for file_path in directory.glob("*.txt"):
        category = file_path.stem.lower()
        domains: Set[str] = set()

        with file_path.open("r", encoding="utf-8") as f:
            for line in f:
                line = line.strip().lower()

                if not line or line.startswith("#"):
                    continue

                domains.add(line.rstrip("."))

        result[category] = domains

    return result