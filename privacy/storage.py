"""Privacy-aware persistence for DNS query events.

Every write is filtered through the active PrivacyMode + anonymizer, so what
lands on disk already respects the mode:

  strict   -> aggregate rows only (no domain, no IP)
  balanced -> no domain, truncated network prefix as IP
  debug    -> full domain and full IP

The DNS server is threaded, so a single shared connection is guarded by a lock
and opened with check_same_thread=False.
"""
from __future__ import annotations

import sqlite3
import threading
import time
from typing import Dict, List, Optional, Tuple

from privacy.anonymizer import apply_ip_policy, redact_domain
from privacy.privacy_modes import PrivacyMode

_SCHEMA = """
CREATE TABLE IF NOT EXISTS query_events (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    ts        INTEGER NOT NULL,
    domain    TEXT,
    qtype     TEXT,
    blocked   INTEGER NOT NULL,
    category  TEXT,
    client_ip TEXT
);
CREATE INDEX IF NOT EXISTS idx_query_events_ts ON query_events(ts);
"""


class QueryStore:
    def __init__(self, db_path: str, privacy: PrivacyMode):
        self.privacy = privacy
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.executescript(_SCHEMA)
        self._conn.commit()

    @property
    def persists_anything(self) -> bool:
        return self.privacy.aggregate_stats or self.privacy.store_raw_queries

    def record(
        self,
        *,
        blocked: bool,
        category: str = "",
        qtype: str = "",
        domain: Optional[str] = None,
        client_ip: Optional[str] = None,
        ts: Optional[int] = None,
    ) -> None:
        """Persist one query event, after applying the privacy policy."""
        if not self.persists_anything:
            return

        event_ts = int(ts if ts is not None else time.time())
        stored_domain = redact_domain(domain, self.privacy.store_raw_queries)
        stored_ip = apply_ip_policy(client_ip, self.privacy.client_ip_policy)

        with self._lock:
            self._conn.execute(
                "INSERT INTO query_events "
                "(ts, domain, qtype, blocked, category, client_ip) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (event_ts, stored_domain, qtype, 1 if blocked else 0,
                 category, stored_ip),
            )
            self._conn.commit()

    def stats(self) -> Dict[str, object]:
        """Aggregate counts suitable for a dashboard (no PII)."""
        with self._lock:
            total, blocked = self._conn.execute(
                "SELECT COUNT(*), COALESCE(SUM(blocked), 0) FROM query_events"
            ).fetchone()
            by_category = dict(
                self._conn.execute(
                    "SELECT category, COUNT(*) FROM query_events "
                    "WHERE blocked = 1 GROUP BY category"
                ).fetchall()
            )
        return {
            "total": total,
            "blocked": blocked,
            "allowed": total - blocked,
            "by_category": by_category,
        }

    def top_blocked_domains(self, limit: int = 10) -> List[Tuple[str, int]]:
        """Most-blocked domains. Empty unless the mode stored raw domains."""
        with self._lock:
            return self._conn.execute(
                "SELECT domain, COUNT(*) AS c FROM query_events "
                "WHERE blocked = 1 AND domain IS NOT NULL "
                "GROUP BY domain ORDER BY c DESC LIMIT ?",
                (limit,),
            ).fetchall()

    def prune(self, retention_days: int) -> int:
        """Delete events older than retention_days. Returns rows removed."""
        cutoff = int(time.time()) - retention_days * 86400
        with self._lock:
            cur = self._conn.execute(
                "DELETE FROM query_events WHERE ts < ?", (cutoff,)
            )
            self._conn.commit()
            return cur.rowcount

    def close(self) -> None:
        with self._lock:
            self._conn.close()
