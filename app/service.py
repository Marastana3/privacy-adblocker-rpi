"""Framework-agnostic application service.

All dashboard/API behavior lives here as plain Python so it can be tested
without a web server. app/api.py is a thin FastAPI layer over this class.
"""
from __future__ import annotations

from typing import Callable, Dict, List, Optional

from dns_engine.block_engine import BlockEngine, _normalize
from dns_engine.blocklist_loader import load_blocklists
from dns_engine.list_manager import ListManager
from dns_engine.updater import RemoteBlocklistUpdater
from privacy.privacy_modes import PrivacyMode, describe_retention, get_mode
from privacy.storage import QueryStore


def _valid_domain(domain: str) -> str:
    d = _normalize(domain)
    if not d or "." not in d or " " in d or "/" in d:
        raise ValueError(f"invalid domain: {domain!r}")
    return d


class AdblockService:
    def __init__(
        self,
        *,
        engine: BlockEngine,
        list_manager: ListManager,
        store: Optional[QueryStore],
        privacy_mode: PrivacyMode,
        blocklists_dir: str,
        remote_sources: Optional[Dict[str, List[str]]] = None,
    ):
        self.engine = engine
        self.list_manager = list_manager
        self.store = store
        self.privacy_mode = privacy_mode
        self.blocklists_dir = blocklists_dir
        self.remote_sources = remote_sources or {}

    # -- stats --------------------------------------------------------------

    def stats(self) -> Dict[str, object]:
        if self.store is None:
            return {"total": 0, "blocked": 0, "allowed": 0, "by_category": {}}
        return self.store.stats()

    def top_blocked(self, limit: int = 10) -> List[Dict[str, object]]:
        if self.store is None:
            return []
        return [
            {"domain": d, "count": c}
            for d, c in self.store.top_blocked_domains(limit)
        ]

    # -- categories ---------------------------------------------------------

    def categories(self) -> List[Dict[str, object]]:
        return [
            {"name": c, "enabled": self.engine.is_category_enabled(c)}
            for c in sorted(self.engine.categories)
        ]

    def set_category(self, name: str, enabled: bool) -> None:
        if name.lower() not in {c.lower() for c in self.engine.categories}:
            raise KeyError(f"unknown category: {name!r}")
        self.engine.set_category_enabled(name, enabled)

    # -- whitelist ----------------------------------------------------------

    def whitelist(self) -> List[str]:
        return self.engine.whitelisted_domains()

    def add_allow(self, domain: str) -> None:
        self.list_manager.add_allow(_valid_domain(domain))

    def remove_allow(self, domain: str) -> bool:
        return self.list_manager.remove_allow(_normalize(domain))

    # -- blocklist ----------------------------------------------------------

    def blocklist(self) -> Dict[str, List[str]]:
        return self.engine.blocked_by_category()

    def add_block(self, domain: str, category: str = "custom") -> None:
        self.list_manager.add_block(_valid_domain(domain), category)

    def remove_block(self, domain: str) -> bool:
        return self.list_manager.remove_block(_normalize(domain))

    # -- privacy ------------------------------------------------------------

    def privacy(self) -> Dict[str, str]:
        return {
            "mode": self.privacy_mode.name,
            "retention": describe_retention(self.privacy_mode),
        }

    # -- remote blocklist update -------------------------------------------

    def update_remote(
        self, fetcher: Optional[Callable[[str], str]] = None
    ) -> Dict[str, int]:
        """Fetch configured remote sources, merge, and reload the live engine."""
        updater = (
            RemoteBlocklistUpdater(self.blocklists_dir, fetcher)
            if fetcher is not None
            else RemoteBlocklistUpdater(self.blocklists_dir)
        )
        result = updater.update_all(self.remote_sources)
        self.reload()
        return result

    def reload(self) -> None:
        """Rebuild engine rules from disk (preserves category toggle state)."""
        self.engine.load(load_blocklists(self.blocklists_dir))


def build_service_from_config(cfg, store: Optional[QueryStore] = None) -> AdblockService:
    """Construct a service from an AppConfig (see dns_engine.resolver.load_config)."""
    engine = BlockEngine(
        load_blocklists(cfg.blocklists_dir),
        disabled_categories=cfg.disabled_categories,
    )
    list_manager = ListManager(cfg.blocklists_dir, engine)
    privacy_mode = get_mode(cfg.privacy_mode)
    if store is None:
        store = QueryStore(cfg.db_path, privacy_mode)
    return AdblockService(
        engine=engine,
        list_manager=list_manager,
        store=store,
        privacy_mode=privacy_mode,
        blocklists_dir=cfg.blocklists_dir,
        remote_sources=getattr(cfg, "remote_sources", None),
    )
