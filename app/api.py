"""FastAPI wrapper over AdblockService.

Thin by design: every route delegates to the service, which holds the logic and
is unit-tested without a server. Run with:

    uvicorn app.api:app                      # uses config.yaml
    PAB_API_KEY=secret uvicorn app.api:app   # require X-API-Key on writes
"""
from __future__ import annotations

import os
from typing import List, Optional

from fastapi import Depends, FastAPI, Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from app.service import AdblockService, build_service_from_config


# -- request models ---------------------------------------------------------

class CategoryUpdate(BaseModel):
    enabled: bool


class DomainIn(BaseModel):
    domain: str


class BlockDomainIn(BaseModel):
    domain: str
    category: str = "custom"


def create_app(service: AdblockService, api_key: Optional[str] = None) -> FastAPI:
    app = FastAPI(title="privacy-adblocker-rpi API", version="0.1.0")

    # This runs as a LAN appliance and the dashboard is served from a different
    # origin during development (Vite on :5173), so allow cross-origin calls.
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_methods=["*"],
        allow_headers=["*"],
    )

    def require_key(x_api_key: Optional[str] = Header(default=None)) -> None:
        # Auth only enforced if an API key is configured; reads stay open.
        if api_key and x_api_key != api_key:
            raise HTTPException(status_code=401, detail="invalid or missing API key")

    write = [Depends(require_key)]

    @app.get("/health")
    def health():
        return {"status": "ok"}

    @app.get("/stats")
    def stats():
        return service.stats()

    @app.get("/stats/top-blocked")
    def top_blocked(limit: int = 10):
        return service.top_blocked(limit)

    @app.get("/privacy")
    def privacy():
        return service.privacy()

    # categories
    @app.get("/categories")
    def categories():
        return service.categories()

    @app.post("/categories/{name}", dependencies=write)
    def set_category(name: str, body: CategoryUpdate):
        try:
            service.set_category(name, body.enabled)
        except KeyError:
            raise HTTPException(status_code=404, detail=f"unknown category: {name}")
        return {"name": name, "enabled": body.enabled}

    # whitelist
    @app.get("/lists/whitelist")
    def get_whitelist():
        return service.whitelist()

    @app.post("/lists/whitelist", dependencies=write)
    def add_allow(body: DomainIn):
        try:
            service.add_allow(body.domain)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc))
        return {"domain": body.domain, "allowed": True}

    @app.delete("/lists/whitelist/{domain}", dependencies=write)
    def remove_allow(domain: str):
        removed = service.remove_allow(domain)
        return {"domain": domain, "removed": removed}

    # blocklist
    @app.get("/lists/block")
    def get_blocklist():
        return service.blocklist()

    @app.post("/lists/block", dependencies=write)
    def add_block(body: BlockDomainIn):
        try:
            service.add_block(body.domain, body.category)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc))
        return {"domain": body.domain, "category": body.category, "blocked": True}

    @app.delete("/lists/block/{domain}", dependencies=write)
    def remove_block(domain: str):
        removed = service.remove_block(domain)
        return {"domain": domain, "removed": removed}

    # remote update
    @app.post("/blocklists/update", dependencies=write)
    def update_remote():
        return service.update_remote()

    # If the dashboard has been built (frontend/dist), serve it at / so the Pi
    # can run the API and UI from a single process. Mounted last so it never
    # shadows the API routes above.
    here = os.path.dirname(os.path.abspath(__file__))
    dist = os.path.abspath(os.path.join(here, "..", "frontend", "dist"))
    if os.path.isdir(dist):
        from fastapi.staticfiles import StaticFiles

        app.mount("/", StaticFiles(directory=dist, html=True), name="dashboard")

    return app


def _build_default_app() -> FastAPI:
    # Imported lazily so tests that only touch the service don't need config.
    from dns_engine.resolver import load_config

    here = os.path.dirname(os.path.abspath(__file__))
    repo_root = os.path.abspath(os.path.join(here, ".."))
    cfg_path = os.environ.get("PAB_CONFIG", os.path.join(repo_root, "config.yaml"))
    cfg = load_config(cfg_path)
    service = build_service_from_config(cfg)
    return create_app(service, api_key=os.environ.get("PAB_API_KEY"))


# ASGI entrypoint for `uvicorn app.api:app`
app = _build_default_app()
