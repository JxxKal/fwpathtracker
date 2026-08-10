"""LibreNMS-Verbindungstest + Cache-Invalidierung (Settings-Panel)."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request

from deps import require_admin
from librenms.client import LibrenmsNotConfigured
from routers.config import read_config

router = APIRouter(prefix="/api/librenms", tags=["librenms"])


@router.post("/test")
async def test_connection(request: Request, _admin: dict = Depends(require_admin)) -> dict:
    cfg = await read_config("librenms")
    if not cfg.get("base_url"):
        raise HTTPException(400, "LibreNMS nicht konfiguriert – bitte zuerst speichern.")
    try:
        return await request.app.state.locate.librenms.test(cfg)
    except LibrenmsNotConfigured as exc:
        raise HTTPException(400, str(exc)) from exc
    except Exception as exc:
        raise HTTPException(502, f"Verbindung fehlgeschlagen: {exc}") from exc


@router.post("/refresh")
async def refresh_cache(request: Request, _admin: dict = Depends(require_admin)) -> dict:
    """Caches leeren — nach einer frisch angestoßenen Discovery in LibreNMS."""
    request.app.state.locate.librenms.invalidate()
    return {"ok": True}
