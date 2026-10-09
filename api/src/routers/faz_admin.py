"""FortiAnalyzer-Verbindungstest + Cache-Invalidierung (Settings-Panel)."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request

from deps import require_admin
from faz.client import FazNotConfigured
from routers.config import read_config

router = APIRouter(prefix="/api/faz", tags=["faz"])


@router.post("/test")
async def test_connection(request: Request, _admin: dict = Depends(require_admin)) -> dict:
    cfg = await read_config("faz")
    try:
        return await request.app.state.faz.test(cfg)
    except FazNotConfigured as exc:
        raise HTTPException(400, f"{exc} Bitte zuerst speichern.") from exc
    except Exception as exc:
        raise HTTPException(502, f"Verbindung fehlgeschlagen: {exc}") from exc


@router.post("/refresh")
async def refresh_cache(request: Request, _admin: dict = Depends(require_admin)) -> dict:
    request.app.state.faz.invalidate()
    return {"ok": True}
