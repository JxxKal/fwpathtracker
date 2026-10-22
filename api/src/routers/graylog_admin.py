"""Graylog als eigene Quelle: Verbindungstest mit Diagnose (Settings-Panel)."""
from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request

from deps import require_admin
from graylog.client import GraylogNotConfigured
from graylog.winlog import diagnose
from routers.config import read_config

router = APIRouter(prefix="/api/graylog", tags=["graylog"])


@router.post("/test")
async def test_connection(request: Request, _admin: dict = Depends(require_admin)) -> dict:
    """Version, lesbare Streams, Winlogbeat-Feldschreibweise, Treffer der
    letzten 24 h je Rolle (AD, iFIX) und Vorschläge für den iFIX-Filter."""
    cfg = await read_config("graylog")
    if not cfg.get("base_url"):
        raise HTTPException(400, "Graylog nicht konfiguriert – bitte zuerst speichern.")
    try:
        return {"ok": True, **await diagnose(request.app.state.graylog, cfg,
                                             datetime.now(timezone.utc))}
    except GraylogNotConfigured as exc:
        raise HTTPException(400, str(exc)) from exc
    except Exception as exc:
        raise HTTPException(502, f"Verbindung fehlgeschlagen: {exc}") from exc
