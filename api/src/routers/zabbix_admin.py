"""Zabbix-Verbindungstest + Cache-Invalidierung (Settings-Panel)."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request

from deps import require_admin
from routers.config import read_config
from zabbix.client import ZabbixNotConfigured

router = APIRouter(prefix="/api/zabbix", tags=["zabbix"])


@router.post("/test")
async def test_connection(request: Request, _admin: dict = Depends(require_admin)) -> dict:
    cfg = await read_config("zabbix")
    if not cfg.get("base_url"):
        raise HTTPException(400, "Zabbix nicht konfiguriert – bitte zuerst speichern.")
    try:
        return await request.app.state.zabbix.test(cfg)
    except ZabbixNotConfigured as exc:
        raise HTTPException(400, str(exc)) from exc
    except Exception as exc:
        raise HTTPException(502, f"Verbindung fehlgeschlagen: {exc}") from exc


@router.post("/refresh")
async def refresh_cache(request: Request, _admin: dict = Depends(require_admin)) -> dict:
    request.app.state.zabbix.invalidate()
    return {"ok": True}
