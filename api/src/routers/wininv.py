"""Windows-Inventar: Verbindungstest, Import, Hosts (nur Admins — die Daten
enthalten Konten, Freigaben und Dienste)."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request

from deps import require_admin
from netguard import guard_egress_host
from routers.config import read_config
from wininv.source import SourceError, is_unc, unc_parts

router = APIRouter(prefix="/api/wininv", tags=["wininv"])


async def _cfg() -> dict:
    cfg = await read_config("wininv")
    path = (cfg.get("path") or "").strip()
    if not path:
        raise HTTPException(400, "Kein Pfad zur Freigabe konfiguriert – bitte zuerst speichern.")
    if is_unc(path):
        try:
            server, _ = unc_parts(path)
        except SourceError as exc:
            raise HTTPException(400, str(exc)) from exc
        guard_egress_host(server, "Inventar-Server")
    return cfg


@router.post("/test")
async def test(request: Request, _admin: dict = Depends(require_admin)) -> dict:
    cfg = await _cfg()
    try:
        return await request.app.state.wininv.test(cfg)
    except SourceError as exc:
        raise HTTPException(502, str(exc)) from exc
    except Exception as exc:
        raise HTTPException(502, f"Freigabe nicht lesbar: {exc}") from exc


@router.post("/import")
async def run_import(request: Request, _admin: dict = Depends(require_admin)) -> dict:
    cfg = await _cfg()
    try:
        return await request.app.state.wininv.run(cfg)
    except RuntimeError as exc:
        raise HTTPException(409, str(exc)) from exc
    except Exception as exc:
        raise HTTPException(502, f"Import fehlgeschlagen: {exc}") from exc


@router.get("/status")
async def status(request: Request, _admin: dict = Depends(require_admin)) -> dict:
    svc = request.app.state.wininv
    return {"running": svc.running, "last": svc.last}


@router.get("/hosts")
async def hosts(request: Request, _admin: dict = Depends(require_admin)) -> dict:
    cfg = await read_config("wininv")
    items = await request.app.state.wininv.hosts(int(cfg.get("stale_days") or 3))
    return {"hosts": items, "last": request.app.state.wininv.last}


@router.get("/hosts/{hostname}")
async def host(hostname: str, request: Request, _admin: dict = Depends(require_admin)) -> dict:
    cfg = await read_config("wininv")
    item = await request.app.state.wininv.host(hostname, int(cfg.get("stale_days") or 3))
    if item is None:
        raise HTTPException(404, f"{hostname} ist nicht im Windows-Inventar.")
    return item
