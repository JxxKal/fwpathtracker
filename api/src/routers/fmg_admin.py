"""FMG-Verwaltung: Verbindungstest, Inventory-Sync, Status, Summary."""
from __future__ import annotations

import asyncio

from fastapi import APIRouter, Depends, HTTPException, Request

from database import get_pool
from deps import get_current_user, require_admin
from fmg.client import FmgError
from fmg.factory import build_fmg_client
from routers.config import read_config

router = APIRouter(prefix="/api/fmg", tags=["fmg"])


@router.post("/test")
async def test_connection(request: Request, _admin: dict = Depends(require_admin)) -> dict:
    """Verbindung testen: FMG-Version + verfügbare ADOMs zurückgeben."""
    fmg_cfg = await read_config("fmg")
    client = build_fmg_client(fmg_cfg, request.app.state.cfg)
    try:
        status = await client.rpc("get", "/sys/status")
        adoms = await client.rpc("get", "/dvmdb/adom") or []
        return {
            "ok": True,
            "version": (status or {}).get("Version") or (status or {}).get("version"),
            "hostname": (status or {}).get("Hostname") or (status or {}).get("hostname"),
            "adoms": sorted(
                a.get("name") for a in adoms
                if a.get("name") and not str(a.get("name")).startswith("FortiAnalyzer")
            ),
        }
    except FmgError as exc:
        raise HTTPException(502, f"FMG-Verbindung fehlgeschlagen: {exc}") from exc
    finally:
        await client.close()


@router.post("/sync")
async def start_sync(request: Request, _admin: dict = Depends(require_admin)) -> dict:
    state = request.app.state
    if state.sync_manager.state["phase"] == "running":
        raise HTTPException(409, "Sync läuft bereits.")
    fmg_cfg = await read_config("fmg")
    adoms = fmg_cfg.get("adoms") or []
    if not adoms:
        raise HTTPException(400, "Keine ADOMs konfiguriert – zuerst FMG-Test ausführen und ADOMs wählen.")
    client = build_fmg_client(fmg_cfg, state.cfg)

    async def _run() -> None:
        try:
            await state.sync_manager.run(
                get_pool(), client, adoms, on_done=state.set_inventory
            )
        finally:
            await client.close()

    asyncio.create_task(_run())
    return {"status": "started"}


@router.get("/sync/status")
async def sync_status(request: Request, _user: dict = Depends(get_current_user)) -> dict:
    return request.app.state.sync_manager.state


@router.get("/inventory/summary")
async def inventory_summary(request: Request, _user: dict = Depends(get_current_user)) -> dict:
    return request.app.state.inventory.summary()


@router.get("/inventory/owns/{ip}")
async def inventory_owns(ip: str, request: Request,
                         _user: dict = Depends(get_current_user)) -> dict:
    """Welche VDOM/Firewall hält dieses Netz? Alle PrefixTable-Treffer für die IP
    (connected/static/override, längster Präfix zuerst) plus der gewählte Start-Hop
    — zum sauberen Prüfen der Netz→VDOM-Zuordnung."""
    import ipaddress

    from engine.path import TraceError, find_ingress

    try:
        ipaddress.IPv4Address(ip.strip())
    except ipaddress.AddressValueError as exc:
        raise HTTPException(422, f"Ungültige IPv4-Adresse: {ip}") from exc

    state = request.app.state
    matches = [
        {"device": e.device, "vdom": e.vdom, "interface": e.interface,
         "cidr": str(e.network), "prefixlen": e.network.prefixlen,
         "source": e.source, "site_name": e.site_name}
        for e in state.prefixes.lookup_all(ip.strip())
    ]
    ingress = None
    try:
        d, v, i = find_ingress(state.prefixes, state.inventory, ip.strip())
        ingress = {"device": d, "vdom": v, "interface": i}
    except TraceError:
        pass
    return {"ip": ip.strip(), "ingress": ingress, "matches": matches}
