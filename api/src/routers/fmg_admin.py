"""FMG-Verwaltung: Verbindungstest, Inventory-Sync, Status, Summary."""
from __future__ import annotations

import asyncio

from fastapi import APIRouter, Depends, HTTPException, Query, Request

from database import get_pool
from deps import get_current_user, require_admin, resolve_query
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


@router.get("/inventory/owns")
async def inventory_owns_query(
    request: Request,
    q: str = Query(min_length=2, max_length=128,
                   description="IP-Adresse oder auflösbarer Name (FMG-Objekt, iTop, DNS)"),
    _user: dict = Depends(get_current_user),
) -> dict:
    """Netz-Zugehörigkeit für IP ODER Namen.

    Eigener Endpunkt statt Pfad-Parameter, weil FMG-Objektnamen Schrägstriche und
    Leerzeichen enthalten dürfen ('NET-10.1.0.0/16') — als Pfadsegment wäre das
    nicht zuverlässig zu übertragen.
    """
    ip, names = await resolve_query(request, q)
    return _owns(request, ip, names)


@router.get("/inventory/owns/{ip}")
async def inventory_owns(ip: str, request: Request,
                         _user: dict = Depends(get_current_user)) -> dict:
    """Bestandspfad (reine IP) — bleibt für vorhandene Links/Skripte bestehen."""
    import ipaddress

    try:
        ipaddress.IPv4Address(ip.strip())
    except ipaddress.AddressValueError as exc:
        raise HTTPException(422, f"Ungültige IPv4-Adresse: {ip}") from exc
    return _owns(request, ip.strip(), [])


def _owns(request: Request, ip: str, names: list[str]) -> dict:
    """Welche VDOM/Firewall hält dieses Netz? Alle PrefixTable-Treffer für die IP
    (connected/static/override, längster Präfix zuerst) plus der gewählte Start-Hop
    — zum sauberen Prüfen der Netz→VDOM-Zuordnung."""
    from engine.path import TraceError, find_ingress

    state = request.app.state
    inv = state.inventory
    # Nur connected/override zeigen den URSPRUNG des Netzes — statische Routen
    # (bloße Erreichbarkeit) sind hier uninteressant.
    matches = []
    for e in state.prefixes.lookup_all(ip):
        if e.source not in ("connected", "override"):
            continue
        info = inv.interface(e.device, e.interface) if e.interface else None
        gateway = None
        if info:
            candidates = ([info["ip"]] if info.get("ip") else []) + info.get("secondary_ips", [])
            for iface in candidates:
                if iface is not None and iface.network == e.network:
                    gateway = str(iface.ip)   # Interface-IP = Gateway des Segments
                    break
        matches.append({
            "device": e.device, "vdom": e.vdom, "interface": e.interface,
            "vlan": (info or {}).get("vlanid"),
            "cidr": str(e.network), "prefixlen": e.network.prefixlen,
            "netmask": str(e.network.netmask), "gateway": gateway,
            "source": e.source, "site_name": e.site_name,
        })
    ingress = None
    try:
        d, v, i = find_ingress(state.prefixes, state.inventory, ip)
        ingress = {"device": d, "vdom": v, "interface": i}
    except TraceError:
        pass
    # Namen mitgeben: bei Eingabe eines Objektnamens soll sichtbar sein, auf
    # welche IP er aufgelöst wurde.
    return {"ip": ip, "names": names, "ingress": ingress, "matches": matches}
