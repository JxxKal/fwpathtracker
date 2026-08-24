"""Switchport-Suche: an welchem Switch und Port hängt eine IP?

Dazu der Netzwerkport-Check: dieselbe Kette, aber vollständig ausgebreitet —
alle Fundstellen mit VLAN, die Portliste des Geräts (wenn es selbst überwacht
wird) und die VLAN-Interfaces der Firewalls, die das Netz tragen.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, Request

from deps import get_current_user, require_admin, resolve_query
from routers.config import read_config
from vlan import hostports

router = APIRouter(prefix="/api", tags=["locate"])


async def _librenms_cfg() -> dict:
    cfg = await read_config("librenms")
    if not cfg.get("base_url"):
        raise HTTPException(
            400, "LibreNMS ist nicht konfiguriert — bitte unter Einstellungen eintragen."
        )
    return cfg


@router.get("/arp-cache/status")
async def arp_cache_status(request: Request,
                           _user: dict = Depends(get_current_user)) -> dict:
    """Zustand der IP↔MAC-Historie: letzter Sweep + Bestand."""
    state = request.app.state
    try:
        stats = await state.arp_store.stats()
    except Exception as exc:
        stats = {"error": str(exc)}
    tracker = await read_config("tracker")
    return {
        "sweep": state.arp_sweeper.state,
        "stats": stats,
        "interval_s": int(tracker.get("arp_sweep_interval_s", 900)),
        "retention_days": int(tracker.get("arp_retention_days", 180)),
    }


@router.post("/arp-cache/sweep")
async def arp_cache_sweep(request: Request,
                          _admin: dict = Depends(require_admin)) -> dict:
    """Sweep sofort anstoßen (sonst läuft er im Hintergrund-Takt)."""
    state = request.app.state
    tracker = await read_config("tracker")
    return await state.arp_sweeper.run(
        state.arp_store, state.prefixes, await read_config("fmg"), state.cfg,
        retention_days=int(tracker.get("arp_retention_days", 180)),
    )


@router.get("/locate")
async def locate(
    request: Request,
    q: str = Query(min_length=2, max_length=128,
                   description="IP-Adresse oder auflösbarer Name"),
    _user: dict = Depends(get_current_user),
) -> dict:
    state = request.app.state
    ip, names = await resolve_query(request, q)
    return await state.locate.locate(
        ip, state.prefixes, await _librenms_cfg(), await read_config("fmg"), state.cfg,
        names=names,
    )


@router.get("/host-ports")
async def host_ports(
    request: Request,
    q: str = Query(min_length=2, max_length=128,
                   description="IP-Adresse oder auflösbarer Name"),
    _user: dict = Depends(get_current_user),
) -> dict:
    """Netzwerkport-Check: alle Ports des Hosts samt VLAN-Details."""
    state = request.app.state
    ip, names = await resolve_query(request, q)
    librenms_cfg = await _librenms_cfg()
    located = await state.locate.locate(
        ip, state.prefixes, librenms_cfg, await read_config("fmg"), state.cfg, names=names,
    )
    return await hostports.check(
        ip=ip, names=names, inv=state.inventory, prefixes=state.prefixes,
        client=state.locate.librenms, librenms_cfg=librenms_cfg,
        locate_result=located,
    )
