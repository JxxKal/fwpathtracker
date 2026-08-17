"""Switchport-Suche: an welchem Switch und Port hängt eine IP?

Dazu der Netzwerkport-Check: dieselbe Kette, aber vollständig ausgebreitet —
alle Fundstellen mit VLAN, die Portliste des Geräts (wenn es selbst überwacht
wird) und die VLAN-Interfaces der Firewalls, die das Netz tragen.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, Request

from deps import get_current_user
from resolver.chain import is_ip, is_ipv6
from routers.config import read_config
from vlan import hostports

router = APIRouter(prefix="/api", tags=["locate"])


async def _resolve(request: Request, value: str) -> tuple[str, list[str]]:
    """Eingabe (IP oder Name) → (IP, alle bekannten Namen).

    Immer über die Resolver-Kette gehen — auch bei einer IP. Die Namen sind
    hier nicht Kosmetik: der FMG-Objektname des Ziels ist das, wonach in
    LLDP-Nachbarschaften und Port-Descriptions gesucht wird.
    """
    if is_ipv6(value):
        raise HTTPException(400, "IPv6 wird nicht unterstützt (wie im Pfad-Tracker).")
    state = request.app.state
    itop_cfg, dns_cfg = await read_config("itop"), await read_config("dns")
    try:
        resolved = await state.resolver.resolve_endpoint(
            value, state.inventory, itop_cfg, dns_cfg
        )
        return resolved["ip"], [n["name"] for n in resolved.get("names", []) if n.get("name")]
    except ValueError as exc:
        if not is_ip(value):
            raise HTTPException(422, str(exc)) from exc
        # Eine IP ohne bekannten Namen ist völlig in Ordnung — dann eben ohne
        # Alias-Abgleich weiter.
        return value, []


async def _librenms_cfg() -> dict:
    cfg = await read_config("librenms")
    if not cfg.get("base_url"):
        raise HTTPException(
            400, "LibreNMS ist nicht konfiguriert — bitte unter Einstellungen eintragen."
        )
    return cfg


@router.get("/locate")
async def locate(
    request: Request,
    q: str = Query(min_length=2, max_length=128,
                   description="IP-Adresse oder auflösbarer Name"),
    _user: dict = Depends(get_current_user),
) -> dict:
    state = request.app.state
    ip, names = await _resolve(request, q.strip())
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
    ip, names = await _resolve(request, q.strip())
    librenms_cfg = await _librenms_cfg()
    located = await state.locate.locate(
        ip, state.prefixes, librenms_cfg, await read_config("fmg"), state.cfg, names=names,
    )
    return await hostports.check(
        ip=ip, names=names, inv=state.inventory, prefixes=state.prefixes,
        client=state.locate.librenms, librenms_cfg=librenms_cfg,
        locate_result=located,
    )
