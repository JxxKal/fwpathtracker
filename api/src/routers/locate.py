"""Switchport-Suche: an welchem Switch und Port hängt eine IP?"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, Request

from deps import get_current_user
from resolver.chain import is_ip, is_ipv6
from routers.config import read_config

router = APIRouter(prefix="/api", tags=["locate"])


@router.get("/locate")
async def locate(
    request: Request,
    q: str = Query(min_length=2, max_length=128,
                   description="IP-Adresse oder auflösbarer Name"),
    _user: dict = Depends(get_current_user),
) -> dict:
    state = request.app.state
    value = q.strip()

    if is_ipv6(value):
        raise HTTPException(400, "IPv6 wird nicht unterstützt (wie im Pfad-Tracker).")

    itop_cfg, dns_cfg = await read_config("itop"), await read_config("dns")

    # Immer über die Resolver-Kette gehen — auch bei einer IP. Die Namen sind
    # hier nicht Kosmetik: der FMG-Objektname des Ziels ist das, wonach in
    # LLDP-Nachbarschaften und Port-Descriptions gesucht wird.
    ip, names = value, []
    try:
        resolved = await state.resolver.resolve_endpoint(
            value, state.inventory, itop_cfg, dns_cfg
        )
        ip = resolved["ip"]
        names = [n["name"] for n in resolved.get("names", []) if n.get("name")]
    except ValueError as exc:
        if not is_ip(value):
            raise HTTPException(422, str(exc)) from exc
        # Eine IP ohne bekannten Namen ist völlig in Ordnung — dann eben ohne
        # Alias-Abgleich weiter.

    librenms_cfg = await read_config("librenms")
    if not librenms_cfg.get("base_url"):
        raise HTTPException(
            400, "LibreNMS ist nicht konfiguriert — bitte unter Einstellungen eintragen."
        )

    return await state.locate.locate(
        ip, state.prefixes, librenms_cfg, await read_config("fmg"), state.cfg,
        names=names,
    )
