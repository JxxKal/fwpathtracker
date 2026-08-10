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

    ip = value
    if not is_ip(value):
        # Namen über dieselbe Kette auflösen wie Quelle/Ziel im Tracker,
        # damit Autocomplete-Treffer hier ohne Umweg funktionieren.
        try:
            resolved = await state.resolver.resolve_endpoint(
                value, state.inventory,
                await read_config("itop"), await read_config("dns"),
            )
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from exc
        ip = resolved["ip"]

    librenms_cfg = await read_config("librenms")
    if not librenms_cfg.get("base_url"):
        raise HTTPException(
            400, "LibreNMS ist nicht konfiguriert — bitte unter Einstellungen eintragen."
        )

    return await state.locate.locate(
        ip, state.prefixes, librenms_cfg, await read_config("fmg"), state.cfg
    )
