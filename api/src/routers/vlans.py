"""VLAN-Übersicht: belegte VLAN-Nummern aus Switch- und Firewall-Sicht, plus freie."""
from __future__ import annotations

from fastapi import APIRouter, Depends, Request

from deps import get_current_user
from routers.config import read_config
from vlan import overview

router = APIRouter(prefix="/api", tags=["vlans"])


@router.get("/vlans")
async def vlans(request: Request, _user: dict = Depends(get_current_user)) -> dict:
    """Alle bekannten VLANs mit Beschreibung, Subnetz und Fundorten.

    Ohne LibreNMS-Konfiguration liefert der Endpunkt die reine Firewall-Sicht
    statt eines Fehlers — eine halbe Übersicht ist hier mehr wert als keine.
    """
    state = request.app.state
    return await overview.build(
        state.inventory, state.locate.librenms, await read_config("librenms")
    )
