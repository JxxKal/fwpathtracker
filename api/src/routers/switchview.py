"""Switch-Ansicht: was hängt an welchem Port — interaktiv statt als Zeichnung.

Die draw.io-Datei ist der Weg aufs Papier. Beim Nachsehen im Alltag will man
aber klicken: Switch wählen, Buchsen sehen, auf eine Buchse klicken und lesen,
was daran hängt. Genau diese Frage beantwortet die Switchport-Suche von der
anderen Seite — dort sucht man ein Gerät, hier schaut man auf ein Blech.

Dieselbe Quelle wie die physische Zeichnung: Ports und FDB aus LibreNMS,
IP↔MAC aus der Historie, Namen aus dem Reverse-DNS. Ist für das Modell ein
Bild mit zugeordneten Buchsen hinterlegt, kommt es mit — dann zeigt die
Oberfläche dieselbe Frontblende wie der Plan.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request

from deps import get_current_user
from diagram import physical
from resolver.dns_cache import build_reverse
from routers.config import read_config

router = APIRouter(prefix="/api/switch-view", tags=["switchview"])


async def _librenms(request: Request) -> dict:
    cfg = await read_config("librenms")
    if not cfg.get("base_url"):
        raise HTTPException(400, "LibreNMS ist nicht konfiguriert.")
    return cfg


@router.get("/filters")
async def filters(request: Request, _user: dict = Depends(get_current_user)) -> dict:
    """Standorte und Gerätegruppen aus LibreNMS."""
    cfg = await _librenms(request)
    client = request.app.state.locate.librenms
    out: dict = {"locations": [], "groups": [], "warnings": []}
    try:
        out["locations"] = sorted(
            {n for n in (physical.location_name(r.get("location"))
                         for r in await client.locations(cfg)) if n})
    except Exception as exc:
        out["warnings"].append(f"Standorte nicht abrufbar: {exc}")
    try:
        out["groups"] = [{"name": str(g.get("name")), "desc": g.get("desc") or None}
                         for g in await client.device_groups(cfg) if g.get("name")]
    except Exception as exc:
        out["warnings"].append(f"Gerätegruppen nicht abrufbar: {exc}")
    return out


@router.get("/devices")
async def devices(request: Request, location: str | None = None, group: str | None = None,
                  _user: dict = Depends(get_current_user)) -> dict:
    cfg = await _librenms(request)
    client = request.app.state.locate.librenms
    try:
        index = await client.device_index(cfg)
        allow = await physical.allowed_devices(client, cfg, location, group)
    except Exception as exc:
        raise HTTPException(502, f"LibreNMS nicht abrufbar: {exc}") from exc
    seen: dict[str, dict] = {}
    for dev in index.values():
        did = str(dev.get("device_id") or "")
        if did and did not in seen and (allow is None or did in allow):
            seen[did] = {"device_id": did,
                         "name": dev.get("sysName") or dev.get("hostname") or did,
                         "ip": dev.get("ip"), "hardware": dev.get("hardware"),
                         "location": physical.location_name(dev.get("location"))}
    return {"devices": sorted(seen.values(), key=lambda d: d["name"].lower())}


@router.get("")
async def switch_view(request: Request, device_id: str,
                      _user: dict = Depends(get_current_user)) -> dict:
    """Ein Switch mit allen Ports, Belegung und — falls hinterlegt — seinem
    Blech samt Buchsenlage."""
    state = request.app.state
    cfg = await _librenms(request)
    warnings: list[str] = []

    async def arp_by_mac(macs: list[str]) -> dict:
        try:
            return await state.arp_store.latest_by_macs(macs)
        except Exception as exc:
            warnings.append(f"IP↔MAC-Historie nicht lesbar: {exc}")
            return {}

    reverse = await build_reverse(state, await read_config("dns"))
    model = await physical.switch_model(state.locate.librenms, cfg, device_id,
                                        arp_by_mac, warnings, dns=reverse)
    if reverse is not None:
        await reverse.flush()
    dev = model["device"]
    rules = (await read_config("shapes")).get("rules") or []
    rule = physical.match_rule(dev, rules)
    place = physical.port_places(rule)

    ports = []
    for p in model["ports"]:
        spot = place(p["name"]) if place else None
        ports.append({**p, "unit": physical.port_unit(p["name"]), "spot": spot})
    shape = None
    if rule and place:
        shape = {"image": rule["image"], "width": rule.get("width") or 800,
                 "height": rule.get("height") or 120, "label": rule.get("label")}
    return {
        "device": {"device_id": str(device_id),
                   "name": dev.get("sysName") or dev.get("hostname") or str(device_id),
                   "ip": dev.get("ip"), "hardware": dev.get("hardware"),
                   "os": dev.get("os"),
                   "location": physical.location_name(dev.get("location"))},
        "ports": ports, "logical": model.get("logical", 0),
        "units": sorted({p["unit"] for p in ports}),
        "shape": shape, "warnings": warnings,
    }
