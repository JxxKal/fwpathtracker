"""iTop-Verbindungstest + Subnetz-Tools (Settings-Panel / Free-Subnet-Finder)."""
from __future__ import annotations

import ipaddress

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from deps import get_current_user, require_admin
from routers.config import read_config

router = APIRouter(prefix="/api/itop", tags=["itop"])

# Standort-Supernetze (Vorauswahl im Free-Subnet-Finder). Default = die in iTop
# gepflegten Bereiche; über config-Key 'site_supernets' ({sites:[{name,cidr}]})
# überschreibbar.
DEFAULT_SITE_SUPERNETS = [
    {"name": "Holstein", "cidr": "10.180.0.0/20"},
    {"name": "Gas Nord", "cidr": "10.180.16.0/20"},
    {"name": "Hamburg", "cidr": "10.180.32.0/20"},
    {"name": "Oel West", "cidr": "10.180.48.0/21"},
    {"name": "Oel Nord", "cidr": "10.180.56.0/21"},
]


def _normalize_sites(sites: list) -> list[dict]:
    """Gespeicherte Supernetze robust einlesen: Alt-Feld 'label' als Name
    akzeptieren, leere Namen aus den Defaults per CIDR nachfüllen. Verhindert
    leere Beschreibungsfelder im Panel bei Alt-/Teil-Configs."""
    by_cidr = {s["cidr"]: s["name"] for s in DEFAULT_SITE_SUPERNETS}
    out: list[dict] = []
    for s in sites:
        if not isinstance(s, dict):
            continue
        cidr = str(s.get("cidr") or "").strip()
        if not cidr:
            continue
        name = str(s.get("name") or s.get("label") or "").strip()
        if not name:
            name = by_cidr.get(cidr, "")
        out.append({"name": name, "cidr": cidr})
    return out


@router.get("/site-supernets")
async def site_supernets(_user: dict = Depends(get_current_user)) -> dict:
    cfg = await read_config("site_supernets")
    sites = cfg.get("sites")
    if isinstance(sites, list) and sites:
        return {"sites": _normalize_sites(sites)}
    return {"sites": DEFAULT_SITE_SUPERNETS}


@router.post("/test")
async def test_connection(request: Request, _admin: dict = Depends(require_admin)) -> dict:
    cfg = await read_config("itop")
    if not cfg.get("base_url"):
        raise HTTPException(400, "iTop nicht konfiguriert – bitte zuerst speichern.")
    try:
        return await request.app.state.resolver.itop.test(cfg)
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(502, f"Verbindung fehlgeschlagen: {exc}") from exc


class FreeSubnetRequest(BaseModel):
    supernet: str = Field(min_length=1, max_length=64)
    prefix: int = Field(ge=1, le=32)


@router.post("/free-subnets")
async def free_subnets(body: FreeSubnetRequest, request: Request,
                       _user: dict = Depends(get_current_user)) -> dict:
    """Freie Subnetze gewünschter Größe in einem Supernet finden — belegter Bestand
    kommt aus iTop (IPAM). Liefert ausgerichtete freie Blöcke (überlappungsfrei)."""
    cfg = await read_config("itop")
    if not cfg.get("base_url"):
        raise HTTPException(400, "iTop nicht konfiguriert – bitte zuerst speichern.")
    try:
        supernet = ipaddress.IPv4Network(body.supernet.strip(), strict=False)
    except ValueError as exc:
        raise HTTPException(422, f"Ungültiges Supernet (CIDR erwartet): {body.supernet}") from exc
    if body.prefix < supernet.prefixlen:
        raise HTTPException(
            422, f"Gewünschte Blockgröße /{body.prefix} ist größer als das Supernet "
            f"/{supernet.prefixlen} — kleineren Block (größeres Präfix) wählen.")

    try:
        subs = await request.app.state.resolver.itop.subnets(cfg)
    except Exception as exc:
        raise HTTPException(502, f"iTop-Subnetze konnten nicht geladen werden: {exc}") from exc

    allocated = []
    for s in subs:
        try:
            n = ipaddress.IPv4Network(s["cidr"])
        except ValueError:
            continue
        if n.overlaps(supernet):
            allocated.append(n)

    free: list[str] = []
    scanned = 0
    MAX_SCAN, MAX_FREE = 50000, 512
    for cand in supernet.subnets(new_prefix=body.prefix):
        scanned += 1
        if scanned > MAX_SCAN:
            break
        if not any(cand.overlaps(a) for a in allocated):
            free.append(str(cand))
            if len(free) >= MAX_FREE:
                break
    return {
        "supernet": str(supernet), "prefix": body.prefix,
        "allocated": len(allocated), "subnets_total": len(subs),
        "free": free, "capped": scanned > MAX_SCAN or len(free) >= MAX_FREE,
    }


@router.post("/refresh")
async def refresh_index(request: Request, _admin: dict = Depends(require_admin)) -> dict:
    """Host-Index (Namensauflösung) sofort neu laden — Cache invalidieren."""
    cfg = await read_config("itop")
    if not cfg.get("base_url"):
        raise HTTPException(400, "iTop nicht konfiguriert – bitte zuerst speichern.")
    try:
        count = await request.app.state.resolver.itop.refresh(cfg)
        return {"ok": True, "count": count}
    except Exception as exc:
        raise HTTPException(502, f"iTop-Refresh fehlgeschlagen: {exc}") from exc
