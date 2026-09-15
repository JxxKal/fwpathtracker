"""Netzplan als draw.io-Datei: Scope (VDOM oder Firewall) → Netze, Kopplungen,
optional Hosts — aus FMG-Inventar, iTop, ARP-Historie und LibreNMS."""
from __future__ import annotations

import ipaddress
import logging
import re

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

import httpx

from deps import get_current_user, require_admin
from diagram import drawio, model as diagram_model
from netguard import guard_egress_url
from routers.config import read_config

log = logging.getLogger("routers.diagram")
router = APIRouter(prefix="/api/diagram", tags=["diagram"])


class DiagramRequest(BaseModel):
    scope: str = Field(pattern="^(vdom|firewall)$")
    device: str = Field(min_length=1, max_length=128)
    vdom: str | None = Field(default=None, max_length=64)
    hosts: str = Field(default="auto", pattern="^(auto|all|netdev|none)$")


async def drawio_url() -> str | None:
    """Selbst gehostete draw.io-Instanz (system_config['drawio'].base_url) —
    ohne Schrägstrich am Ende, leer = kein „In draw.io öffnen"."""
    cfg = await read_config("drawio")
    url = str(cfg.get("base_url") or "").strip().rstrip("/")
    return url or None


@router.get("/scopes")
async def scopes(request: Request, _user: dict = Depends(get_current_user)) -> dict:
    """Geräte und VDOMs aus dem FMG-Inventar — Auswahl im Werkzeug. Dazu die
    draw.io-URL, damit das Werkzeug den Öffnen-Button anbieten kann."""
    inv = request.app.state.inventory
    devices = [{"device": d, "adom": info["adom"], "vdoms": list(info["vdoms"] or ["root"])}
               for d, info in sorted(inv.devices.items())]
    return {"devices": devices, "max_hosts": diagram_model.MAX_HOSTS,
            "drawio_url": await drawio_url()}


@router.post("/drawio/test")
async def drawio_test(_admin: dict = Depends(require_admin)) -> dict:
    """Erreichbarkeit der draw.io-Instanz vom Server aus — ein GET auf die
    Basis-URL. Der Browser der Kollegen muss sie zusätzlich selbst erreichen."""
    url = await drawio_url()
    if not url:
        raise HTTPException(400, "draw.io-URL nicht konfiguriert – bitte zuerst speichern.")
    # Die URL ist für die BROWSER der Nutzer gedacht, nicht für den Server. Ein
    # Kurzname wie 'svo3041-ot' löst im Container auf 127.0.1.1 auf (Debian
    # legt den eigenen Hostnamen darauf) — das darf der SSRF-Schutz nicht
    # durchlassen, macht die URL für den Browser aber nicht falsch. Also:
    # nicht prüfbar ≠ kaputt.
    try:
        guard_egress_url(url, "draw.io-URL")
    except HTTPException as exc:
        return {"ok": False, "checked": False, "status": None, "looks_like_drawio": False,
                "hint": f"Vom Server aus nicht prüfbar ({exc.detail}). Für den Browser kann "
                        "die URL trotzdem stimmen — mit 'Im Browser öffnen' testen oder "
                        "LAN-IP/FQDN statt Kurzname eintragen."}
    try:
        async with httpx.AsyncClient(timeout=10, verify=False, follow_redirects=True) as client:
            r = await client.get(url + "/")
    except Exception as exc:
        return {"ok": False, "checked": True, "status": None, "looks_like_drawio": False,
                "hint": f"Vom Server aus nicht erreichbar: {exc}. Im Browser prüfen."}
    looks = "draw.io" in r.text or "diagrams.net" in r.text or "mxgraph" in r.text.lower()
    return {"ok": r.status_code < 400, "checked": True, "status": r.status_code,
            "looks_like_drawio": looks, "hint": None}


@router.post("")
async def build(body: DiagramRequest, request: Request,
                _user: dict = Depends(get_current_user)) -> dict:
    state = request.app.state
    inv, prefixes = state.inventory, state.prefixes
    try:
        targets = diagram_model.scope_vdoms(inv, body.scope, body.device, body.vdom)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc

    warnings: list[str] = []
    itop_cfg = await read_config("itop")
    itop_subnets: list[dict] = []
    itop_hosts: list[dict] = []
    itop_addresses: dict[str, dict] = {}
    if itop_cfg.get("base_url") and body.hosts != "none":
        itop = state.resolver.itop
        try:
            ipam = await itop.ipam(itop_cfg)
            itop_subnets = ipam["subnets"]
            itop_hosts = await itop.hosts(itop_cfg)
            # Adressobjekte nur für die Netze im Scope — nicht den ganzen Bestand.
            nets = [n for d, v in targets for n, _ in inv.connected_networks(d, v)]
            ids = [s["id"] for s in itop_subnets
                   if any(ipaddress.IPv4Network(s["cidr"]).overlaps(n) for n in nets)]
            itop_addresses = await itop.addresses(itop_cfg, ids)
        except Exception as exc:
            warnings.append(f"iTop nicht vollständig abrufbar: {exc}")
    elif itop_cfg.get("base_url"):
        try:
            itop_subnets = (await state.resolver.itop.ipam(itop_cfg))["subnets"]
        except Exception as exc:
            warnings.append(f"iTop-Subnetze nicht abrufbar: {exc}")

    librenms_cfg = await read_config("librenms")
    librenms = state.locate.librenms if librenms_cfg.get("base_url") else None
    librenms_devices: dict[str, dict] = {}
    if librenms is not None and body.hosts != "none":
        try:
            librenms_devices = await librenms.device_index(librenms_cfg)
        except Exception as exc:
            warnings.append(f"LibreNMS-Geräte nicht abrufbar: {exc}")

    async def arp(cidr: str) -> list[dict]:
        return await state.arp_store.in_network(cidr)

    try:
        mdl = await diagram_model.build(
            inv, prefixes, scope=body.scope, device=body.device, vdom=body.vdom,
            hosts=body.hosts, itop_subnets=itop_subnets, itop_hosts=itop_hosts,
            itop_addresses=itop_addresses, arp=arp, librenms=librenms,
            librenms_cfg=librenms_cfg if librenms else None, librenms_devices=librenms_devices,
        )
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    if mdl["stats"]["hosts_reduced"]:
        warnings.append(
            f"{mdl['stats']['hosts_found']} Hosts gefunden — mehr als {diagram_model.MAX_HOSTS}. "
            "Gezeichnet sind nur Netzwerkgeräte; für alle Hosts 'alle Hosts' wählen oder "
            "den Scope auf einen VDOM verkleinern.")
    xml = drawio.render(mdl)
    stem = re.sub(r"[^A-Za-z0-9_.-]+", "_", f"{body.device}" + (f"_{body.vdom}" if body.vdom else ""))
    return {"filename": f"A38_Netzplan_{stem}.drawio", "xml": xml,
            "stats": mdl["stats"], "hosts_mode": mdl["hosts_mode"], "warnings": warnings}
