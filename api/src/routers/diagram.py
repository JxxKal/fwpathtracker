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
from diagram import drawio, model as diagram_model, titleblock
from netguard import guard_egress_url
from routers.config import read_config

log = logging.getLogger("routers.diagram")
router = APIRouter(prefix="/api/diagram", tags=["diagram"])


class DiagramRequest(BaseModel):
    scope: str = Field(pattern="^(vdom|firewall|site|global)$")
    device: str | None = Field(default=None, max_length=128)
    vdom: str | None = Field(default=None, max_length=64)
    site: str | None = Field(default=None, max_length=128)
    hosts: str = Field(default="auto", pattern="^(auto|all|netdev|none)$")
    expand_hosts: bool = False


async def _sites() -> list[dict]:
    """Standort-Supernetze aus den Einstellungen — dieselbe Quelle wie der
    Free-Subnet-Finder, damit ein Standort überall dasselbe bedeutet."""
    from routers.itop_admin import DEFAULT_SITE_SUPERNETS, _normalize_sites
    cfg = await read_config("site_supernets")
    sites = cfg.get("sites")
    if isinstance(sites, list) and sites:
        return _normalize_sites(sites)
    return DEFAULT_SITE_SUPERNETS


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
    state = request.app.state
    inv, prefixes = state.inventory, state.prefixes
    sites = await _sites()
    supernets = diagram_model._supernets(sites)
    devices = []
    for d, info in sorted(inv.devices.items()):
        vdoms = list(info["vdoms"] or ["root"])
        names = [diagram_model.site_of(inv, prefixes, d, v, supernets) for v in vdoms]
        devices.append({"device": d, "adom": info["adom"], "vdoms": vdoms,
                        "site": next((n for n in names if n), None)})
    # Nur Standorte anbieten, hinter denen auch ein VDOM steht — eine leere
    # Auswahl, die dann 422 wirft, ist keine Auswahl.
    used = {d["site"] for d in devices if d["site"]}
    site_list = [{"name": s["name"], "cidr": s["cidr"],
                  "devices": sorted(d["device"] for d in devices if d["site"] == s["name"])}
                 for s in sites if s["name"] in used]
    return {"devices": devices, "sites": site_list, "max_hosts": diagram_model.MAX_HOSTS,
            "drawio_url": await drawio_url()}


async def _title_block(mdl: dict, stem: str, user: dict) -> dict | None:
    """Schriftfeld füllen — Titel, Scope-Zahlen, Datum und Autor kennt A38
    selbst; Firma, Vermerk, Gruppe und Logo sind Stammdaten."""
    cfg = await read_config("titleblock")
    if cfg.get("enabled") is False:
        return None
    st, sc = mdl["stats"], mdl["scope"]

    def n(count: int, one: str, many: str) -> str:
        return f"{count} {one if count == 1 else many}"

    parts = [f"Scope {_SCOPE_LABEL.get(sc['scope'], sc['scope'])}",
             n(st["devices"], "Firewall", "Firewalls"), n(st["vdoms"], "VDOM", "VDOMs"),
             n(st["networks"], "Netz", "Netze")]
    if mdl["hosts_mode"] != "none":
        parts.append(n(st["hosts_shown"], "Host", "Hosts"))
    prefix = (cfg.get("drawing_no_prefix") or "A38").strip()
    return titleblock.info_from(
        cfg, title=sc.get("title") or "Netzplan", subtitle=" · ".join(parts),
        author=str(user.get("username") or ""),
        drawing_no=f"{prefix}-{stem.upper()}",
        note=f"Erzeugt von A38 aus FortiManager, iTop und LibreNMS",
    )


_SCOPE_LABEL = {"vdom": "VDOM", "firewall": "Firewall", "site": "Standort",
                "global": "gesamt"}


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
                user: dict = Depends(get_current_user)) -> dict:
    state = request.app.state
    inv, prefixes = state.inventory, state.prefixes
    sites = await _sites()
    try:
        targets = diagram_model.scope_vdoms(inv, body.scope, body.device, body.vdom,
                                            body.site, prefixes, sites)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc

    warnings: list[str] = []
    itop_cfg = await read_config("itop")
    itop_subnets: list[dict] = []
    itop_hosts: list[dict] = []
    itop_addresses: dict[str, dict] = {}
    wants_hosts = body.hosts != "none" and body.scope != "global"
    if itop_cfg.get("base_url") and wants_hosts:
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
    if librenms is not None and wants_hosts:
        try:
            librenms_devices = await librenms.device_index(librenms_cfg)
        except Exception as exc:
            warnings.append(f"LibreNMS-Geräte nicht abrufbar: {exc}")

    async def arp(cidr: str) -> list[dict]:
        return await state.arp_store.in_network(cidr)

    try:
        mdl = await diagram_model.build(
            inv, prefixes, scope=body.scope, device=body.device, vdom=body.vdom,
            site=body.site, hosts=body.hosts, sites=sites, itop_subnets=itop_subnets,
            itop_hosts=itop_hosts, itop_addresses=itop_addresses, arp=arp, librenms=librenms,
            librenms_cfg=librenms_cfg if librenms else None, librenms_devices=librenms_devices,
        )
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    if mdl["stats"]["hosts_reduced"]:
        warnings.append(
            f"{mdl['stats']['hosts_found']} Hosts gefunden — mehr als {diagram_model.MAX_HOSTS}. "
            "Gezeichnet sind nur Netzwerkgeräte; für alle Hosts 'alle Hosts' wählen oder "
            "den Scope auf einen VDOM verkleinern.")
    if body.scope == "global":
        warnings.append("Gesamtplan: gezeichnet werden die Kopplungen der Firewalls, "
                        "nicht ihre Netze und Hosts — dafür einen Standort oder eine "
                        "Firewall wählen.")
    raw = {"global": "gesamt", "site": body.site or "", "firewall": body.device or "",
           "vdom": f"{body.device}_{body.vdom}"}[body.scope]
    stem = re.sub(r"[^A-Za-z0-9_.-]+", "_", raw).strip("_") or "netzplan"
    xml = drawio.render(mdl, collapse=not body.expand_hosts,
                        title_block=await _title_block(mdl, stem, user))
    return {"filename": f"A38_Netzplan_{stem}.drawio", "xml": xml,
            "stats": mdl["stats"], "hosts_mode": mdl["hosts_mode"], "warnings": warnings}
