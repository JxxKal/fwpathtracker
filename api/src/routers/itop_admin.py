"""iTop-Verbindungstest + IPAM-Werkzeuge (Free-Subnet-Finder, Free-IP-Finder)."""
from __future__ import annotations

import ipaddress
import logging

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from deps import get_current_user, require_admin
from ipam import free_ip, ping as ping_probe, tree as ipam_tree
from locate import arp_fortigate
from resolver import dns_source
from routers.config import read_config

log = logging.getLogger("routers.itop")

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


@router.get("/ipam-tree")
async def ipam_tree_view(request: Request, _user: dict = Depends(get_current_user)) -> dict:
    """Bereichsbaum für den Free-IP-Finder: Standorte → iTop-Subnetze → Ranges."""
    cfg = await read_config("itop")
    if not cfg.get("base_url"):
        raise HTTPException(400, "iTop nicht konfiguriert – bitte zuerst speichern.")
    sites = (await site_supernets(_user))["sites"]
    try:
        ipam = await request.app.state.resolver.itop.ipam(cfg)
    except Exception as exc:
        raise HTTPException(502, f"iTop-Subnetze konnten nicht geladen werden: {exc}") from exc
    return {
        "nodes": ipam_tree.build_tree(sites, ipam["subnets"], ipam["ranges"]),
        "subnets": len(ipam["subnets"]), "ranges": len(ipam["ranges"]),
    }


class FreeIpRequest(BaseModel):
    cidr: str = Field(min_length=1, max_length=64)
    start: str | None = Field(default=None, max_length=15)
    end: str | None = Field(default=None, max_length=15)
    want: int = Field(default=10, ge=1, le=free_ip.MAX_WANT)


def _fw_ips(inv, net: ipaddress.IPv4Network) -> dict[str, str]:
    """Firewall-Interface-Adressen (inkl. Secondary-IPs) im Netz — die stehen in
    keinem IPAM als Host, sind aber garantiert nicht frei."""
    out: dict[str, str] = {}
    for dev, table in (getattr(inv, "interfaces", None) or {}).items():
        for intf in table.values():
            addrs = [intf["ip"]] if intf.get("ip") is not None else []
            addrs += intf.get("secondary_ips") or []
            for a in addrs:
                if a.ip in net:
                    out[str(a.ip)] = f"{dev}/{intf.get('vdom')}/{intf.get('name')}"
    return out


async def _prime_arp(state, net: ipaddress.IPv4Network, fmg_cfg: dict,
                     warnings: list[str]) -> None:
    """Live-ARP des zuständigen VDOMs einmal holen und in die Historie schreiben —
    ein Aufruf für das ganze Netz. Danach sieht der Historien-Lookup je Adresse
    auch, wer in den letzten Minuten gesprochen hat, ohne ICMP zu beantworten."""
    if not fmg_cfg.get("host") and not fmg_cfg.get("fixture_mode"):
        return
    probe_ip = str(next(net.hosts(), net.network_address))
    seen: list[dict] = []
    try:
        await arp_fortigate.resolve(probe_ip, state.prefixes, fmg_cfg, state.cfg,
                                    warnings, seen=seen)
    except Exception as exc:
        warnings.append(f"Live-ARP nicht abrufbar: {exc}")
    # „steht nicht in der ARP-Tabelle" ist hier keine Warnung — wir wollten nur die Tabelle.
    warnings[:] = [w for w in warnings if "steht nicht in der ARP-Tabelle" not in w]
    if seen:
        try:
            await state.arp_store.record(seen)
        except Exception as exc:
            log.warning("ARP-Historie nicht schreibbar: %s", exc)


@router.post("/free-ips")
async def free_ips(body: FreeIpRequest, request: Request,
                   _user: dict = Depends(get_current_user)) -> dict:
    """Freie Host-Adressen in einem Netz/Bereich: iTop-Bestand (Adressobjekte
    allocated/reserved + Management-IPs der CIs), Firewall-Interfaces und
    DHCP-Ranges scheiden aus; der Rest wird per Ping, PTR und ARP-Historie geprüft."""
    cfg = await read_config("itop")
    if not cfg.get("base_url"):
        raise HTTPException(400, "iTop nicht konfiguriert – bitte zuerst speichern.")
    try:
        net = ipaddress.IPv4Network(body.cidr.strip(), strict=False)
    except ValueError as exc:
        raise HTTPException(422, f"Ungültiges Netz (CIDR erwartet): {body.cidr}") from exc
    try:
        list(free_ip._range_bounds(net, body.start, body.end))
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    if net.prefixlen < 8:
        raise HTTPException(422, "Netz zu groß — bitte ein Subnetz oder einen Bereich wählen.")

    state = request.app.state
    itop = state.resolver.itop
    warnings: list[str] = []
    try:
        ipam = await itop.ipam(cfg)
        overlapping = [s for s in ipam["subnets"]
                       if ipaddress.IPv4Network(s["cidr"]).overlaps(net)]
        addresses = await itop.addresses(cfg, [s["id"] for s in overlapping])
        ci_hosts = {h["ip"]: h["name"] for h in await itop.hosts(cfg)}
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(502, f"iTop-Bestand konnte nicht geladen werden: {exc}") from exc
    if not overlapping:
        warnings.append(f"{net} ist in iTop nicht als Subnetz geführt — dort kann es "
                        "keine Adressobjekte geben; geprüft wird trotzdem.")

    ids = {s["id"] for s in overlapping}
    dhcp = [(ipaddress.IPv4Address(r["first"]), ipaddress.IPv4Address(r["last"]), r["name"])
            for r in ipam["ranges"] if r["subnet_id"] in ids and r["dhcp"]]
    # Gateway: exakt passendes iTop-Subnetz, sonst das kleinste umschließende.
    gateway = None
    for s in sorted(overlapping, key=lambda x: -ipaddress.IPv4Network(x["cidr"]).prefixlen):
        if s.get("gateway") and net.subnet_of(ipaddress.IPv4Network(s["cidr"])):
            gateway = s["gateway"]
            break

    dns_cfg = await read_config("dns")
    await _prime_arp(state, net, await read_config("fmg"), warnings)
    if not ping_probe.available():
        warnings.append("Ping ist auf dem Server nicht verfügbar — Erreichbarkeit nicht prüfbar.")

    async def dns(ip: str) -> str | None:
        try:
            hit = await dns_source.resolve_ip(dns_cfg, ip, timeout_s=1.5)
        except Exception:
            return None
        return hit["name"] if hit else None

    async def arp(ip: str) -> dict | None:
        try:
            rows = await state.arp_store.by_ip(ip, limit=1)
        except Exception:
            return None
        if not rows:
            return None
        r = rows[0]
        return {"mac": r["mac"], "device": r["device"], "vdom": r["vdom"],
                "last_seen": r["last_seen"], "age_s": r["age_s"]}

    found = await free_ip.find_free(
        net, itop_addresses=addresses, ci_hosts=ci_hosts, fw_ips=_fw_ips(state.inventory, net),
        dhcp_ranges=dhcp, gateway=gateway, ping=ping_probe.ping, dns=dns, arp=arp,
        want=body.want, start=body.start, end=body.end,
    )
    domains = [d for d in (dns_cfg.get("search_domains") or []) if d]
    return {
        "cidr": str(net), "start": body.start, "end": body.end, "want": body.want,
        "gateway": gateway, "itop_subnets": [s["cidr"] for s in overlapping],
        "dns_domain": domains[0] if domains else None,
        "warnings": warnings, **found,
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
