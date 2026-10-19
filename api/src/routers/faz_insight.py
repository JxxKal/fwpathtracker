"""Tracker-Analysen aus dem FortiAnalyzer und dem Bestand.

- POST /api/faz/flow-history  „Gestern ging es noch": ein Flow über die Zeit
- GET  /api/faz/blocked       Was wird bei Host X gerade geblockt?
- GET  /api/reconcile         Bestandsabgleich iTop ↔ ARP ↔ FAZ ↔ DNS

Alles rein lesend. Die Logsuche kostet den FAZ spürbar Arbeit, deshalb sind
Zeitfenster und Zeilenzahl nach oben begrenzt.
"""
from __future__ import annotations

import asyncio
import ipaddress
import logging

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field

from deps import get_current_user, resolve_query
from faz import logs as faz_logs
from faz.client import LOG_LIMIT, FazError, FazNotConfigured, in_network
from inventory.store import parse_subnet
from ipam.reconcile import reconcile
from resolver.dns_cache import build_reverse
from routers.config import read_config

log = logging.getLogger("routers.faz_insight")
router = APIRouter(prefix="/api", tags=["faz-insight"])

MAX_FLOW_HOURS = 24 * 31
MAX_BLOCKED_HOURS = 24 * 7
DNS_BUDGET = 256
DNS_CONCURRENCY = 16
# Kleiner als /16 wird es zur Inventur des ganzen Standorts — dafür ist die
# Tabelle nicht gebaut, und iTop/DNS würden minutenlang gefragt.
MIN_PREFIXLEN = 16


async def _faz_cfg(state) -> dict:
    cfg = await read_config("faz")
    if not state.faz.configured(cfg):
        raise HTTPException(400, "FortiAnalyzer ist nicht konfiguriert — bitte unter "
                                 "Einstellungen → FortiAnalyzer eintragen.")
    return cfg


def _policy_namer(inv):
    """(Gerät, VDOM, Policy-ID) → Name aus dem FMG-Cache. Der FAZ nennt das
    Gerät beim Hostnamen; der FMG meist genauso — sonst ohne Rücksicht auf
    Groß-/Kleinschreibung. Ohne VDOM wird nur ein eindeutiger Treffer genommen."""
    by_lower = {d.lower(): d for d in inv.devices}

    def name(dev: str | None, vd: str | None, pid: int | None) -> str | None:
        if pid is None or pid == faz_logs.IMPLICIT_DENY:
            return None
        if pid >= 1 << 30:
            hit = inv.global_policy(pid)
            return (hit or {}).get("name") or None
        d = by_lower.get(str(dev or "").lower())
        if d is None:
            return None
        vdoms = [vd] if vd else list(inv.devices[d].get("vdoms") or ["root"])
        names = {p.get("name") for v in vdoms for p in inv.policies.get((d, v), [])
                 if str(p.get("policyid")) == str(pid)}
        names.discard(None)
        return names.pop() if len(names) == 1 else None
    return name


async def _search(state, cfg: dict, *, filter: str, hours: float) -> dict:
    start, end = faz_logs.time_range(hours, faz_logs.tz_of(cfg))
    try:
        return await state.faz.logsearch(cfg, logtype="traffic", filter=filter,
                                         start=start, end=end)
    except FazNotConfigured as exc:
        raise HTTPException(400, str(exc)) from exc
    except FazError as exc:
        raise HTTPException(502, f"{exc} — Darf der API-Benutzer Log View lesen?") from exc
    except Exception as exc:
        raise HTTPException(502, f"FortiAnalyzer nicht erreichbar: {exc}") from exc


class FlowHistoryRequest(BaseModel):
    src: str = Field(min_length=1, max_length=255)
    dst: str = Field(min_length=1, max_length=255)
    protocol: str | None = Field(default=None, pattern="^(?i)(tcp|udp|icmp)$")
    dst_port: int | None = Field(default=None, ge=1, le=65535)
    hours: float = Field(default=48, gt=0, le=MAX_FLOW_HOURS)


@router.post("/faz/flow-history")
async def flow_history(body: FlowHistoryRequest, request: Request,
                       _user: dict = Depends(get_current_user)) -> dict:
    state = request.app.state
    cfg = await _faz_cfg(state)
    src, src_names = await resolve_query(request, body.src)
    dst, dst_names = await resolve_query(request, body.dst)
    flt = faz_logs.flow_filter(src, dst, body.protocol, body.dst_port)
    res = await _search(state, cfg, filter=flt, hours=body.hours)
    out = faz_logs.flow_history(
        res["logs"], hours=body.hours, tz=faz_logs.tz_of(cfg),
        policy_name=_policy_namer(state.inventory), complete=res["complete"],
        limit_hit=len(res["logs"]) >= LOG_LIMIT)
    return dict(out, src=src, dst=dst, src_names=src_names[:3], dst_names=dst_names[:3],
                protocol=(body.protocol or "").lower() or None, dst_port=body.dst_port,
                hours=body.hours, filter=flt, total=res["total"])


async def _names(state, ips: list[str]) -> dict[str, str | None]:
    """IP → Name: iTop-CI, sonst FMG-Objekt, sonst DNS (gecacht, begrenzt)."""
    from resolver import fmg_source

    out: dict[str, str | None] = {}
    itop_cfg = await read_config("itop")
    try:
        by_ip = {h["ip"]: h["name"] for h in await state.resolver.itop.hosts(itop_cfg)}
    except Exception:
        by_ip = {}
    todo = []
    for ip in ips:
        name = by_ip.get(ip) or (fmg_source.resolve_ip(state.inventory, ip) or {}).get("name")
        if name:
            out[ip] = name
        else:
            todo.append(ip)
    out.update(await _dns(state, todo))
    return out


async def _dns(state, ips: list[str]) -> dict[str, str | None]:
    reverse = await build_reverse(state, await read_config("dns"))
    if reverse is None or not ips:
        return {}
    ips = ips[:DNS_BUDGET]
    await reverse.prime(ips)
    sem = asyncio.Semaphore(DNS_CONCURRENCY)

    async def one(ip: str) -> tuple[str, str | None]:
        async with sem:
            try:
                return ip, await reverse(ip)
            except Exception:
                return ip, None

    out = dict(await asyncio.gather(*(one(ip) for ip in ips)))
    await reverse.flush()
    return out


@router.get("/faz/blocked")
async def blocked(request: Request,
                  q: str = Query(min_length=2, max_length=128,
                                 description="IP-Adresse oder auflösbarer Name"),
                  hours: float = Query(default=1, gt=0, le=MAX_BLOCKED_HOURS),
                  direction: str = Query(default="both", pattern="^(src|dst|both)$"),
                  _user: dict = Depends(get_current_user)) -> dict:
    state = request.app.state
    cfg = await _faz_cfg(state)
    ip, names = await resolve_query(request, q)
    dirs = ["src", "dst"] if direction == "both" else [direction]
    results = await asyncio.gather(*(
        _search(state, cfg, filter=faz_logs.deny_filter(ip, d), hours=hours) for d in dirs))
    namer = _policy_namer(state.inventory)
    tz = faz_logs.tz_of(cfg)
    rows = [row for d, res in zip(dirs, results)
            for row in faz_logs.blocked(res["logs"], direction=d, tz=tz, policy_name=namer)]
    rows.sort(key=lambda r: -r["count"])
    peers = sorted({r["peer"] for r in rows if r["peer"]})
    peer_names = await _names(state, peers)
    for r in rows:
        r["peer_name"] = peer_names.get(r["peer"])
    lines = sum(len(res["logs"]) for res in results)
    return {
        "ip": ip, "names": names[:3], "hours": hours, "direction": direction,
        "rows": rows, "lines": lines,
        "implicit": sum(r["count"] for r in rows if r["policyid"] == faz_logs.IMPLICIT_DENY),
        "complete": all(res["complete"] for res in results),
        "limit_hit": any(len(res["logs"]) >= LOG_LIMIT for res in results),
    }


async def _resolve_network(request: Request, q: str) -> tuple[str, str]:
    """CIDR direkt; eine IP oder ein Name → das Netz, in dem sie liegt
    (iTop-Subnetz, sonst connected Netz aus dem FMG). Rückgabe (cidr, Herkunft)."""
    state = request.app.state
    q = q.strip()
    if "/" in q:
        try:
            return str(ipaddress.IPv4Network(q, strict=False)), "eingegeben"
        except ValueError as exc:
            raise HTTPException(422, f"Kein gültiges Netz: {q}") from exc
    ip, _ = await resolve_query(request, q)
    addr = ipaddress.IPv4Address(ip)
    try:
        subnets = (await state.resolver.itop.ipam(await read_config("itop")))["subnets"]
    except Exception:
        subnets = []
    hits = [ipaddress.IPv4Network(s["cidr"]) for s in subnets
            if addr in ipaddress.IPv4Network(s["cidr"])]
    if hits:
        return str(max(hits, key=lambda n: n.prefixlen)), "iTop-Subnetz"
    entry = state.prefixes.lookup_owner(addr)
    if entry is not None and entry.network.prefixlen >= MIN_PREFIXLEN:
        return str(entry.network), f"connected an {entry.device}/{entry.vdom}"
    raise HTTPException(422, f"Zu {ip} ist kein Netz bekannt — bitte als CIDR eingeben.")


def _firewall_ips(inv, net: ipaddress.IPv4Network) -> dict[str, str]:
    return {str(intf["ip"].ip): f"{dev}/{intf['name']}"
            for dev, table in inv.interfaces.items() for intf in table.values()
            if intf.get("ip") is not None and intf["ip"].ip in net}


def _fmg_names(inv, net: ipaddress.IPv4Network) -> dict[str, str]:
    out: dict[str, str] = {}
    for objs in inv.addresses.values():
        for oname, obj in objs.items():
            sub = parse_subnet(obj.get("subnet"))
            if sub and sub.prefixlen == 32 and sub.network_address in net:
                out.setdefault(str(sub.network_address), oname)
    return out


@router.get("/reconcile")
async def reconcile_network(
    request: Request,
    q: str = Query(min_length=2, max_length=128, description="Netz (CIDR), IP oder Name"),
    active_days: int = Query(default=7, ge=1, le=90),
    stale_days: int = Query(default=30, ge=1, le=365),
    dns: bool = True,
    _user: dict = Depends(get_current_user),
) -> dict:
    state = request.app.state
    cidr, origin = await _resolve_network(request, q)
    net = ipaddress.IPv4Network(cidr)
    if net.prefixlen < MIN_PREFIXLEN:
        raise HTTPException(422, f"Netz zu groß (/{net.prefixlen}) — höchstens "
                                 f"/{MIN_PREFIXLEN}.")
    warnings: list[str] = []

    itop_cfg = await read_config("itop")
    itop_hosts: list[dict] = []
    itop_addresses: dict[str, dict] = {}
    if itop_cfg.get("base_url"):
        itop = state.resolver.itop
        try:
            itop_hosts = await itop.hosts(itop_cfg)
            subnets = (await itop.ipam(itop_cfg))["subnets"]
            ids = [s["id"] for s in subnets
                   if ipaddress.IPv4Network(s["cidr"]).overlaps(net)]
            itop_addresses = await itop.addresses(itop_cfg, ids)
        except Exception as exc:
            warnings.append(f"iTop nicht vollständig lesbar: {exc}")
    else:
        warnings.append("iTop ist nicht konfiguriert — ohne Soll ist der Abgleich nur "
                        "eine Liste der gesehenen Hosts.")

    try:
        arp_rows = await state.arp_store.bindings_in_network(cidr)
    except Exception as exc:
        arp_rows = []
        warnings.append(f"ARP-Historie nicht lesbar: {exc}")

    faz_hosts = None
    faz_cfg = await read_config("faz")
    if state.faz.configured(faz_cfg):
        try:
            faz_hosts = in_network(await state.faz.endpoints(faz_cfg), cidr)
        except Exception as exc:
            warnings.append(f"FortiAnalyzer nicht abrufbar: {exc}")

    librenms_devices: dict[str, dict] = {}
    librenms_cfg = await read_config("librenms")
    if librenms_cfg.get("base_url"):
        try:
            librenms_devices = await state.locate.librenms.device_index(librenms_cfg)
        except Exception as exc:
            warnings.append(f"LibreNMS nicht abrufbar: {exc}")

    known = sorted({h["ip"] for h in itop_hosts if _in(net, h.get("ip"))}
                   | {ip for ip in itop_addresses if _in(net, ip)}
                   | {b["ip"] for b in arp_rows}
                   | {f["ip"] for f in faz_hosts or []})
    dns_names = await _dns(state, known) if dns else {}
    if dns and len(known) > DNS_BUDGET:
        warnings.append(f"DNS nur für die ersten {DNS_BUDGET} von {len(known)} Adressen gefragt.")

    out = reconcile(cidr, itop_hosts=itop_hosts, itop_addresses=itop_addresses,
                    arp_rows=arp_rows, faz_hosts=faz_hosts, dns_names=dns_names,
                    librenms_devices=librenms_devices,
                    fmg_names=_fmg_names(state.inventory, net),
                    firewall_ips=_firewall_ips(state.inventory, net),
                    active_days=active_days, stale_days=stale_days)
    if not out["observed"]:
        warnings.append("In diesem Netz liegt keine ARP-Beobachtung vor — „verwaist im iTop“ "
                        "wird deshalb nicht gemeldet.")
    return dict(out, origin=origin, warnings=warnings, dns=bool(dns_names))


def _in(net: ipaddress.IPv4Network, ip) -> bool:
    try:
        return ipaddress.IPv4Address(str(ip).strip()) in net
    except ValueError:
        return False
