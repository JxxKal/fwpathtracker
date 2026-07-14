"""Trace-API: Pfad-Trace ausführen + Verlauf."""
from __future__ import annotations

import time

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from database import get_pool
from deps import get_current_user
from engine.path import TraceError, run_trace
from engine.verdict import Endpoint, TraceResult, aggregate_verdict
from fmg.client import FmgError
from fmg.factory import build_fmg_client
from resolver.chain import is_ipv6
from routers.config import read_config
from suggest.builder import build_suggestion

router = APIRouter(prefix="/api", tags=["trace"])


def _fmg_policy_url(fmg_cfg: dict, adom: str | None, pkg: str | None) -> str | None:
    """Best-effort Deep-Link ins FortiManager-Policy-Package (Stelle zum Anlegen).
    Basis aus fmg.gui_url bzw. https://<host>; Template über fmg.policy_url_template
    anpassbar (FMG-Version-abhängig). {base}/{adom}/{pkg} als Platzhalter.
    """
    host = (fmg_cfg.get("host") or "").strip()
    base = (fmg_cfg.get("gui_url") or (f"https://{host}" if host else "")).strip()
    if not base or not pkg or not adom:
        return None
    tmpl = fmg_cfg.get("policy_url_template") or \
        "{base}/p/app/#!/pm/config/adom/{adom}/pkg/{pkg}/firewall/policy"
    try:
        return tmpl.format(base=base.rstrip("/"), adom=adom, pkg=pkg)
    except (KeyError, IndexError, ValueError):
        return base.rstrip("/")


class TraceRequest(BaseModel):
    src: str = Field(min_length=1, max_length=255)
    dst: str = Field(min_length=1, max_length=255)
    protocol: str = Field(pattern="^(?i)(tcp|udp|icmp)$")
    dst_port: int | None = Field(default=None, ge=1, le=65535)
    src_port: int | None = Field(default=None, ge=1, le=65535)
    icmp_type: int | None = Field(default=None, ge=0, le=255)
    icmp_code: int | None = Field(default=None, ge=0, le=255)


async def _execute_trace(state, body: "TraceRequest", *, fmg_cfg: dict,
                         tracker_cfg: dict, itop_cfg: dict, dns_cfg: dict,
                         client) -> TraceResult:
    """Führt einen Trace aus und liefert das TraceResult (ohne History-Persistenz).
    Wiederverwendbar für Einzel-Trace und Batch-Check. Der Client wird NICHT hier
    geschlossen (Aufrufer verwaltet ihn — beim Batch einer für alle Checks)."""
    started = time.monotonic()

    for value in (body.src, body.dst):
        if is_ipv6(value):
            raise HTTPException(400, "IPv6 wird in V1 nicht unterstützt.")
    proto = body.protocol.lower()
    if proto in ("tcp", "udp") and body.dst_port is None:
        raise HTTPException(400, f"Für {proto.upper()} ist ein Ziel-Port erforderlich.")

    inv = state.inventory
    prefixes = state.prefixes
    if not inv.devices:
        raise HTTPException(409, "Kein FMG-Inventar vorhanden — zuerst Sync ausführen.")

    try:
        src_ep = await state.resolver.resolve_endpoint(body.src, inv, itop_cfg, dns_cfg)
        dst_ep = await state.resolver.resolve_endpoint(body.dst, inv, itop_cfg, dns_cfg)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc

    try:
        hops = await run_trace(
            src_ip=src_ep["ip"], dst_ip=dst_ep["ip"], protocol=proto,
            dst_port=body.dst_port, src_port=body.src_port,
            icmp_type=body.icmp_type, icmp_code=body.icmp_code,
            inv=inv, prefixes=prefixes, client=client,
            overlay_pattern=tracker_cfg.get("overlay_pattern", "(?i)(vpn|ovl|sdwan|tun|ipsec)"),
            router_vdom_pattern=tracker_cfg.get("router_vdom_pattern", "(?i)(router|wan.?edge)"),
            max_hops=int(tracker_cfg.get("max_hops", 8)),
        )
    except TraceError as exc:
        raise HTTPException(422, str(exc)) from exc
    except FmgError as exc:
        raise HTTPException(502, f"FMG-Fehler: {exc}") from exc

    warnings: list[str] = []
    # VIP/NAT-Erkennung: Ziel ist externe VIP-Adresse → Re-Trace-Hinweis
    vip = None
    for adom in inv.adoms:
        vip_obj = inv.vip_for(adom, dst_ep["ip"])
        if vip_obj:
            mapped = vip_obj.get("mappedip")
            mapped = mapped[0] if isinstance(mapped, list) and mapped else mapped
            vip = {"name": vip_obj.get("name"), "extip": vip_obj.get("extip"),
                   "mappedip": str(mapped) if mapped else None}
            warnings.append(
                f"Ziel {dst_ep['ip']} ist eine VIP ('{vip['name']}'). FortiOS macht "
                "den VIP-Lookup vor dem Policy-Lookup — Trace mit der mapped IP "
                f"({vip['mappedip']}) wiederholen für den Pfad hinter dem NAT."
            )
            break

    # Regel-Vorschläge für JEDEN blockierenden Hop — um den Flow durchgängig zu
    # öffnen, braucht es eine Regel auf jeder blockenden Firewall, nicht nur der
    # ersten. Nachgelagerte Hops werden im Frontend als "nachgelagert" markiert,
    # der Vorschlag bleibt aber verfügbar.
    for hop in hops:
        if hop.verdict == "DENY":
            hop.suggestion = build_suggestion(
                inv, hop, src_ip=src_ep["ip"], dst_ip=dst_ep["ip"],
                protocol=proto, dst_port=body.dst_port,
                src_names=src_ep["names"], dst_names=dst_ep["names"],
            )
            if hop.suggestion:
                hop.suggestion["fmg_url"] = _fmg_policy_url(
                    fmg_cfg, hop.suggestion["adom"], hop.suggestion.get("package"))

    result = TraceResult(
        verdict=aggregate_verdict(hops),
        src=Endpoint(**src_ep), dst=Endpoint(**dst_ep),
        protocol=proto, dst_port=body.dst_port, src_port=body.src_port,
        icmp_type=body.icmp_type, icmp_code=body.icmp_code,
        hops=hops, warnings=warnings, vip=vip,
        duration_ms=int((time.monotonic() - started) * 1000),
        inventory_synced_at=inv.synced_at,
    )
    return result


@router.post("/trace", response_model=TraceResult)
async def trace(body: TraceRequest, request: Request,
                user: dict = Depends(get_current_user)) -> TraceResult:
    state = request.app.state
    fmg_cfg = await read_config("fmg")
    tracker_cfg = await read_config("tracker")
    itop_cfg = await read_config("itop")
    dns_cfg = await read_config("dns")

    client = build_fmg_client(fmg_cfg, state.cfg)
    try:
        result = await _execute_trace(
            state, body, fmg_cfg=fmg_cfg, tracker_cfg=tracker_cfg,
            itop_cfg=itop_cfg, dns_cfg=dns_cfg, client=client)
    finally:
        await client.close()

    pool = get_pool()
    async with pool.acquire() as conn:
        await conn.execute(
            """
            INSERT INTO traces (username, request, result, verdict, duration_ms)
            VALUES ($1, $2, $3, $4, $5)
            """,
            user.get("username", "?"), body.model_dump(), result.model_dump(),
            result.verdict, result.duration_ms,
        )
    return result


@router.get("/traces")
async def list_traces(request: Request, limit: int = 50,
                      _user: dict = Depends(get_current_user)) -> list[dict]:
    pool = get_pool()
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            """
            SELECT id, created_at, username, request, verdict, duration_ms
            FROM traces ORDER BY created_at DESC LIMIT $1
            """,
            min(limit, 200),
        )
    return [dict(r) for r in rows]


@router.get("/traces/{trace_id}")
async def get_trace(trace_id: int, request: Request,
                    _user: dict = Depends(get_current_user)) -> dict:
    pool = get_pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow("SELECT * FROM traces WHERE id = $1", trace_id)
    if not row:
        raise HTTPException(404, "Trace nicht gefunden")
    return dict(row)
