"""Check-Gruppen: Flow-Sets speichern und als Batch prüfen (Soll- vs. Ist-Verdict).

Anwendungsfall: ein ganzes Regel-Set zu testender Flows anlegen, laufen lassen,
im FortiManager umsetzen und erneut prüfen, ob es jetzt zieht (Regressions-Check).
Speicherung im system_config-Key 'checks'; Ausführung teilt sich die Trace-Engine.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from deps import get_current_user, require_admin
from fmg.factory import build_fmg_client
from routers.config import read_config, write_config
from routers.trace import TraceRequest, _execute_trace

router = APIRouter(prefix="/api/checks", tags=["checks"])


class CheckItem(BaseModel):
    id: str | None = None
    label: str | None = None
    src: str = Field(min_length=1, max_length=255)
    dst: str = Field(min_length=1, max_length=255)
    protocol: str = Field(default="tcp", pattern="^(?i)(tcp|udp|icmp)$")
    dst_port: int | None = Field(default=None, ge=1, le=65535)
    src_port: int | None = Field(default=None, ge=1, le=65535)
    icmp_type: int | None = Field(default=None, ge=0, le=255)
    icmp_code: int | None = Field(default=None, ge=0, le=255)
    expect: str = Field(default="ALLOW", pattern="^(ALLOW|DENY)$")


class CheckGroup(BaseModel):
    id: str
    name: str = Field(min_length=1, max_length=120)
    checks: list[CheckItem] = Field(default_factory=list)


class ChecksDoc(BaseModel):
    groups: list[CheckGroup] = Field(default_factory=list)


class RunRequest(BaseModel):
    checks: list[CheckItem] = Field(min_length=1, max_length=200)


@router.get("")
async def get_checks(_user: dict = Depends(get_current_user)) -> dict:
    doc = await read_config("checks")
    return doc if doc.get("groups") is not None else {"groups": []}


@router.put("")
async def save_checks(body: ChecksDoc, _admin: dict = Depends(require_admin)) -> dict:
    data = body.model_dump()
    await write_config("checks", data)
    return data


@router.post("/run")
async def run_checks(body: RunRequest, request: Request,
                     _user: dict = Depends(get_current_user)) -> dict:
    state = request.app.state
    if not state.inventory.devices:
        raise HTTPException(409, "Kein FMG-Inventar vorhanden — zuerst Sync ausführen.")

    fmg_cfg = await read_config("fmg")
    tracker_cfg = await read_config("tracker")
    itop_cfg = await read_config("itop")
    dns_cfg = await read_config("dns")

    client = build_fmg_client(fmg_cfg, state.cfg)
    results: list[dict] = []
    try:
        for c in body.checks:
            base = {"id": c.id, "label": c.label, "src": c.src, "dst": c.dst,
                    "protocol": c.protocol, "dst_port": c.dst_port, "expect": c.expect}
            try:
                req = TraceRequest(
                    src=c.src, dst=c.dst, protocol=c.protocol, dst_port=c.dst_port,
                    src_port=c.src_port, icmp_type=c.icmp_type, icmp_code=c.icmp_code)
                res = await _execute_trace(
                    state, req, fmg_cfg=fmg_cfg, tracker_cfg=tracker_cfg,
                    itop_cfg=itop_cfg, dns_cfg=dns_cfg, client=client)
                results.append({**base, "actual": res.verdict,
                                "ok": res.verdict == c.expect, "error": None,
                                # Volles Ergebnis: aufgelöste Endpunkte (FMG/iTop/DNS),
                                # Hops, Deny-Details + Regelvorschlag, Graph-Daten.
                                "result": res.model_dump()})
            except HTTPException as exc:
                results.append({**base, "actual": None, "ok": False,
                                "error": str(exc.detail), "result": None})
            except Exception as exc:  # ein fehlerhafter Check darf den Rest nicht kippen
                results.append({**base, "actual": None, "ok": False,
                                "error": str(exc), "result": None})
    finally:
        await client.close()

    passed = sum(1 for r in results if r["ok"])
    return {"results": results, "passed": passed, "total": len(results),
            "synced_at": state.inventory.synced_at}
