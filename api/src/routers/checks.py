"""Check-Gruppen: Flow-Sets speichern und als Batch prüfen (Soll- vs. Ist-Verdict).

Anwendungsfall: ein ganzes Regel-Set zu testender Flows anlegen, laufen lassen,
im FortiManager umsetzen und erneut prüfen, ob es jetzt zieht (Regressions-Check).
Speicherung im system_config-Key 'checks'; Ausführung teilt sich die Trace-Engine.

Pro Check wird der Bearbeitungsstand mitgeführt: der letzte Lauf (`last_run`) und
ob er nach der Umsetzung erfolgreich getestet und damit erledigt ist (`done`).
"""
from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from deps import get_current_user, require_admin
from fmg.factory import build_fmg_client
from routers.config import read_config, write_config
from routers.trace import TraceRequest, _execute_trace

router = APIRouter(prefix="/api/checks", tags=["checks"])


class LastRun(BaseModel):
    """Ergebnis des letzten Laufs — bleibt am Check hängen, auch nach Reload."""
    at: str
    actual: str | None = None
    ok: bool = False
    error: str | None = None


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
    # Bearbeitungsstand (siehe /status) — von der Ausführung nicht angefasst.
    done: bool = False
    done_at: str | None = None
    done_by: str | None = None
    last_run: LastRun | None = None


class CheckGroup(BaseModel):
    id: str
    name: str = Field(min_length=1, max_length=120)
    checks: list[CheckItem] = Field(default_factory=list)


class ChecksDoc(BaseModel):
    groups: list[CheckGroup] = Field(default_factory=list)


class RunRequest(BaseModel):
    checks: list[CheckItem] = Field(min_length=1, max_length=200)


class StatusUpdate(BaseModel):
    check_id: str
    done: bool | None = None          # explizit erledigt / wieder geöffnet
    record_run: bool = False          # Lauf-Ergebnis übernehmen (actual/ok/error)
    actual: str | None = None
    ok: bool | None = None
    error: str | None = None


class StatusRequest(BaseModel):
    group_id: str
    updates: list[StatusUpdate] = Field(min_length=1, max_length=200)


def apply_status(doc: dict, group_id: str, updates: list[StatusUpdate], *,
                 username: str, now: str) -> dict:
    """Bearbeitungsstand in das gespeicherte Checks-Dokument einpflegen.

    Regeln:
    * `record_run` schreibt `last_run`; ein erfolgreicher Lauf markiert den Check
      automatisch als erledigt ("nach der Umsetzung erfolgreich getestet").
    * Ein bereits erledigter Check behält sein ursprüngliches `done_at` — die
      Erledigung datiert auf den ersten grünen Lauf, nicht auf jede Wiederholung.
    * Ein fehlgeschlagener Lauf setzt `done` **nicht** zurück; der Rückfall wird
      im UI als Regression sichtbar (erledigt, aber letzter Lauf rot).
    * `done` explizit gesetzt hat Vorrang (manuell erledigt / wieder geöffnet).

    Wirft ValueError, wenn die Gruppe nicht existiert.
    """
    groups = doc.get("groups") or []
    group = next((g for g in groups if g.get("id") == group_id), None)
    if group is None:
        raise ValueError(f"Check-Gruppe '{group_id}' nicht gefunden")

    by_id = {c.get("id"): c for c in group.get("checks") or [] if c.get("id")}
    touched = 0
    for u in updates:
        check = by_id.get(u.check_id)
        if check is None:                       # zwischenzeitlich gelöscht
            continue
        touched += 1
        if u.record_run:
            check["last_run"] = {"at": now, "actual": u.actual,
                                 "ok": bool(u.ok), "error": u.error}
            if u.ok and not check.get("done"):
                check["done"] = True
                check["done_at"] = now
                check["done_by"] = username
        if u.done is True:
            check["done"] = True
            if not check.get("done_at"):
                check["done_at"] = now
                check["done_by"] = username
        elif u.done is False:
            check["done"] = False
            check["done_at"] = None
            check["done_by"] = None

    if touched == 0:
        raise ValueError("Keiner der Checks existiert (noch) in dieser Gruppe")
    return doc


@router.get("")
async def get_checks(_user: dict = Depends(get_current_user)) -> dict:
    doc = await read_config("checks")
    return doc if doc.get("groups") is not None else {"groups": []}


@router.put("")
async def save_checks(body: ChecksDoc, _admin: dict = Depends(require_admin)) -> dict:
    data = body.model_dump()
    await write_config("checks", data)
    return data


@router.post("/status")
async def update_status(body: StatusRequest,
                        user: dict = Depends(get_current_user)) -> dict:
    """Erledigt-Status/Lauf-Ergebnis eines Checks fortschreiben.

    Bewusst ohne Admin-Zwang: das ist kein Bearbeiten der Check-Definition,
    sondern das Protokollieren eines Laufs — und laufen lassen darf jeder
    angemeldete Benutzer.
    """
    doc = await read_config("checks")
    if not doc.get("groups"):
        raise HTTPException(404, "Keine Check-Gruppen gespeichert.")
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    try:
        updated = apply_status(doc, body.group_id, body.updates,
                               username=str(user.get("username") or "?"), now=now)
    except ValueError as exc:
        raise HTTPException(404, str(exc))
    await write_config("checks", updated)
    return updated


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
