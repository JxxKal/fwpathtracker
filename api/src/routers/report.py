"""Wochenreport: Liste, Einzelbericht, manueller Lauf (nur Admins — der Bericht
enthält Konto- und Benutzernamen aus AD, FortiGate und iTop)."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel

from deps import require_admin
from report import build as report_build, period
from routers.config import read_config

router = APIRouter(prefix="/api/report", tags=["report"])

MAX_SPAN = timedelta(days=31)


class RunRequest(BaseModel):
    start: datetime | None = None
    end: datetime | None = None


@router.get("")
async def reports(request: Request, _admin: dict = Depends(require_admin)) -> dict:
    cfg = await read_config("report")
    now = datetime.now(timezone.utc)
    nxt = period.last_slot(now, cfg) + period.WEEK
    return {"reports": await request.app.state.report_store.list(),
            "schedule": {"enabled": bool(cfg.get("enabled")), "next": nxt.isoformat()},
            "default": {"start": (period.last_slot(now, cfg)).isoformat(), "end": now.isoformat()}}


@router.get("/{rid}")
async def report(rid: int, request: Request, _admin: dict = Depends(require_admin)) -> dict:
    out = await request.app.state.report_store.get(rid)
    if not out:
        raise HTTPException(404, "Bericht nicht gefunden.")
    return out


@router.delete("/{rid}")
async def delete(rid: int, request: Request, _admin: dict = Depends(require_admin)) -> dict:
    if not await request.app.state.report_store.delete(rid):
        raise HTTPException(404, "Bericht nicht gefunden.")
    return {"ok": True}


@router.post("/run")
async def run(body: RunRequest, request: Request, admin: dict = Depends(require_admin)) -> dict:
    """Jetzt erzeugen. Ohne Angabe: die letzten sieben Tage bis jetzt."""
    now = datetime.now(timezone.utc)
    end = body.end or now
    start = body.start or end - period.WEEK
    for d in (start, end):
        if d.tzinfo is None:
            raise HTTPException(422, "Zeitangaben brauchen eine Zeitzone.")
    if not start < end or end - start > MAX_SPAN:
        raise HTTPException(422, "Zeitraum muss positiv und höchstens 31 Tage lang sein.")
    return await report_build.run(request.app.state, read_config, start, end,
                                  trigger="manual", user=str(admin.get("username") or ""))
