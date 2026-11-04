"""iTop↔DNS-Abgleich (Todos): Läufe, Auswahl, Freigabe, Ausnahmen. Nur Admins."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from deps import require_admin
from dnssync import service
from dnssync.itop import ItopWriteBlocked
from routers.config import read_config

router = APIRouter(prefix="/api/dnssync", tags=["dnssync"])


class Toggle(BaseModel):
    ids: list[str] = Field(max_length=20000)
    selected: bool


class Ignore(BaseModel):
    ip_id: str = Field(min_length=1, max_length=20)
    ip: str = Field(min_length=1, max_length=45)
    reason: str | None = Field(default=None, max_length=300)


def _store(request: Request):
    return request.app.state.dnssync_store


@router.get("")
async def overview(request: Request, _admin: dict = Depends(require_admin)) -> dict:
    cfg = await read_config("dnssync")
    return {"runs": await _store(request).list(), "write_enabled": bool(cfg.get("write_enabled")),
            "open_items": await _store(request).open_count()}


@router.get("/runs/{rid}")
async def get_run(rid: int, request: Request, _admin: dict = Depends(require_admin)) -> dict:
    run = await _store(request).get(rid)
    if run is None:
        raise HTTPException(404, "Lauf nicht gefunden.")
    return run


@router.post("/runs")
async def create_run(request: Request, admin: dict = Depends(require_admin)) -> dict:
    try:
        rid = await service.generate(_store(request), read_config, trigger="manual",
                                     user=admin.get("username"))
    except service.DnsSyncError as exc:
        raise HTTPException(400, str(exc)) from exc
    except Exception as exc:
        raise HTTPException(502, f"Abgleich fehlgeschlagen: {exc}") from exc
    return {"id": rid}


@router.patch("/runs/{rid}/items")
async def toggle_items(rid: int, body: Toggle, request: Request,
                       _admin: dict = Depends(require_admin)) -> dict:
    run = await _store(request).get(rid)
    if run is None or run["status"] != "open":
        raise HTTPException(409, "Nur offene Läufe lassen sich ändern.")
    items = service.toggle(run["items"], set(body.ids), body.selected)
    await _store(request).set_items(rid, items)
    return {"selected": sum(1 for i in items if i["selected"])}


@router.post("/runs/{rid}/apply")
async def apply_run(rid: int, request: Request, admin: dict = Depends(require_admin)) -> dict:
    run = await _store(request).get(rid)
    if run is None:
        raise HTTPException(404, "Lauf nicht gefunden.")
    try:
        return await service.apply(_store(request), read_config, run, admin.get("username") or "?")
    except (service.DnsSyncError, ItopWriteBlocked) as exc:
        raise HTTPException(409, str(exc)) from exc


@router.post("/runs/{rid}/discard")
async def discard_run(rid: int, request: Request, admin: dict = Depends(require_admin)) -> dict:
    run = await _store(request).get(rid)
    if run is None or run["status"] != "open":
        raise HTTPException(409, "Nur offene Läufe lassen sich verwerfen.")
    await _store(request).decide(rid, "discarded", admin.get("username") or "?", None, None)
    return {"ok": True}


@router.get("/ignore")
async def list_ignored(request: Request, _admin: dict = Depends(require_admin)) -> list[dict]:
    return await _store(request).ignored()


@router.post("/ignore")
async def add_ignore(body: Ignore, request: Request, admin: dict = Depends(require_admin)) -> dict:
    await _store(request).ignore(body.ip_id, body.ip, body.reason, admin.get("username") or "?")
    # Aus dem offenen Lauf nehmen, damit die Liste sofort stimmt.
    for run in [r for r in await _store(request).list(5) if r["status"] == "open"]:
        full = await _store(request).get(run["id"])
        items = [i for i in full["items"] if i["id"] != body.ip_id]
        await _store(request).set_items(run["id"], items)
    return {"ok": True}


@router.delete("/ignore/{ip_id}")
async def remove_ignore(ip_id: str, request: Request, _admin: dict = Depends(require_admin)) -> dict:
    return {"ok": await _store(request).unignore(ip_id)}
