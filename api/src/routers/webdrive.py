"""Webdrive-Dashboard: Zustand für alle Rollen, Verbindungstest und Poller-Stand für Admins."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Request

from deps import get_current_user, require_admin
from routers.config import read_config
from webdrive.graylog import GraylogNotConfigured, base_url
from webdrive.state import build

router = APIRouter(prefix="/api/webdrive", tags=["webdrive"])

STALE_AFTER = timedelta(minutes=3)


def clamp_since(since: datetime | None, now: datetime, retention_days: int) -> datetime:
    """Zeitraum-Beginn kommt vom Browser (lokale Mitternacht kennt nur er);
    weiter zurück als die Aufbewahrung reicht nichts."""
    if since is None:
        return now - timedelta(hours=24)
    if since.tzinfo is None:
        since = since.replace(tzinfo=timezone.utc)
    return min(max(since, now - timedelta(days=retention_days)), now)


@router.get("/status")
async def status(request: Request, since: datetime | None = None,
                 _user: dict = Depends(get_current_user)) -> dict:
    cfg = await read_config("webdrive")
    if not cfg.get("base_url"):
        return {"configured": False}
    now = datetime.now(timezone.utc)
    since = clamp_since(since, now, int(cfg.get("retention_days", 7)))
    store = request.app.state.webdrive_store
    poll = await store.get_poll()
    events = await store.load_events(since - timedelta(hours=24))   # Sync-Kopf braucht Vorlauf
    model = build(events, await store.load_identities(), now, since,
                  int(cfg.get("active_window_min", 15)))
    last_ok = poll.get("last_ok")
    return {
        "configured": True,
        "now": now.isoformat(),
        "since": since.isoformat(),
        "graylog_url": base_url(cfg),
        "sync_rule": cfg.get("sync_rule") or "Webdrive-User",
        "poll": {
            "last_ok": last_ok.isoformat() if last_ok else None,
            "last_error": poll.get("last_error"),
            "stale": last_ok is None or now - last_ok > STALE_AFTER,
        },
        **model,
    }


@router.post("/test")
async def test_connection(request: Request, _admin: dict = Depends(require_admin)) -> dict:
    cfg = await read_config("webdrive")
    try:
        return await request.app.state.webdrive_poller.client.test(cfg)
    except GraylogNotConfigured as exc:
        raise HTTPException(400, f"{exc} Bitte zuerst speichern.") from exc
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(502, f"Verbindung fehlgeschlagen: {exc}") from exc


@router.get("/poller")
async def poller_state(request: Request, _admin: dict = Depends(require_admin)) -> dict:
    poll = await request.app.state.webdrive_store.get_poll()
    return {k: (v.isoformat() if isinstance(v, datetime) else v) for k, v in poll.items()}
