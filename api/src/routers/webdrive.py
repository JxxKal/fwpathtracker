"""Webdrive-Dashboard: Zustand für alle Rollen, Verbindungstest und Poller-Stand für Admins."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Request

from deps import get_current_user, require_admin
from routers.config import read_config
from webdrive.graylog import GraylogNotConfigured, base_url
from webdrive.parse import detect_source, parse_message
from webdrive.poller import queries
from webdrive.state import build

router = APIRouter(prefix="/api/webdrive", tags=["webdrive"])

STALE_AFTER = timedelta(minutes=3)
PROBE_WINDOW = timedelta(minutes=15)
PROBE_SAMPLES = 3


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


@router.post("/reload")
async def reload(request: Request, _admin: dict = Depends(require_admin)) -> dict:
    """Letzte 24 h neu aus Graylog einlesen — nach Änderungen an Stream oder Abfragen."""
    cfg = await read_config("webdrive")
    await request.app.state.webdrive_store.reset_poll()
    try:
        stats = await request.app.state.webdrive_poller.run_once(cfg, datetime.now(timezone.utc))
    except Exception as exc:
        raise HTTPException(502, f"Einlesen fehlgeschlagen: {exc}") from exc
    return {"ok": True, "stats": stats}


@router.post("/probe")
async def probe(request: Request, _admin: dict = Depends(require_admin)) -> dict:
    """Diagnose fürs Settings-Panel: die tatsächlichen Abfragen, die Treffer der
    letzten 15 min je erkannter Quelle und Rohnachrichten, so wie A38 sie
    bekommt — damit sich ein abweichendes Logformat ohne Graylog-Zugang erkennen lässt."""
    cfg = await read_config("webdrive")
    client = request.app.state.webdrive_poller.client
    now = datetime.now(timezone.utc)
    qs = queries(cfg)
    out = {"queries": qs, "stream_id": cfg.get("stream_id") or None, "error": None,
           "fac": {"hits": 0, "recognized": {}, "dropped_samples": []},
           "oc": {"hits": 0, "recognized": {}, "dropped_samples": []}}
    if not qs:
        out["error"] = "Weder Stream-ID noch Abfrage eingetragen."
        return out
    try:
        for q in qs:
            for m in await client.search(cfg, q, now - PROBE_WINDOW, now):
                src = detect_source(m)
                bucket = out[src]
                bucket["hits"] += 1
                ev = parse_message(src, m, cfg)
                if ev:
                    bucket["recognized"][ev.kind] = bucket["recognized"].get(ev.kind, 0) + 1
                elif len(bucket["dropped_samples"]) < PROBE_SAMPLES:
                    bucket["dropped_samples"].append(m)
    except Exception as exc:
        out["error"] = str(exc)
    return out
