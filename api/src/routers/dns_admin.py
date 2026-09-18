"""Stand des Reverse-DNS-Caches + Handaufräumen (Settings-Panel).

Ohne Zahlen ist ein Cache eine Blackbox: niemand sieht, ob er trägt oder ob
seit Wochen nur Fehlanzeigen darin liegen, weil der falsche Resolver
eingetragen ist.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request

from deps import require_admin
from resolver.dns_cache import RETENTION_DAYS
from routers.config import read_config

router = APIRouter(prefix="/api/dns", tags=["dns"])


def _cache(request: Request):
    cache = getattr(request.app.state, "dns_cache", None)
    if cache is None:
        raise HTTPException(503, "DNS-Cache nicht verfügbar.")
    return cache


@router.get("/cache")
async def cache_stats(request: Request, _admin: dict = Depends(require_admin)) -> dict:
    try:
        stats = await _cache(request).stats()
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(502, f"DNS-Cache nicht lesbar: {exc}") from exc
    cfg = await read_config("dns")
    stats["retention_days"] = int(cfg.get("cache_retention_days", RETENTION_DAYS))
    return stats


@router.post("/cache/purge")
async def cache_purge(request: Request, days: int | None = None,
                      _admin: dict = Depends(require_admin)) -> dict:
    """`days=0` leert die Tabelle ganz — etwa nach einem Resolver-Wechsel, wenn
    die gespeicherten Namen aus der falschen Zone stammen."""
    if days is None:
        days = int((await read_config("dns")).get("cache_retention_days", RETENTION_DAYS))
    if days < 0:
        raise HTTPException(400, "Aufbewahrung darf nicht negativ sein.")
    try:
        return {"removed": await _cache(request).purge(days)}
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(502, f"DNS-Cache nicht aufräumbar: {exc}") from exc
