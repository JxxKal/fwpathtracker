"""Tabelle weekly_report: ausgewertete Berichte, je Zeitraum einer."""
from __future__ import annotations

from datetime import datetime

import asyncpg

LIST_COLS = "id, period_start, period_end, created_at, trigger, status, created_by"


def _row(r, with_data: bool = False) -> dict:
    out = {"id": r["id"], "period_start": r["period_start"].isoformat(),
           "period_end": r["period_end"].isoformat(), "created_at": r["created_at"].isoformat(),
           "trigger": r["trigger"], "status": r["status"], "created_by": r["created_by"]}
    if "summary" in r.keys():
        out["summary"] = r["summary"]
    if with_data:
        out["data"] = r["data"]
    return out


class ReportStore:
    def __init__(self, pool: asyncpg.Pool) -> None:
        self._pool = pool

    async def save(self, start: datetime, end: datetime, trigger: str, status: str,
                   data: dict, created_by: str | None) -> int:
        """Ein Zeitraum = ein Bericht: erneut erzeugt ersetzt ihn."""
        async with self._pool.acquire() as conn:
            return await conn.fetchval(
                """INSERT INTO weekly_report (period_start, period_end, trigger, status, data,
                                              created_by)
                   VALUES ($1, $2, $3, $4, $5, $6)
                   ON CONFLICT (period_start, period_end) DO UPDATE SET
                     trigger = EXCLUDED.trigger, status = EXCLUDED.status, data = EXCLUDED.data,
                     created_by = EXCLUDED.created_by, created_at = now(), pdf = NULL
                   RETURNING id""", start, end, trigger, status, data, created_by)

    async def list(self, limit: int = 60) -> list[dict]:
        async with self._pool.acquire() as conn:
            rows = await conn.fetch(
                f"SELECT {LIST_COLS}, data->'summary' AS summary FROM weekly_report "
                "ORDER BY period_end DESC LIMIT $1", limit)
        return [_row(r) for r in rows]

    async def get(self, rid: int) -> dict | None:
        async with self._pool.acquire() as conn:
            r = await conn.fetchrow(f"SELECT {LIST_COLS}, data FROM weekly_report WHERE id = $1",
                                    rid)
        return _row(r, True) if r else None

    async def delete(self, rid: int) -> bool:
        async with self._pool.acquire() as conn:
            res = await conn.execute("DELETE FROM weekly_report WHERE id = $1", rid)
        return res.endswith(" 1")

    async def last_scheduled_end(self) -> datetime | None:
        async with self._pool.acquire() as conn:
            return await conn.fetchval(
                "SELECT max(period_end) FROM weekly_report WHERE trigger = 'schedule'")

    async def previous(self, start: datetime) -> dict | None:
        """Der Bericht, der direkt vor diesem Zeitraum endet — für ▲▼."""
        async with self._pool.acquire() as conn:
            r = await conn.fetchrow(
                "SELECT data FROM weekly_report WHERE period_end <= $1 AND status <> 'failed' "
                "ORDER BY period_end DESC LIMIT 1", start)
        return r["data"] if r else None

    async def purge(self, days: int) -> int:
        if days <= 0:
            return 0
        async with self._pool.acquire() as conn:
            res = await conn.execute(
                "DELETE FROM weekly_report WHERE period_end < now() - ($1 || ' days')::interval",
                str(int(days)))
        return int(res.rsplit(" ", 1)[-1]) if res else 0
