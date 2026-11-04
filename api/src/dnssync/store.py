"""Tabellen dns_sync_run und dns_sync_ignore."""
from __future__ import annotations

import asyncpg

COLS = ("id, created_at, trigger, created_by, status, stats, decided_by, decided_at, result")


def _row(r, items: bool = False) -> dict:
    out = {k: r[k] for k in ("id", "trigger", "created_by", "status", "stats", "decided_by",
                             "result")}
    out["created_at"] = r["created_at"].isoformat()
    out["decided_at"] = r["decided_at"].isoformat() if r["decided_at"] else None
    if items:
        out["items"] = r["items"]
    return out


class DnsSyncStore:
    def __init__(self, pool: asyncpg.Pool) -> None:
        self._pool = pool

    async def create(self, trigger: str, user: str | None, stats: dict, items: list[dict]) -> int:
        """Neuer Lauf; ältere offene Läufe sind damit überholt."""
        async with self._pool.acquire() as conn, conn.transaction():
            await conn.execute("UPDATE dns_sync_run SET status = 'superseded' "
                               "WHERE status = 'open'")
            return await conn.fetchval(
                "INSERT INTO dns_sync_run (trigger, created_by, status, stats, items) "
                "VALUES ($1, $2, 'open', $3, $4) RETURNING id", trigger, user, stats, items)

    async def list(self, limit: int = 30) -> list[dict]:
        async with self._pool.acquire() as conn:
            rows = await conn.fetch(f"SELECT {COLS} FROM dns_sync_run ORDER BY created_at DESC "
                                    "LIMIT $1", limit)
        return [_row(r) for r in rows]

    async def get(self, rid: int) -> dict | None:
        async with self._pool.acquire() as conn:
            r = await conn.fetchrow(f"SELECT {COLS}, items FROM dns_sync_run WHERE id = $1", rid)
        return _row(r, True) if r else None

    async def set_items(self, rid: int, items: list[dict]) -> None:
        async with self._pool.acquire() as conn:
            await conn.execute("UPDATE dns_sync_run SET items = $2 WHERE id = $1 "
                               "AND status = 'open'", rid, items)

    async def decide(self, rid: int, status: str, user: str, items: list[dict] | None,
                     result: dict | None) -> None:
        async with self._pool.acquire() as conn:
            await conn.execute(
                "UPDATE dns_sync_run SET status = $2, decided_by = $3, decided_at = now(), "
                "items = COALESCE($4, items), result = $5 WHERE id = $1", rid, status, user,
                items, result)

    async def last_scheduled(self):
        async with self._pool.acquire() as conn:
            return await conn.fetchval("SELECT max(created_at) FROM dns_sync_run "
                                       "WHERE trigger = 'schedule'")

    async def open_count(self) -> int:
        async with self._pool.acquire() as conn:
            return await conn.fetchval(
                "SELECT coalesce(sum(jsonb_array_length(items)), 0) FROM dns_sync_run "
                "WHERE status = 'open'")

    async def ignored(self) -> list[dict]:
        async with self._pool.acquire() as conn:
            rows = await conn.fetch("SELECT ip_id, ip, reason, created_by, created_at "
                                    "FROM dns_sync_ignore ORDER BY created_at DESC")
        return [dict(r, created_at=r["created_at"].isoformat()) for r in rows]

    async def ignore(self, ip_id: str, ip: str, reason: str | None, user: str) -> None:
        async with self._pool.acquire() as conn:
            await conn.execute(
                "INSERT INTO dns_sync_ignore (ip_id, ip, reason, created_by) VALUES ($1,$2,$3,$4) "
                "ON CONFLICT (ip_id) DO UPDATE SET reason = EXCLUDED.reason", ip_id, ip, reason,
                user)

    async def unignore(self, ip_id: str) -> bool:
        async with self._pool.acquire() as conn:
            res = await conn.execute("DELETE FROM dns_sync_ignore WHERE ip_id = $1", ip_id)
        return res.endswith(" 1")
