"""Tabellen win_inventory (aktueller Stand) und win_inventory_history."""
from __future__ import annotations

from datetime import datetime

import asyncpg


class WinInvStore:
    def __init__(self, pool: asyncpg.Pool) -> None:
        self._pool = pool

    async def known(self) -> dict[tuple[str, str], dict]:
        """(Host, Art) → Name, Größe, mtime, Hash des gespeicherten Stands."""
        async with self._pool.acquire() as conn:
            rows = await conn.fetch("SELECT hostname, kind, file_name, file_size, file_mtime, "
                                    "sha256 FROM win_inventory")
        return {(r["hostname"], r["kind"]): {"name": r["file_name"], "size": r["file_size"],
                                             "mtime": r["file_mtime"], "sha256": r["sha256"]}
                for r in rows}

    async def touch(self, keys: list[tuple[str, str]], now: datetime) -> None:
        if not keys:
            return
        async with self._pool.acquire() as conn:
            await conn.executemany("UPDATE win_inventory SET checked_at = $3 "
                                   "WHERE hostname = $1 AND kind = $2",
                                   [(h, k, now) for h, k in keys])

    async def save(self, host: str, kind: str, name: str, size: int, mtime: datetime,
                   sha: str, rows: list[dict], changed: bool, now: datetime) -> None:
        """changed=False: gleicher Inhalt, nur die Datei wurde neu geschrieben."""
        async with self._pool.acquire() as conn, conn.transaction():
            if changed:
                await conn.execute(
                    """INSERT INTO win_inventory (hostname, kind, file_name, file_size, file_mtime,
                                                  sha256, rows, changed_at, checked_at)
                       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $8)
                       ON CONFLICT (hostname, kind) DO UPDATE SET
                         file_name = EXCLUDED.file_name, file_size = EXCLUDED.file_size,
                         file_mtime = EXCLUDED.file_mtime, sha256 = EXCLUDED.sha256,
                         rows = EXCLUDED.rows, changed_at = EXCLUDED.changed_at,
                         checked_at = EXCLUDED.checked_at""",
                    host, kind, name, size, mtime, sha, rows, now)
                await conn.execute(
                    "INSERT INTO win_inventory_history (hostname, kind, sha256, file_mtime, rows, "
                    "valid_from) VALUES ($1, $2, $3, $4, $5, $6)", host, kind, sha, mtime, rows,
                    mtime)
            else:
                await conn.execute(
                    "UPDATE win_inventory SET file_name = $3, file_size = $4, file_mtime = $5, "
                    "checked_at = $6 WHERE hostname = $1 AND kind = $2",
                    host, kind, name, size, mtime, now)

    async def current(self, host: str | None = None) -> list[dict]:
        sql = ("SELECT hostname, kind, file_mtime, changed_at, checked_at, rows "
               "FROM win_inventory")
        async with self._pool.acquire() as conn:
            rows = (await conn.fetch(sql + " WHERE hostname = $1", host) if host
                    else await conn.fetch(sql))
        return [dict(r) for r in rows]

    async def current_kinds(self, kinds: list[str]) -> list[dict]:
        async with self._pool.acquire() as conn:
            rows = await conn.fetch(
                "SELECT hostname, kind, file_mtime, changed_at, checked_at, rows "
                "FROM win_inventory WHERE kind = ANY($1::text[])", kinds)
        return [dict(r) for r in rows]

    async def window(self, frm: datetime, to: datetime) -> dict:
        """Alle Stände mit Beginn im Zeitraum, je (Host, Art) zusätzlich der
        letzte davor als Vergleichsbasis — und wann der Verlauf überhaupt
        beginnt."""
        async with self._pool.acquire() as conn:
            start = await conn.fetchval("SELECT min(valid_from) FROM win_inventory_history")
            inside = await conn.fetch(
                "SELECT hostname, kind, valid_from, rows FROM win_inventory_history "
                "WHERE valid_from >= $1 AND valid_from < $2 ORDER BY valid_from", frm, to)
            base = await conn.fetch(
                """SELECT DISTINCT ON (h.hostname, h.kind) h.hostname, h.kind, h.valid_from,
                          h.rows
                   FROM win_inventory_history h
                   JOIN (SELECT DISTINCT hostname, kind FROM win_inventory_history
                         WHERE valid_from >= $1 AND valid_from < $2) c
                     ON c.hostname = h.hostname AND c.kind = h.kind
                   WHERE h.valid_from < $1
                   ORDER BY h.hostname, h.kind, h.valid_from DESC""", frm, to)
            newest = await conn.fetch(
                "SELECT hostname, max(file_mtime) AS newest FROM win_inventory GROUP BY hostname")
        return {"history_start": start, "inside": [dict(r) for r in inside],
                "base": [dict(r) for r in base],
                "newest": {r["hostname"]: r["newest"] for r in newest}}

    async def history(self, host: str, kind: str | None = None, limit: int = 30) -> list[dict]:
        async with self._pool.acquire() as conn:
            rows = await conn.fetch(
                "SELECT kind, valid_from, rows FROM win_inventory_history WHERE hostname = $1 "
                "AND ($2::text IS NULL OR kind = $2) ORDER BY valid_from DESC LIMIT $3",
                host, kind, limit)
        return [dict(r) for r in rows]

    async def purge(self, days: int) -> int:
        """Alte Stände löschen — den jeweils jüngsten je Host und Art nie."""
        async with self._pool.acquire() as conn:
            res = await conn.execute(
                """DELETE FROM win_inventory_history h
                   WHERE valid_from < now() - make_interval(days => $1)
                     AND EXISTS (SELECT 1 FROM win_inventory_history n
                                 WHERE n.hostname = h.hostname AND n.kind = h.kind
                                   AND n.valid_from > h.valid_from)""", days)
        return int(res.split()[-1])
