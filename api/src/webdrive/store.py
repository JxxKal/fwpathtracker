"""Persistenz des Webdrive-Dashboards: Ereignisse, Identitäten, Abfrage-Stand.

Kapselt allen SQL-Zugriff, damit Poller und Router gegen eine Attrappe
testbar bleiben (Muster wie locate/arp_store.py).
"""
from __future__ import annotations

from datetime import datetime

import asyncpg

from webdrive.parse import Event


class WebdriveStore:
    def __init__(self, pool: asyncpg.Pool) -> None:
        self._pool = pool

    async def insert_events(self, events: list[Event]) -> None:
        if not events:
            return
        async with self._pool.acquire() as conn:
            await conn.executemany(
                """
                INSERT INTO webdrive_event (gl_id, ts, source, kind, username, token, opaque_id, data)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
                ON CONFLICT (gl_id) DO NOTHING
                """,
                [(e.gl_id, e.ts, e.source, e.kind, e.username, e.token, e.opaque_id, e.data)
                 for e in events],
            )

    async def load_events(self, since: datetime) -> list[Event]:
        async with self._pool.acquire() as conn:
            rows = await conn.fetch(
                """
                SELECT gl_id, ts, source, kind, username, token, opaque_id, data
                FROM webdrive_event WHERE ts >= $1 ORDER BY ts, id
                """,
                since,
            )
        return [Event(r["gl_id"], r["ts"], r["source"], r["kind"], r["username"], r["token"],
                      r["opaque_id"], dict(r["data"] or {})) for r in rows]

    async def load_identities(self) -> dict[str, tuple[str, datetime]]:
        async with self._pool.acquire() as conn:
            rows = await conn.fetch("SELECT opaque_id, username, first_seen FROM webdrive_identity")
        return {r["opaque_id"]: (r["username"], r["first_seen"]) for r in rows}

    async def save_identities(self, new: dict[str, tuple[str, datetime]]) -> None:
        if not new:
            return
        async with self._pool.acquire() as conn:
            await conn.executemany(
                """
                INSERT INTO webdrive_identity (opaque_id, username, first_seen) VALUES ($1, $2, $3)
                ON CONFLICT (opaque_id) DO NOTHING
                """,
                [(o, u, fs) for o, (u, fs) in new.items()],
            )

    async def get_poll(self) -> dict:
        async with self._pool.acquire() as conn:
            row = await conn.fetchrow(
                "SELECT polled_until, last_ok, last_error, stats FROM webdrive_poll WHERE id = 1")
        return dict(row) if row else {}

    async def mark_ok(self, polled_until: datetime, at: datetime, stats: dict) -> None:
        async with self._pool.acquire() as conn:
            await conn.execute(
                """
                INSERT INTO webdrive_poll (id, polled_until, last_ok, last_error, stats)
                VALUES (1, $1, $2, NULL, $3)
                ON CONFLICT (id) DO UPDATE SET polled_until = EXCLUDED.polled_until,
                    last_ok = EXCLUDED.last_ok, last_error = NULL, stats = EXCLUDED.stats
                """,
                polled_until, at, stats,
            )

    async def reset_poll(self) -> None:
        """Nächster Lauf liest die letzten 24 h neu ein (Doppelte verhindert der Unique-Index)."""
        async with self._pool.acquire() as conn:
            await conn.execute("UPDATE webdrive_poll SET polled_until = NULL WHERE id = 1")

    async def mark_error(self, msg: str, at: datetime) -> None:
        async with self._pool.acquire() as conn:
            await conn.execute(
                """
                INSERT INTO webdrive_poll (id, last_error) VALUES (1, $1)
                ON CONFLICT (id) DO UPDATE SET last_error = EXCLUDED.last_error
                """,
                f"{at.isoformat()} {msg}",
            )

    async def purge(self, days: int) -> int:
        async with self._pool.acquire() as conn:
            res = await conn.execute(
                "DELETE FROM webdrive_event WHERE ts < now() - make_interval(days => $1)", days)
        return int(res.split()[-1]) if res else 0
