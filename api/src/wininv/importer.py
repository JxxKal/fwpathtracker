"""Einlesen: nur Dateien, deren Größe oder Zeitstempel sich geändert hat;
neuer Verlaufseintrag nur, wenn sich der Inhalt geändert hat."""
from __future__ import annotations

import asyncio
import hashlib
import logging
from datetime import datetime, timezone

from wininv import parse

log = logging.getLogger("wininv")

READ_PARALLEL = 8


async def run(source, store, now: datetime | None = None) -> dict:
    now = now or datetime.now(timezone.utc)
    entries = await source.list()
    known = await store.known()
    stats = {"files": 0, "hosts": 0, "read": 0, "changed": 0, "unchanged": 0, "skipped": 0,
             "foreign": 0, "errors": [], "started": now.isoformat()}
    todo, same = [], []
    hosts: set[str] = set()
    for e in entries:
        key = parse.split_name(e.name)
        if key is None:
            stats["foreign"] += 1
            continue
        stats["files"] += 1
        hosts.add(key[0])
        old = known.get(key)
        if old and old["size"] == e.size and old["mtime"] == e.mtime:
            same.append(key)
            continue
        if e.size > parse.MAX_FILE_BYTES:
            stats["errors"].append(f"{e.name}: größer als {parse.MAX_FILE_BYTES // 2**20} MB")
            continue
        todo.append((key, e, old))
    stats["hosts"] = len(hosts)
    await store.touch(same, now)
    stats["skipped"] = len(same)

    sem = asyncio.Semaphore(READ_PARALLEL)

    async def one(key, e, old) -> None:
        async with sem:
            try:
                raw = await source.read(e.name)
            except Exception as exc:
                stats["errors"].append(f"{e.name}: {exc}")
                return
        stats["read"] += 1
        sha = hashlib.sha256(raw).hexdigest()
        changed = not old or old["sha256"] != sha
        try:
            rows = parse.parse_csv(raw, key[1]) if changed else []
        except Exception as exc:
            stats["errors"].append(f"{e.name}: nicht lesbar ({exc})")
            return
        await store.save(key[0], key[1], e.name, e.size, e.mtime, sha, rows, changed, now)
        stats["changed" if changed else "unchanged"] += 1

    await asyncio.gather(*(one(*t) for t in todo))
    stats["errors"] = stats["errors"][:50]
    log.info("Windows-Inventar: %d Dateien von %d Hosts, %d gelesen, %d geändert, %d Fehler",
             stats["files"], stats["hosts"], stats["read"], stats["changed"],
             len(stats["errors"]))
    return stats
