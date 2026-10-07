"""Graylog abfragen, Nachrichten zu Ereignissen machen, Identitäten nachziehen.

Ein Lauf holt das Fenster seit dem letzten erfolgreichen Stand (mit 2 min
Überlappung gegen spät eintreffende Nachrichten; Doppelte verhindert der
Unique-Index auf die Graylog-ID). Nach einem Ausfall wird höchstens 24 h
nachgeholt, in Scheiben von 1 h — so bleibt jede Scheibe unter dem
Ergebnisfenster von OpenSearch. Der Stand rückt nach jeder fertigen Scheibe
vor: Fällt Graylog mittendrin aus, ist das Geholte gesichert und der Rest
kommt beim nächsten Lauf.
"""
from __future__ import annotations

from collections import Counter
from datetime import datetime, timedelta

from webdrive.correlate import new_identities
from webdrive.parse import parse_message

SLICE = timedelta(hours=1)
OVERLAP = timedelta(minutes=2)
MAX_CATCHUP = timedelta(hours=24)
# Ein verwaister Browser-Tab erzeugt rund 1.400 dieser Zeilen am Tag.
FAC_NOISE = '"Failed to send user info"'


def build_query(source: str, query: str) -> str:
    if source == "fac":
        return f"({query}) AND NOT {FAC_NOISE}"
    return query


class WebdrivePoller:
    def __init__(self, client, store) -> None:
        self.client = client          # auch für den Verbindungstest im Settings-Panel
        self._store = store

    async def run_once(self, cfg: dict, now: datetime) -> dict:
        poll = await self._store.get_poll()
        until = poll.get("polled_until")
        start = max(until - OVERLAP, now - MAX_CATCHUP) if until else now - MAX_CATCHUP
        sources = [(src, cfg.get(key) or "") for src, key in (("fac", "fac_query"), ("oc", "oc_query"))]
        counts: Counter = Counter()
        t = start
        try:
            while t < now:
                end = min(t + SLICE, now)
                for source, query in sources:
                    if not query:
                        continue
                    msgs = await self.client.search(cfg, build_query(source, query), t, end)
                    events = []
                    for m in msgs:
                        ev = parse_message(source, m, cfg)
                        if ev:
                            events.append(ev)
                        counts[f"{source}_{'events' if ev else 'dropped'}"] += 1
                    await self._store.insert_events(events)
                await self._store.mark_ok(end, now, dict(counts))
                t = end
        except Exception as exc:
            await self._store.mark_error(str(exc), now)
            raise

        recent = await self._store.load_events(now - MAX_CATCHUP)
        known = set((await self._store.load_identities()).keys())
        await self._store.save_identities(new_identities(recent, known))
        await self._store.purge(int(cfg.get("retention_days", 7)))
        return dict(counts)
