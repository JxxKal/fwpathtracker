"""Reverse-DNS-Cache: IP → Name, persistent in Postgres.

Warum überhaupt: eine Zeichnung fragt bis zu 400 Adressen ab, die
Switch-Ansicht 300, der Free-IP-Finder 256 — und beim zweiten Mal wieder.
Der teure Teil sind dabei die Adressen OHNE PTR-Eintrag: die laufen jedes Mal
in die volle Zeitüberschreitung. Deshalb hält der Cache auch die Fehlanzeige
fest, nur kürzer.

Warum nur rückwärts: ein veralteter Name an einer Adresse beschriftet falsch,
mehr nicht. Eine veraltete Adresse zu einem Namen würde den Pfad-Tracker den
falschen Weg prüfen lassen, ohne dass es jemandem auffällt. Die
Vorwärtsauflösung bleibt deshalb ungecacht.
"""
from __future__ import annotations

import asyncio
import ipaddress
import logging
from collections.abc import Awaitable, Callable

import asyncpg

log = logging.getLogger("resolver.dns_cache")

HIT_TTL_S = 7 * 24 * 3600      # Treffer: Namen ändern sich selten
MISS_TTL_S = 24 * 3600         # Fehlanzeige: wird eher mal zum Eintrag
RETENTION_DAYS = 180


def normalize_ip(ip: str) -> str | None:
    try:
        return str(ipaddress.IPv4Address(str(ip).strip()))
    except (ipaddress.AddressValueError, ValueError):
        return None


class DnsCache:
    """Tabelle dns_cache. Fehler kosten nie mehr als den Cache-Vorteil."""

    def __init__(self, pool: asyncpg.Pool) -> None:
        self._pool = pool

    async def get(self, ips: list[str], hit_ttl_s: int = HIT_TTL_S,
                  miss_ttl_s: int = MISS_TTL_S) -> dict[str, str | None]:
        """Frische Einträge für diese Adressen: IP → Name (oder None für eine
        gültige Fehlanzeige). Abgelaufene und unbekannte fehlen im Ergebnis."""
        clean = sorted({n for n in (normalize_ip(i) for i in ips) if n})
        if not clean:
            return {}
        async with self._pool.acquire() as conn:
            rows = await conn.fetch(
                "SELECT ip, name FROM dns_cache WHERE ip = ANY($1::text[]) AND ("
                "  (name IS NOT NULL AND checked_at > now() - ($2 || ' seconds')::interval)"
                "  OR (name IS NULL AND checked_at > now() - ($3 || ' seconds')::interval))",
                clean, str(int(hit_ttl_s)), str(int(miss_ttl_s)))
        return {r["ip"]: r["name"] for r in rows}

    async def put(self, entries: dict[str, str | None]) -> int:
        """Ergebnisse festhalten — auch die Fehlanzeigen."""
        rows = [(n, entries[ip]) for ip in entries
                if (n := normalize_ip(ip)) is not None]
        if not rows:
            return 0
        async with self._pool.acquire() as conn:
            await conn.executemany(
                "INSERT INTO dns_cache (ip, name) VALUES ($1, $2) "
                "ON CONFLICT (ip) DO UPDATE SET name = EXCLUDED.name, "
                "checked_at = now(), hits = dns_cache.hits + 1", rows)
        return len(rows)

    async def touch(self, ips: list[str]) -> None:
        """Treffer zählen — zeigt später, ob der Cache überhaupt etwas bringt."""
        clean = sorted({n for n in (normalize_ip(i) for i in ips) if n})
        if not clean:
            return
        async with self._pool.acquire() as conn:
            await conn.execute(
                "UPDATE dns_cache SET hits = hits + 1 WHERE ip = ANY($1::text[])", clean)

    async def purge(self, retention_days: int = RETENTION_DAYS) -> int:
        async with self._pool.acquire() as conn:
            result = await conn.execute(
                "DELETE FROM dns_cache WHERE checked_at < now() - ($1 || ' days')::interval",
                str(int(retention_days)))
        return int(result.split()[-1]) if result else 0

    async def stats(self) -> dict:
        async with self._pool.acquire() as conn:
            row = await conn.fetchrow(
                "SELECT count(*) AS total, count(name) AS named, "
                "coalesce(sum(hits), 0) AS hits, min(first_seen) AS oldest "
                "FROM dns_cache")
        return {"total": row["total"], "named": row["named"],
                "misses": row["total"] - row["named"], "hits": int(row["hits"]),
                "oldest": row["oldest"].isoformat() if row["oldest"] else None}


class ReverseResolver:
    """Rückwärtsauflösung mit Cache — eine Stelle für alle Aufrufer.

    `prime` holt alles Bekannte in EINER Abfrage; danach kostet jede bereits
    bekannte Adresse nichts mehr. Was fehlt, wird gefragt und weggeschrieben.
    """

    def __init__(self, cache: DnsCache | None,
                 resolve: Callable[[str], Awaitable[str | None]],
                 hit_ttl_s: int = HIT_TTL_S, miss_ttl_s: int = MISS_TTL_S) -> None:
        self._cache = cache
        self._resolve = resolve
        self._hit_ttl_s = hit_ttl_s
        self._miss_ttl_s = miss_ttl_s
        self._known: dict[str, str | None] = {}
        self._new: dict[str, str | None] = {}
        self._lock = asyncio.Lock()
        self.stats = {"cached": 0, "asked": 0, "found": 0}

    async def prime(self, ips: list[str]) -> None:
        if self._cache is None or not ips:
            return
        try:
            self._known.update(await self._cache.get(ips, self._hit_ttl_s, self._miss_ttl_s))
        except Exception as exc:
            log.warning("DNS-Cache nicht lesbar: %s", exc)

    async def __call__(self, ip: str) -> str | None:
        key = normalize_ip(ip) or ip
        if key in self._known:
            self.stats["cached"] += 1
            return self._known[key]
        self.stats["asked"] += 1
        try:
            name = await self._resolve(ip)
        except Exception:
            return None                      # nicht merken, was nur schiefging
        if name:
            self.stats["found"] += 1
        self._known[key] = name
        async with self._lock:
            self._new[key] = name
        return name

    async def flush(self) -> None:
        """Neu Gelerntes wegschreiben — das Scheitern kostet nur den Cache."""
        if self._cache is None:
            return
        async with self._lock:
            new, self._new = self._new, {}
        try:
            if new:
                await self._cache.put(new)
            hits = [ip for ip in self._known if ip not in new]
            if hits:
                await self._cache.touch(hits)
        except Exception as exc:
            log.warning("DNS-Cache nicht schreibbar: %s", exc)


def _int(cfg: dict, key: str, default: int) -> int:
    """Eine unsinnige Einstellung darf die Auflösung nicht abschalten."""
    try:
        value = int(cfg.get(key, default))
    except (TypeError, ValueError):
        return default
    return value if value >= 0 else default


async def build_reverse(state, dns_cfg: dict):
    """Rückwärtsauflöser für einen Aufruf — mit Cache, wenn es einen gibt.

    Ohne konfigurierte Resolver UND ohne Suchdomains gibt es nichts zu fragen;
    dann liefert der Aufrufer besser gar keinen Namen, statt in jede
    Zeitüberschreitung zu laufen.
    """
    from resolver import dns_source

    if not (dns_cfg.get("resolvers") or dns_cfg.get("search_domains")):
        return None

    async def ask(ip: str) -> str | None:
        hit = await dns_source.resolve_ip(dns_cfg, ip, timeout_s=1.5)
        return hit["name"] if hit else None

    # Null Stunden heißt „nicht cachen" — nicht „alles ist abgelaufen, aber
    # trotzdem fragen": beides führt zum selben Ergebnis, nur kostet das eine
    # zusätzlich eine Datenbankabfrage pro Aufruf.
    hit_days = _int(dns_cfg, "cache_hit_days", 7)
    miss_hours = _int(dns_cfg, "cache_miss_hours", 24)
    cache = getattr(state, "dns_cache", None) if (hit_days or miss_hours) else None
    return ReverseResolver(cache, ask,
                           hit_ttl_s=hit_days * 24 * 3600,
                           miss_ttl_s=miss_hours * 3600)
