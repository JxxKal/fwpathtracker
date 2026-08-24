"""IP↔MAC-Historie: was ARP vergisst, sobald ein Host schweigt.

Die Switchport-Suche scheitert bei einem abgeschalteten Host nicht am Port —
LibreNMS hält dessen FDB-Eintrag noch tagelang vor (`ports_fdb_purge`, Default
10 Tage). Sie scheitert eine Stufe früher: Ohne IP→MAC kommt die Kette dort nie
an. Die FortiGate wirft ARP-Einträge nach Minuten weg, und LibreNMS gleicht
seine `ipv4_mac`-Tabelle bei jeder Discovery mit dem Gerät ab. Beide Quellen
kennen nur die Gegenwart.

Deshalb hier: ein Eintrag je (ip, mac) mit dem Zeitraum, in dem die Bindung
gesehen wurde. Mehrere MACs an derselben IP sind kein Widerspruch, sondern der
Verlauf — nach einem Gerätetausch hängt dort eben eine andere.

Die Klasse kapselt allen SQL-Zugriff, damit die Locate-Kette gegen eine
Attrappe testbar bleibt: sie bekommt den Speicher übergeben und kennt nur diese
vier Methoden.
"""
from __future__ import annotations

import ipaddress
import logging
from datetime import datetime, timezone

import asyncpg

from locate.mac import normalize_mac

log = logging.getLogger("locate.arp_store")


def normalize_ip(ip: str) -> str | None:
    """Kanonische IPv4-Schreibweise, sonst None (führende Nullen o.ä.)."""
    try:
        return str(ipaddress.IPv4Address(str(ip).strip()))
    except (ipaddress.AddressValueError, ValueError):
        return None


def age_s(ts: datetime | None) -> int | None:
    """Alter in Sekunden. Die DB liefert tz-bewusste Zeitstempel (timestamptz)."""
    if ts is None:
        return None
    now = datetime.now(tz=ts.tzinfo) if ts.tzinfo else datetime.now()
    return max(0, int((now - ts).total_seconds()))


def row_to_binding(row) -> dict:
    """DB-Zeile → Bindung fürs API-Ergebnis (JSON-serialisierbar)."""
    last = row["last_seen"]
    return {
        "ip": row["ip"],
        "mac": row["mac"],
        "device": row["device"],
        "vdom": row["vdom"],
        "interface": row["interface"],
        "source": row["source"],
        "first_seen": row["first_seen"].isoformat() if row["first_seen"] else None,
        "last_seen": last.isoformat() if last else None,
        "age_s": age_s(last),
        "seen_count": row["seen_count"],
    }


class ArpStore:
    """Persistente IP↔MAC-Bindungen (Tabelle arp_history)."""

    def __init__(self, pool: asyncpg.Pool) -> None:
        self._pool = pool

    async def record(self, observations: list[dict]) -> int:
        """Beobachtungen einpflegen (Upsert je (ip, mac)).

        `last_seen` wird hochgesetzt, `first_seen` NICHT angefasst — sonst ginge
        genau die Information verloren, seit wann die Bindung besteht. Gerät und
        Interface werden mitgeführt, weil sie beim nächsten Mal anders sein
        können (Host umgezogen) und dann die neuere Angabe gilt.
        """
        rows = []
        for obs in observations:
            ip = normalize_ip(obs.get("ip") or "")
            mac = normalize_mac(obs.get("mac") or "")
            if not ip or not mac:
                continue
            rows.append((ip, mac, obs.get("device"), obs.get("vdom"),
                         obs.get("interface"), obs.get("source") or "unknown"))
        if not rows:
            return 0
        async with self._pool.acquire() as conn:
            await conn.executemany(
                """
                INSERT INTO arp_history (ip, mac, device, vdom, interface, source)
                VALUES ($1, $2, $3, $4, $5, $6)
                ON CONFLICT (ip, mac) DO UPDATE SET
                    last_seen  = now(),
                    seen_count = arp_history.seen_count + 1,
                    device     = COALESCE(EXCLUDED.device, arp_history.device),
                    vdom       = COALESCE(EXCLUDED.vdom, arp_history.vdom),
                    interface  = COALESCE(EXCLUDED.interface, arp_history.interface),
                    source     = EXCLUDED.source
                """,
                rows,
            )
        return len(rows)

    async def by_ip(self, ip: str, limit: int = 20) -> list[dict]:
        """Alle je gesehenen MACs dieser IP, zuletzt gesehene zuerst."""
        norm = normalize_ip(ip)
        if norm is None:
            return []
        async with self._pool.acquire() as conn:
            rows = await conn.fetch(
                "SELECT * FROM arp_history WHERE ip = $1 "
                "ORDER BY last_seen DESC LIMIT $2", norm, limit)
        return [row_to_binding(r) for r in rows]

    async def by_mac(self, mac: str, limit: int = 20) -> list[dict]:
        """Alle je gesehenen IPs dieser MAC, zuletzt gesehene zuerst."""
        norm = normalize_mac(mac)
        if not norm:
            return []
        async with self._pool.acquire() as conn:
            rows = await conn.fetch(
                "SELECT * FROM arp_history WHERE mac = $1 "
                "ORDER BY last_seen DESC LIMIT $2", norm, limit)
        return [row_to_binding(r) for r in rows]

    async def purge(self, retention_days: int) -> int:
        """Bindungen löschen, die länger als `retention_days` nicht gesehen wurden."""
        if retention_days <= 0:
            return 0
        async with self._pool.acquire() as conn:
            res = await conn.execute(
                "DELETE FROM arp_history WHERE last_seen < now() - ($1 || ' days')::interval",
                str(int(retention_days)))
        return int(res.rsplit(" ", 1)[-1]) if res else 0

    async def stats(self) -> dict:
        async with self._pool.acquire() as conn:
            row = await conn.fetchrow(
                "SELECT count(*) AS bindings, count(DISTINCT mac) AS macs, "
                "count(DISTINCT ip) AS ips, max(last_seen) AS newest, "
                "min(first_seen) AS oldest FROM arp_history")
        return {
            "bindings": row["bindings"], "macs": row["macs"], "ips": row["ips"],
            "newest": row["newest"].isoformat() if row["newest"] else None,
            "oldest": row["oldest"].isoformat() if row["oldest"] else None,
        }
