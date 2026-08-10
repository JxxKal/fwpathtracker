"""MAC → Switchport aus der LibreNMS-FDB, inklusive Uplink-Erkennung.

Der Knackpunkt ist nicht das Finden, sondern das Aussortieren: eine MAC steht
auf JEDEM Switch im Pfad in der FDB — überall auf dem Uplink-Port. Gesucht ist
der eine Access-Port, an dem das Gerät wirklich steckt.

Zwei unabhängige Signale trennen das:

1. LLDP/CDP-Nachbar am Port  → per Definition ein Uplink. Hartes Signal, aber
   nur vorhanden, wenn auf dem Ring/Trunk auch LLDP läuft.
2. Anzahl MACs am Port       → ein Access-Port trägt eine Handvoll, ein
   Ring-Uplink Hunderte. Weiches Signal, dafür immer verfügbar.

Die beiden ergänzen sich: MOXA-Ringe fahren oft ohne LLDP, dort ist die
MAC-Zahl brutal eindeutig (~180 gegen ~3).
"""
from __future__ import annotations

import logging
from collections import Counter, defaultdict
from datetime import datetime

from librenms.client import LibrenmsClient, LibrenmsError, LibrenmsNotConfigured

log = logging.getLogger("locate.fdb")

# Ab so vielen MACs an einem Port gilt er nicht mehr als Access-Port.
DEFAULT_ACCESS_MAX_MACS = 8
# Älter als das → der Treffer ist eine Vermutung, keine Aussage. LibreNMS
# discovert per Default alle 6 h; ein Eintrag von gestern sagt nichts über jetzt.
DEFAULT_STALE_AFTER_S = 6 * 3600

_TS_FORMATS = ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%dT%H:%M:%S%z")


def _parse_ts(value) -> datetime | None:
    if not value:
        return None
    raw = str(value).strip().replace("Z", "+0000")
    for fmt in _TS_FORMATS:
        try:
            return datetime.strptime(raw, fmt)
        except ValueError:
            continue
    try:
        return datetime.fromisoformat(raw)
    except ValueError:
        return None


def _age_s(ts: datetime | None) -> int | None:
    """Alter in Sekunden.

    LibreNMS liefert `updated_at` naiv in der Zeitzone seines Containers. Wir
    vergleichen deshalb naiv gegen die lokale Zeit — beide Stacks laufen mit
    derselben TZ. Geht das doch einmal auseinander, wird das Alter negativ;
    das klemmen wir auf 0, damit Uhren-Versatz nicht als frischer Treffer
    ausgewiesen wird, aber auch keinen falschen Stale-Alarm auslöst.
    """
    if ts is None:
        return None
    now = datetime.now(tz=ts.tzinfo) if ts.tzinfo else datetime.now()
    return max(0, int((now - ts).total_seconds()))


async def candidates(client: LibrenmsClient, cfg: dict, mac: str,
                     warnings: list[str]) -> list[dict]:
    """Alle Ports, an denen die MAC gesehen wurde — unsortiert, angereichert."""
    try:
        rows = await client.fdb(cfg, mac)
    except LibrenmsNotConfigured:
        warnings.append("LibreNMS ist nicht konfiguriert — keine Portsuche möglich.")
        return []
    except Exception as exc:
        warnings.append(f"LibreNMS-FDB-Abfrage fehlgeschlagen: {exc}")
        return []

    if not rows:
        return []

    try:
        neighbours = await client.neighbours(cfg)
    except Exception as exc:
        # Ohne LLDP funktioniert das Ranking weiter, nur schlechter.
        log.info("LLDP-Nachbarn nicht abrufbar: %s", exc)
        warnings.append(
            "LLDP-Nachbarn konnten nicht geladen werden — "
            "Uplink-Erkennung stützt sich nur auf die MAC-Anzahl."
        )
        neighbours = {}

    stale_after = int(cfg.get("stale_after_s", DEFAULT_STALE_AFTER_S))

    by_device: dict[str, list[dict]] = defaultdict(list)
    for row in rows:
        if row.get("device_id") is None or row.get("port_id") in (None, 0):
            continue
        by_device[str(row["device_id"])].append(row)

    out: list[dict] = []
    for device_id, drows in by_device.items():
        try:
            dev = await client.device(cfg, device_id)
            ports = {str(p.get("port_id")): p for p in await client.device_ports(cfg, device_id)}
            counts = Counter(
                str(r.get("port_id")) for r in await client.device_fdb(cfg, device_id)
            )
        except (LibrenmsError, Exception) as exc:
            warnings.append(f"Gerät {device_id} konnte nicht angereichert werden: {exc}")
            dev, ports, counts = {}, {}, Counter()

        for row in drows:
            pid = str(row.get("port_id"))
            port = ports.get(pid, {})
            ts = _parse_ts(row.get("updated_at"))
            age = _age_s(ts)
            try:
                pid_int = int(pid)
            except ValueError:
                pid_int = -1
            out.append({
                "device_id": int(device_id) if device_id.isdigit() else device_id,
                "hostname": dev.get("hostname"),
                "sys_name": dev.get("sysName"),
                "port_id": pid_int,
                "if_name": port.get("ifName") or port.get("ifDescr"),
                "if_alias": port.get("ifAlias") or None,
                "if_descr": port.get("ifDescr"),
                "oper_status": port.get("ifOperStatus"),
                "vlan_id": row.get("vlan_id"),
                "mac_count": counts.get(pid, 0),
                "has_neighbor": pid_int in neighbours,
                "neighbor": neighbours.get(pid_int),
                "updated_at": row.get("updated_at"),
                "age_s": age,
                "stale": age is not None and age > stale_after,
            })
    return out


def rank(cands: list[dict]) -> list[dict]:
    """Bester Kandidat zuerst: kein Nachbar, wenige MACs, zuletzt gesehen.

    `mac_count == 0` heißt „nicht ermittelbar" (Anreicherung fehlgeschlagen),
    nicht „leerer Port" — solche Kandidaten dürfen nicht nach vorn rutschen und
    werden wie ein mittelgroßer Port behandelt.
    """
    def key(c: dict) -> tuple:
        count = c["mac_count"] if c["mac_count"] > 0 else 10**6
        return (
            1 if c["has_neighbor"] else 0,
            count,
            c["age_s"] if c["age_s"] is not None else 10**9,
        )

    return sorted(cands, key=key)


def confidence(ranked: list[dict], cfg: dict) -> str:
    """high | medium | low | none — wie sehr man dem ersten Treffer glauben darf."""
    if not ranked:
        return "none"
    best = ranked[0]
    access_max = int(cfg.get("access_max_macs", DEFAULT_ACCESS_MAX_MACS))

    if best["has_neighbor"]:
        # Nur Uplinks gefunden: der Zugangsswitch fehlt in LibreNMS.
        level = "low"
    elif 0 < best["mac_count"] <= access_max:
        level = "high"
    else:
        level = "medium"

    if best["stale"] and level != "low":
        level = "medium" if level == "high" else "low"
    return level
