"""MAC → Switchport aus der LibreNMS-FDB, inklusive Portklassifikation.

Der Knackpunkt ist nicht das Finden, sondern das Aussortieren: eine MAC steht
auf JEDEM Switch im Pfad in der FDB — dort jeweils auf dem Uplink. Gesucht ist
der eine Port, hinter dem das Gerät wirklich sitzt.

Wichtig dabei: „Port mit vielen MACs" ist NICHT gleichbedeutend mit „falsch".
Eine VM auf einem Hypervisor hängt völlig legitim hinter einem Trunk, auf dem
Dutzende MACs stehen. Was ausgeschlossen werden kann, ist nur der echte
Switch-zu-Switch-Uplink — und genau den erkennt man daran, dass der LLDP-Nachbar
selbst ein überwachtes Gerät ist.

Daraus vier Portklassen:

    access   wenige MACs, kein LLDP-Nachbar          → der Normalfall
    edge     LLDP-Nachbar, aber NICHT überwacht      → Hypervisor, AP, Telefon
    trunk    viele MACs, kein LLDP-Nachbar           → Ring-Uplink ODER ESX-Trunk
    uplink   LLDP-Nachbar IST ein überwachtes Gerät  → sicher nicht hier

Über all dem steht aber der Topologie-Abgleich, und der schlägt jede Heuristik:

    lldp_peer     Der LLDP-Nachbar dieses Ports IST das gesuchte Gerät.
    description   Die Port-Description nennt das Ziel beim Namen
                  (`uplink-bpvo300`, `bpvo049-Head-P24`).

Beim `lldp_peer` ist die Portklasse ausdrücklich egal — für einen Switch als
Suchziel ist die Antwort *immer* ein Uplink, und genau der mit der passenden
Nachbarschaft. Wer das als Uplink aussortiert, wirft die richtige Zeile weg.

Danach erst Aktualität, dann Klasse. Aktualität vor Klasse, weil ein
FDB-Eintrag bei jedem Discovery-Lauf aufgefrischt wird, solange die MAC dort
noch gesehen wird — ein alter Eintrag heißt „die MAC ist von diesem Port
verschwunden".
"""
from __future__ import annotations

import logging
from collections import Counter, defaultdict
from datetime import datetime

from librenms.client import LibrenmsClient, LibrenmsError, LibrenmsNotConfigured
from locate.naming import matches_description, normalize_host

log = logging.getLogger("locate.fdb")

# Bis zu so vielen MACs gilt ein Port ohne LLDP-Nachbarn als Access-Port.
DEFAULT_ACCESS_MAX_MACS = 8
# Älter als das → der Treffer ist eine Vermutung, keine Aussage. LibreNMS
# discovert per Default alle 6 h; ein Eintrag von gestern sagt nichts über jetzt.
DEFAULT_STALE_AFTER_S = 6 * 3600
# Innerhalb dieses Fensters gelten Einträge als gleich frisch. Ohne Bucketing
# würde die Sortierung nach Aktualität gleichwertige Treffer nach ein paar
# Sekunden Versatz zwischen zwei Discovery-Läufen auseinanderreißen.
DEFAULT_RECENCY_BUCKET_S = 3600

# Reihenfolge der Portklassen beim Ranking (kleiner = wahrscheinlicher).
PORT_KIND_RANK = {"access": 0, "edge": 0, "trunk": 1, "unknown": 1, "uplink": 2}

# Topologie-Abgleich schlägt alles andere (kleiner = stärker).
MATCH_RANK = {"lldp_peer": 0, "description": 1, None: 2}

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


def classify_port(has_neighbor: bool, neighbor_monitored: bool,
                  mac_count: int, access_max: int) -> str:
    """Portklasse aus den beiden verfügbaren Signalen — siehe Modul-Docstring."""
    if has_neighbor:
        return "uplink" if neighbor_monitored else "edge"
    if mac_count <= 0:
        return "unknown"          # Anreicherung fehlgeschlagen, nicht „leerer Port"
    return "access" if mac_count <= access_max else "trunk"


def match_target(neighbour: dict, if_alias: str | None, if_descr: str | None,
                 aliases: set[str], self_device_id=None) -> tuple[str | None, str | None]:
    """(match_reason, match_detail) — Topologie-Abgleich gegen das gesuchte Ziel.

    Der LLDP-Treffer läuft über zwei Wege: die device_id, wenn das Ziel selbst
    in LibreNMS steht, und sonst den Hostnamen gegen die Alias-Menge (die auch
    FMG-Objektnamen enthält). So funktioniert es auch für Geräte, die LibreNMS
    gar nicht kennt, deren Nachbar sie aber per LLDP benennt.
    """
    remote_host = normalize_host(neighbour.get("hostname"))
    remote_id = neighbour.get("device_id")
    if self_device_id is not None and remote_id is not None \
            and str(remote_id) == str(self_device_id):
        return "lldp_peer", neighbour.get("label")
    if remote_host and remote_host in aliases:
        return "lldp_peer", neighbour.get("label")

    hit = matches_description(aliases, if_alias, if_descr)
    if hit:
        return "description", if_alias or if_descr
    return None, None


async def candidates(client: LibrenmsClient, cfg: dict, mac: str,
                     warnings: list[str], aliases: set[str] | None = None,
                     self_device_id=None) -> list[dict]:
    """Alle Ports, an denen die MAC gesehen wurde — unsortiert, angereichert."""
    aliases = aliases or set()
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
    access_max = int(cfg.get("access_max_macs", DEFAULT_ACCESS_MAX_MACS))
    bucket_s = max(1, int(cfg.get("recency_bucket_s", DEFAULT_RECENCY_BUCKET_S)))

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
            nb = neighbours.get(pid_int) or {}
            mac_count = counts.get(pid, 0)
            kind = classify_port(bool(nb), bool(nb.get("monitored")), mac_count, access_max)
            if_alias = port.get("ifAlias") or None
            reason, detail = match_target(
                nb, if_alias, port.get("ifDescr"), aliases, self_device_id
            )
            out.append({
                "device_id": int(device_id) if device_id.isdigit() else device_id,
                "hostname": dev.get("hostname"),
                "sys_name": dev.get("sysName"),
                "port_id": pid_int,
                "if_name": port.get("ifName") or port.get("ifDescr"),
                "if_alias": if_alias,
                "if_descr": port.get("ifDescr"),
                "oper_status": port.get("ifOperStatus"),
                "vlan_id": row.get("vlan_id"),
                "mac_count": mac_count,
                "port_kind": kind,
                "match_reason": reason,
                "match_detail": detail,
                "has_neighbor": bool(nb),
                "neighbor": nb.get("label"),
                "neighbor_monitored": bool(nb.get("monitored")),
                "updated_at": row.get("updated_at"),
                "age_s": age,
                "age_bucket": (age // bucket_s) if age is not None else 10**6,
                "stale": age is not None and age > stale_after,
            })
    return out


def rank(cands: list[dict]) -> list[dict]:
    """Bester Kandidat zuerst.

    Reihenfolge der Kriterien: Topologie-Abgleich, Aktualität, Portklasse,
    MAC-Zahl. Der Abgleich steht vorn, weil er kein Indiz, sondern eine Aussage
    ist — sagt LLDP „an diesem Port hängt genau das gesuchte Gerät", gibt es
    nichts mehr abzuwägen. Insbesondere ist die Portklasse dann irrelevant: für
    einen Switch als Suchziel IST die Antwort ein Uplink.

    Aktualität vor Portklasse, weil ein FDB-Eintrag bei jedem Discovery-Lauf
    aufgefrischt wird, solange die MAC dort noch steht — ein alter Eintrag heißt
    „von diesem Port verschwunden". Gebucketet, damit gleich frische Treffer
    nicht durch Sekunden Versatz zwischen zwei Läufen auseinanderfallen.

    `mac_count == 0` heißt „nicht ermittelbar", nicht „leerer Port" — solche
    Kandidaten dürfen nicht nach vorn rutschen.
    """
    def key(c: dict) -> tuple:
        count = c["mac_count"] if c["mac_count"] > 0 else 10**6
        return (
            MATCH_RANK.get(c.get("match_reason"), 2),
            c.get("age_bucket", 0),
            PORT_KIND_RANK.get(c.get("port_kind", "unknown"), 1),
            count,
            c["age_s"] if c["age_s"] is not None else 10**9,
        )

    return sorted(cands, key=key)


def confidence(ranked: list[dict], cfg: dict) -> str:
    """high | medium | low | none — wie sehr man dem ersten Treffer glauben darf."""
    if not ranked:
        return "none"
    best = ranked[0]
    kind = best.get("port_kind", "unknown")
    reason = best.get("match_reason")

    if reason == "lldp_peer":
        # Topologie-Aussage, keine Heuristik.
        level = "high"
    elif reason == "description":
        # Namenskonventionen können lügen; auf einem plausiblen Port reicht es.
        level = "high" if kind != "uplink" else "medium"
    elif kind == "uplink":
        # Nur echte Switch-zu-Switch-Uplinks: der Zugangsswitch fehlt in LibreNMS.
        level = "low"
    elif kind == "access":
        level = "high"
    else:
        # edge (Hypervisor/AP am LLDP) und trunk sind plausibel, aber nicht eindeutig.
        level = "medium"

    if best["stale"] and level != "low":
        level = "medium" if level == "high" else "low"
    return level
