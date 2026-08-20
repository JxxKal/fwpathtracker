"""Globale VLAN-Übersicht: welche VLAN-Nummer ist wofür vergeben — und was ist frei.

Zwei Quellen, die jeweils die Hälfte wissen:

    LibreNMS    Switch-Sicht  — auf welchen Switches ein VLAN konfiguriert ist
                               und wie es dort heißt (`vlan_vlan`, `vlan_name`).
    FortiGate   L3-Sicht      — welches Interface das VLAN terminiert, mit
                               Subnetz, Zone und Alias (aus dem FMG-Inventar).

Zusammengeführt wird über die VLAN-NUMMER, nicht über Namen: Namen weichen
zwischen Switch und Firewall regelmäßig ab, die Nummer ist die Konstante. Fällt
eine Quelle aus (LibreNMS nicht konfiguriert, FMG-Sync leer), bleibt die andere
stehen — die Übersicht ist dann unvollständig und sagt das auch.

„Frei" heißt hier ausdrücklich: in KEINER der beiden Quellen gesehen. Das ist
eine Aussage über den bekannten Bestand, keine Reservierungs-Datenbank — ein
VLAN, das nur auf einem nicht überwachten Switch existiert, sieht hier frei aus.
"""
from __future__ import annotations

import logging

from inventory.store import Inventory
from librenms.client import LibrenmsClient, LibrenmsNotConfigured

log = logging.getLogger("vlan.overview")

VLAN_MIN, VLAN_MAX = 1, 4094


def _vlan_num(row: dict) -> int | None:
    """VLAN-Nummer aus einer LibreNMS-Zeile (`vlan_vlan`), robust gegen Strings.

    None heißt: nicht als VLAN-Nummer verwertbar (leer, keine Zahl, außerhalb
    1–4094). Solche Zeilen dürfen NICHT stillschweigend verschwinden — sonst
    fehlt ein VLAN in der Übersicht, ohne dass irgendwo steht warum. Der Aufrufer
    zählt sie und weist sie aus. Praktischer Fall: Geräte, die 0 melden (MOXA
    macht das in der FDB, siehe docs/wiki/LibreNMS-MOXA-FDB.md).
    """
    raw = row.get("vlan_vlan")
    if raw is None:
        return None
    try:
        num = int(str(raw).strip())
    except (TypeError, ValueError):
        return None
    return num if VLAN_MIN <= num <= VLAN_MAX else None


def free_ranges(used: set[int], lo: int = VLAN_MIN, hi: int = VLAN_MAX) -> list[list[int]]:
    """Nicht belegte VLAN-IDs als zusammenhängende [von, bis]-Bereiche."""
    out: list[list[int]] = []
    start: int | None = None
    for num in range(lo, hi + 2):          # ein Schritt über hi hinaus schließt den Lauf
        if num <= hi and num not in used:
            if start is None:
                start = num
        elif start is not None:
            out.append([start, num - 1])
            start = None
    return out


async def build(inv: Inventory, client: LibrenmsClient, librenms_cfg: dict) -> dict:
    """VLAN-Tabelle (Nummer → Namen, Switches, Firewall-Interfaces) + freie Nummern."""
    warnings: list[str] = []
    rows: dict[int, dict] = {}

    def row(num: int) -> dict:
        return rows.setdefault(num, {
            "vlan": num, "names": [], "networks": [],
            "switches": [], "firewall_interfaces": [],
        })

    # ── LibreNMS: Switch-Sicht ───────────────────────────────────────────────
    librenms_ok = False
    try:
        vlan_rows = await client.vlans(librenms_cfg)
        librenms_ok = True
    except LibrenmsNotConfigured:
        vlan_rows = []
        warnings.append(
            "LibreNMS ist nicht konfiguriert — die Übersicht zeigt nur die "
            "VLAN-Interfaces der Firewalls, nicht die Switch-Seite."
        )
    except Exception as exc:
        vlan_rows = []
        log.info("LibreNMS-VLANs nicht abrufbar: %s", exc)
        warnings.append(f"LibreNMS-VLANs konnten nicht geladen werden: {exc}")

    device_names: dict[str, str] = {}
    known_devices = 0
    if vlan_rows:
        try:
            index = await client.device_index(librenms_cfg)
            for dev in index.values():
                did = str(dev.get("device_id"))
                device_names[did] = dev.get("hostname") or dev.get("sysName") or did
            known_devices = len(device_names)
        except Exception as exc:      # Namen sind Kür, die Nummern sind Pflicht
            log.info("Geräteindex nicht abrufbar: %s", exc)

    skipped: list[dict] = []
    contributing: set[str] = set()
    for r in vlan_rows:
        num = _vlan_num(r)
        did = str(r.get("device_id"))
        if num is None:
            skipped.append({"device_id": r.get("device_id"),
                            "hostname": device_names.get(did),
                            "vlan_vlan": r.get("vlan_vlan"),
                            "vlan_name": r.get("vlan_name")})
            continue
        contributing.add(did)
        entry = row(num)
        name = (r.get("vlan_name") or "").strip()
        if name and name not in entry["names"]:
            entry["names"].append(name)
        entry["switches"].append({
            "device_id": r.get("device_id"),
            "hostname": device_names.get(did),
            "name": name or None,
            "domain": r.get("vlan_domain"),
        })

    if skipped:
        values = sorted({str(s0["vlan_vlan"]) for s0 in skipped})[:6]
        hosts = sorted({s0["hostname"] or str(s0["device_id"]) for s0 in skipped})[:6]
        warnings.append(
            f"{len(skipped)} VLAN-Zeile(n) aus LibreNMS ohne verwertbare Nummer "
            f"übersprungen (Werte: {', '.join(values)}; Geräte: {', '.join(hosts)}) "
            "— gültig ist 1–4094. Meldet ein Switch 0 oder leer, fehlt das VLAN "
            "hier zwangsläufig."
        )

    # ── FortiGate: L3-Sicht aus dem FMG-Inventar ─────────────────────────────
    fw_interfaces = inv.vlan_interfaces()
    if not fw_interfaces and not inv.devices:
        warnings.append("Kein FMG-Inventar vorhanden — bitte zuerst einen Sync ausführen.")
    for intf in fw_interfaces:
        entry = row(intf["vlan"])
        entry["firewall_interfaces"].append(intf)
        label = intf.get("alias") or intf.get("description")
        if label and label not in entry["names"]:
            entry["names"].append(label)
        for net in filter(None, [intf.get("network"), *intf.get("secondary_networks", [])]):
            if net not in entry["networks"]:
                entry["networks"].append(net)

    for entry in rows.values():
        entry["switch_count"] = len(entry["switches"])
        # Ein VLAN, das nur die Firewall kennt, ist ein anderer Befund als eines,
        # das nur auf Switches steht — sichtbar machen statt verrechnen.
        entry["sources"] = sorted(
            ({"librenms"} if entry["switches"] else set())
            | ({"fmg"} if entry["firewall_interfaces"] else set())
        )

    used = set(rows)
    return {
        "vlans": [rows[n] for n in sorted(rows)],
        "free": free_ranges(used),
        "used_count": len(used),
        "free_count": (VLAN_MAX - VLAN_MIN + 1) - len(used),
        "range": [VLAN_MIN, VLAN_MAX],
        "sources": {"librenms": librenms_ok, "fmg": bool(inv.devices)},
        # Herkunfts-Bilanz: Fehlt ein VLAN, ist die erste Frage, ob sein Switch
        # überhaupt VLANs geliefert hat. LibreNMS gibt in `list_vlans` nur die
        # `vlans`-Tabelle zurück (gefiltert auf vlan_vlan IS NOT NULL und auf die
        # Geräte-Rechte des Tokens) — ein Gerät ohne VLAN-Discovery oder ohne
        # Leserecht taucht schlicht nicht auf, und das ist von außen nicht von
        # 'VLAN existiert nicht' zu unterscheiden.
        "stats": {
            "librenms_rows": len(vlan_rows),
            "librenms_skipped": len(skipped),
            "librenms_devices": len(contributing),
            "librenms_devices_known": known_devices,
            "contributing_devices": sorted(
                filter(None, (device_names.get(d, d) for d in contributing))
            )[:100],
            "fmg_interfaces": len(fw_interfaces),
        },
        "synced_at": inv.synced_at,
        "warnings": warnings,
    }
