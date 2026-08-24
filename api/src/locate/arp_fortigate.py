"""ARP-Quelle 1: die FortiGate selbst, live über den FMG-Proxy.

An den meisten Standorten ist die FortiGate der L3-Router — sie hält damit die
ARP-Tabelle für alle VLANs. Welche FortiGate/VDOM zuständig ist, beantwortet
die PrefixTable; das ist dieselbe Logik, die das Werkzeug „Netz-Zugehörigkeit"
anzeigt. `lookup_owner` statt `lookup`, weil uns der connected-Ursprung
interessiert und nicht bloß irgendeine Route dorthin.

ASSUMPTION (nicht am Lab verifiziert): der Monitor-Endpunkt heißt in FortiOS
7.x `network/arp`. Ältere Builds kennen ihn womöglich nicht. Diese Quelle wirft
deshalb nicht, sondern liefert None und schreibt eine Warnung — die Kette fällt
dann auf LibreNMS zurück, statt die ganze Suche zu verlieren.
"""
from __future__ import annotations

import logging

from config import Config
from fmg.client import FmgError, FmgTargetOffline
from fmg.factory import build_fmg_client
from fmg.proxy import fortios_results, monitor_get
from inventory.prefixes import PrefixTable
from locate.mac import normalize_mac

log = logging.getLogger("locate.arp_fortigate")

# In dieser Reihenfolge probiert; der erste Endpunkt, der antwortet, gewinnt.
ARP_PATHS = ("network/arp", "system/arp")

_IP_KEYS = ("ip", "address", "ip_address")
_MAC_KEYS = ("mac", "mac_address", "hwaddr", "hardware_address")
_IF_KEYS = ("interface", "intf", "ifname", "name")


def _first(row: dict, keys: tuple[str, ...]) -> str | None:
    for k in keys:
        val = row.get(k)
        if val:
            return str(val).strip()
    return None


def _find_ip(rows, ip: str) -> dict | None:
    for row in rows if isinstance(rows, list) else []:
        if not isinstance(row, dict):
            continue
        if _first(row, _IP_KEYS) == ip:
            return row
    return None


async def fetch_table(client, adom: str, device: str, vdom: str,
                      warnings: list[str]) -> list[dict] | None:
    """Komplette ARP-Tabelle eines VDOMs (Rohzeilen) oder None.

    Der Monitor-Endpunkt liefert ohnehin die ganze Tabelle — die Einzelsuche
    filtert sie nur clientseitig. Deshalb ist ein Sweep über alle VDOMs
    derselbe Aufruf und kostet nichts extra.
    """
    for path in ARP_PATHS:
        try:
            resp = await monitor_get(client, adom, device, vdom, path)
        except FmgTargetOffline as exc:
            warnings.append(f"{device} nicht erreichbar: {exc}")
            return None
        except FmgError as exc:
            log.info("ARP-Endpunkt %s auf %s nicht nutzbar: %s", path, device, exc)
            continue
        rows = fortios_results(resp)
        return rows if isinstance(rows, list) else []
    warnings.append(
        f"{device} kennt keinen ARP-Monitor-Endpunkt "
        f"({', '.join(ARP_PATHS)}) — FortiOS-Version zu alt?"
    )
    return None


def observations(rows, device: str, vdom: str,
                 default_interface: str | None = None) -> list[dict]:
    """ARP-Rohzeilen → IP↔MAC-Beobachtungen für die Historie."""
    out: list[dict] = []
    for row in rows if isinstance(rows, list) else []:
        if not isinstance(row, dict):
            continue
        ip = _first(row, _IP_KEYS)
        mac = normalize_mac(_first(row, _MAC_KEYS) or "")
        if not ip or not mac:
            continue
        out.append({
            "ip": ip, "mac": mac, "device": device, "vdom": vdom,
            "interface": _first(row, _IF_KEYS) or default_interface,
            "source": "fortigate",
        })
    return out


async def resolve(ip: str, prefixes: PrefixTable, fmg_cfg: dict,
                  app_cfg: Config, warnings: list[str],
                  seen: list[dict] | None = None) -> dict | None:
    """IP → {mac, device, vdom, interface} aus der Live-ARP-Tabelle, sonst None.

    `seen` (optional) sammelt ALLE Zeilen der abgerufenen Tabelle als
    Beobachtungen ein. Die Antwort enthält sie ohnehin — so füllt jede
    Einzelsuche nebenbei die Historie des ganzen VDOMs.
    """
    entry = prefixes.lookup_owner(ip)
    if entry is None:
        warnings.append(
            f"Für {ip} ist kein connected-Netz im FMG-Snapshot bekannt — "
            "die FortiGate konnte nicht nach ARP gefragt werden."
        )
        return None
    if not fmg_cfg.get("host") and not fmg_cfg.get("fixture_mode"):
        return None

    try:
        client = build_fmg_client(fmg_cfg, app_cfg)
    except Exception as exc:                       # HTTPException aus der Factory
        warnings.append(f"FortiManager nicht verfügbar: {exc}")
        return None

    adom = entry.adom or "root"
    try:
        rows = await fetch_table(client, adom, entry.device, entry.vdom, warnings)
        if rows is None:
            return None
        if seen is not None:
            seen.extend(observations(rows, entry.device, entry.vdom, entry.interface))
        row = _find_ip(rows, ip)
        if row is None:
            warnings.append(
                f"{ip} steht nicht in der ARP-Tabelle von {entry.device}/{entry.vdom} — "
                "das Gerät ist vermutlich still. Einmal anpingen und erneut suchen."
            )
            return None
        mac = normalize_mac(_first(row, _MAC_KEYS))
        if mac is None:
            warnings.append(f"ARP-Eintrag von {entry.device} ohne verwertbare MAC.")
            return None
        return {
            "mac": mac,
            "provenance": "fortigate",
            "device": entry.device,
            "vdom": entry.vdom,
            "interface": _first(row, _IF_KEYS) or entry.interface,
        }
    finally:
        await client.close()
