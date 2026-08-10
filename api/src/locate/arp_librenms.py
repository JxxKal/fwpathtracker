"""ARP-Quelle 2: LibreNMS `ipv4_mac`.

Greift an den Standorten, wo nicht die FortiGate routet, sondern ein
HPE-Stack — die stehen ohnehin in LibreNMS. Dient außerdem als Auffangnetz,
wenn der Live-Weg über den FMG-Proxy nicht funktioniert (Gerät offline,
Endpunkt fehlt).

Anders als die FortiGate-Quelle ist das ein Poll-Ergebnis, kein Live-Blick:
der Eintrag kann veraltet sein. Deshalb wird die Herkunft mitgeliefert und im
UI angezeigt.
"""
from __future__ import annotations

import logging

from librenms.client import LibrenmsClient, LibrenmsError, LibrenmsNotConfigured
from locate.mac import normalize_mac

log = logging.getLogger("locate.arp_librenms")


async def resolve(client: LibrenmsClient, cfg: dict, ip: str,
                  warnings: list[str]) -> dict | None:
    """IP → {mac, device, interface} aus der gepollten ARP-Tabelle, sonst None."""
    try:
        rows = await client.arp(cfg, ip)
    except LibrenmsNotConfigured:
        return None
    except (LibrenmsError, Exception) as exc:      # httpx-Fehler eingeschlossen
        warnings.append(f"LibreNMS-ARP für {ip} fehlgeschlagen: {exc}")
        return None

    for row in rows:
        if str(row.get("ipv4_address") or "").strip() != ip:
            continue
        mac = normalize_mac(row.get("mac_address"))
        if mac is None:
            continue
        device, interface = None, None
        port_id = row.get("port_id")
        if port_id:
            # Nur Provenance ("ARP kam von sw-core / Vlan42") — darf scheitern.
            try:
                port = await client.port(cfg, port_id)
                interface = port.get("ifName") or port.get("ifDescr")
                if port.get("device_id"):
                    dev = await client.device(cfg, port["device_id"])
                    device = dev.get("hostname") or dev.get("sysName")
            except Exception as exc:
                log.info("Provenance für ARP-Port %s nicht ermittelbar: %s", port_id, exc)
        return {
            "mac": mac,
            "provenance": "librenms",
            "device": device,
            "vdom": None,
            "interface": interface,
        }
    return None
