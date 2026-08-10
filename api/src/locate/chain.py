"""Locate-Kette: IP → MAC → Switchport, mit Provenance und Konfidenz.

Zwei Systeme, jedes für das, was es tatsächlich weiß:

    IP → MAC        FortiGate live (FMG-Proxy), sonst LibreNMS-ARP
    MAC → Port      LibreNMS-FDB

Der ARP-Teil kommt bewusst zuerst von der FortiGate: sie ist an fast allen
Standorten der L3-Router und damit die einzige Stelle, die ARP für alle VLANs
hält. LibreNMS springt ein, wo ein HPE-Stack routet — und als Auffangnetz,
wenn der Live-Weg klemmt.
"""
from __future__ import annotations

import logging

from cachetools import TTLCache

from config import Config
from inventory.prefixes import PrefixTable
from librenms.client import LibrenmsClient
from locate import arp_fortigate, arp_librenms, fdb_librenms
from locate.mac import normalize_mac, readable_mac

log = logging.getLogger("locate.chain")


class LocateChain:
    def __init__(self, ttl_s: int = 60) -> None:
        self.librenms = LibrenmsClient()
        # Kurzer Cache: Doppelklicks und Re-Renders sollen keine neue
        # Live-Abfrage gegen FortiGate und LibreNMS auslösen.
        self._cache: TTLCache = TTLCache(maxsize=512, ttl=ttl_s)

    async def locate(self, ip: str, prefixes: PrefixTable, librenms_cfg: dict,
                     fmg_cfg: dict, app_cfg: Config) -> dict:
        cached = self._cache.get(ip)
        if cached is not None:
            return cached
        result = await self._locate(ip, prefixes, librenms_cfg, fmg_cfg, app_cfg)
        self._cache[ip] = result
        return result

    async def _locate(self, ip: str, prefixes: PrefixTable, librenms_cfg: dict,
                      fmg_cfg: dict, app_cfg: Config) -> dict:
        warnings: list[str] = []

        arp = await arp_fortigate.resolve(ip, prefixes, fmg_cfg, app_cfg, warnings)
        if arp is None:
            arp = await arp_librenms.resolve(self.librenms, librenms_cfg, ip, warnings)

        if arp is None:
            warnings.append(
                f"Für {ip} ließ sich keine MAC-Adresse ermitteln — weder über die "
                "FortiGate noch über LibreNMS. Ohne MAC ist keine Portsuche möglich."
            )
            return {
                "ip": ip, "mac": None, "mac_readable": None, "arp": None,
                "best": None, "candidates": [], "confidence": "none",
                "warnings": warnings,
            }

        mac = normalize_mac(arp["mac"])
        cands = await fdb_librenms.candidates(self.librenms, librenms_cfg, mac, warnings)
        ranked = fdb_librenms.rank(cands)
        conf = fdb_librenms.confidence(ranked, librenms_cfg)

        if not ranked:
            warnings.append(
                f"MAC {readable_mac(mac)} steht in keiner FDB-Tabelle in LibreNMS. "
                "Entweder ist der Zugangsswitch nicht eingebunden, oder seine "
                "FDB-Discovery liefert nichts (bei MOXA siehe Wiki-Seite)."
            )
        elif conf == "low" and all(c["has_neighbor"] for c in ranked):
            warnings.append(
                "Die MAC wurde ausschließlich auf Uplink-Ports gesehen — der "
                "Switch, an dem das Gerät wirklich hängt, fehlt in LibreNMS."
            )

        best = ranked[0] if ranked else None
        if best is not None and best["stale"]:
            warnings.append(
                f"Der Treffer ist {best['age_s'] // 60} Minuten alt. FDB-Einträge "
                "altern mit dem Discovery-Intervall — vor einer Entscheidung "
                "einmal frisch discovern lassen."
            )

        return {
            "ip": ip,
            "mac": mac,
            "mac_readable": readable_mac(mac),
            "arp": {
                "provenance": arp["provenance"],
                "device": arp.get("device"),
                "vdom": arp.get("vdom"),
                "interface": arp.get("interface"),
            },
            "best": best,
            "candidates": ranked,
            "confidence": conf,
            "warnings": warnings,
        }
