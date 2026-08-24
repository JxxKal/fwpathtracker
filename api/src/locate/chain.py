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
from locate.naming import build_aliases, is_mac_like

log = logging.getLogger("locate.chain")


def _when(last_seen: str | None, age_s: int | None) -> str:
    """Lesbare Altersangabe für Cache-Treffer — Datum UND Abstand, weil das eine
    ohne das andere schwer einzuordnen ist."""
    if age_s is None:
        return last_seen or "unbekannten Zeitpunkt"
    if age_s < 5400:
        rel = f"vor {max(1, age_s // 60)} min"
    elif age_s < 172800:
        rel = f"vor {age_s // 3600} h"
    else:
        rel = f"vor {age_s // 86400} Tagen"
    return f"{last_seen} ({rel})" if last_seen else rel


class LocateChain:
    def __init__(self, ttl_s: int = 60, store=None) -> None:
        self.librenms = LibrenmsClient()
        # Kurzer Cache: Doppelklicks und Re-Renders sollen keine neue
        # Live-Abfrage gegen FortiGate und LibreNMS auslösen.
        self._cache: TTLCache = TTLCache(maxsize=512, ttl=ttl_s)
        # Persistente IP↔MAC-Historie (locate.arp_store.ArpStore). Optional —
        # ohne sie verhält sich die Kette wie zuvor, nur ohne Offline-Treffer.
        self.store = store

    async def locate(self, ip: str, prefixes: PrefixTable, librenms_cfg: dict,
                     fmg_cfg: dict, app_cfg: Config,
                     names: list[str] | None = None) -> dict:
        key = (ip, tuple(sorted(names or ())))
        cached = self._cache.get(key)
        if cached is not None:
            return cached
        result = await self._locate(ip, prefixes, librenms_cfg, fmg_cfg, app_cfg, names)
        self._cache[key] = result
        return result

    async def _record(self, observations: list[dict]) -> None:
        """Beobachtungen wegschreiben — nie auf Kosten der Suche.

        Eine hakende Datenbank darf die Portsuche nicht scheitern lassen; das
        Aufzeichnen ist Beiwerk, nicht Zweck.
        """
        if self.store is None or not observations:
            return
        try:
            await self.store.record(observations)
        except Exception as exc:
            log.warning("ARP-Historie nicht schreibbar: %s", exc)

    async def _from_history(self, ip: str, warnings: list[str]) -> tuple[dict | None, list[dict]]:
        """Letzte bekannte MAC dieser IP + vollständiger Verlauf.

        Der neueste Eintrag gewinnt. Gab es im Aufbewahrungsfenster mehrere MACs
        an dieser IP, ist das ein Gerätetausch (oder eine Neuvergabe) — dann muss
        die Wahl begründet und die Alternative sichtbar sein, sonst lokalisiert
        man mit gutem Gewissen das falsche Gerät.
        """
        if self.store is None:
            return None, []
        try:
            history = await self.store.by_ip(ip)
        except Exception as exc:
            log.warning("ARP-Historie nicht lesbar: %s", exc)
            return None, []
        if not history:
            return None, []
        newest = history[0]
        if len(history) > 1:
            others = ", ".join(
                f"{h['mac']} (zuletzt {h['last_seen'] or '?'})" for h in history[1:4])
            warnings.append(
                f"An {ip} standen im Aufbewahrungszeitraum mehrere MACs — gewählt "
                f"ist die zuletzt gesehene {newest['mac']}. Ebenfalls gesehen: "
                f"{others}. Bei einem Gerätetausch zeigt der Treffer sonst auf den "
                "Vorgänger."
            )
        return newest, history

    async def _clean_uplinks(self, cfg: dict, device_id, raw: list[dict]) -> list[dict]:
        """LLDP-Nachbarn lesbar machen: lokalen Port auflösen, entrümpeln.

        Rohdaten aus `links` sind unbrauchbar hübsch: Nachbarn ohne sysName
        melden ihre Chassis-MAC als Hostname, derselbe Nachbar taucht mehrfach
        auf, und ohne den lokalen Port weiß man nicht, wo man messen soll.
        """
        try:
            ports = {str(p.get("port_id")): p for p in await self.librenms.device_ports(cfg, device_id)}
        except Exception:
            ports = {}

        seen: set[tuple] = set()
        out: list[dict] = []
        for link in raw:
            host = link.get("remote_hostname")
            if not host or is_mac_like(host):
                continue                       # nur Chassis-MAC — sagt nichts
            key = (host.strip().lower(), (link.get("remote_port") or "").strip().lower())
            if key in seen:
                continue
            seen.add(key)
            local = ports.get(str(link.get("local_port_id")), {})
            out.append({
                "local_port_id": link.get("local_port_id"),
                "local_port": local.get("ifName") or local.get("ifDescr"),
                "local_alias": local.get("ifAlias") or None,
                "remote_hostname": host,
                "remote_port": link.get("remote_port"),
                "remote_platform": link.get("remote_platform"),
                "protocol": link.get("protocol"),
            })
        out.sort(key=lambda u: (u["local_port"] or "", u["remote_hostname"] or ""))
        return out

    async def _self_device(self, ip: str, cfg: dict, warnings: list[str]) -> dict | None:
        """Ist die gesuchte IP selbst ein überwachtes Gerät?

        Dann ist die Portsuche die falsche Frage: die Management-MAC eines
        Switches steht per Definition nur auf Uplinks, weil es keinen Access-Port
        gibt, an dem er „hängt". Was der Suchende wissen will, ist, wo das Gerät
        angeschlossen ist — und das beantwortet LLDP.
        """
        try:
            index = await self.librenms.device_index(cfg)
        except Exception as exc:
            log.info("Geräteindex nicht abrufbar: %s", exc)
            return None
        dev = index.get(ip.strip().lower())
        if dev is None:
            return None

        uplinks: list[dict] = []
        try:
            raw = await self.librenms.device_neighbours(cfg, dev.get("device_id"))
            uplinks = await self._clean_uplinks(cfg, dev.get("device_id"), raw)
        except Exception as exc:
            log.info("LLDP-Nachbarn von %s nicht abrufbar: %s", ip, exc)

        warnings.append(
            f"{ip} ist selbst ein überwachtes Gerät "
            f"({dev.get('hostname') or dev.get('sysName')}). Seine MAC steht "
            "naturgemäß auf Uplinks und an keinem Access-Port — die Fundstellen "
            "unten zeigen den Weg dorthin, nicht den Anschluss."
            + (" Wo es angeschlossen ist, steht in den LLDP-Nachbarn."
               if uplinks else "")
        )
        return {
            "device_id": dev.get("device_id"),
            "hostname": dev.get("hostname"),
            "sys_name": dev.get("sysName"),
            "os": dev.get("os"),
            "hardware": dev.get("hardware"),
            "uplinks": uplinks,
        }

    async def _locate(self, ip: str, prefixes: PrefixTable, librenms_cfg: dict,
                      fmg_cfg: dict, app_cfg: Config,
                      names: list[str] | None = None) -> dict:
        warnings: list[str] = []
        self_device = await self._self_device(ip, librenms_cfg, warnings)

        # Alle bekannten Namen des Ziels — FMG-Adressobjekt, iTop, DNS plus der
        # LibreNMS-Hostname. Damit lassen sich LLDP-Nachbarschaften und
        # Port-Descriptions gegen das gesuchte Gerät abgleichen.
        aliases = build_aliases(names or [], [
            (self_device or {}).get("hostname"),
            (self_device or {}).get("sys_name"),
        ])

        # Jede gelesene ARP-Tabelle wandert in die Historie — die Antwort enthält
        # ohnehin alle Zeilen des VDOMs, nicht nur die gesuchte.
        seen: list[dict] = []
        arp = await arp_fortigate.resolve(ip, prefixes, fmg_cfg, app_cfg, warnings,
                                          seen=seen)
        if arp is None:
            arp = await arp_librenms.resolve(self.librenms, librenms_cfg, ip, warnings)
            if arp is not None:
                seen.append({"ip": ip, "mac": arp["mac"], "device": arp.get("device"),
                             "vdom": arp.get("vdom"), "interface": arp.get("interface"),
                             "source": "librenms"})
        await self._record(seen)

        from_cache: dict | None = None
        history: list[dict] = []
        if arp is None:
            # Live nichts — jetzt zählt, was der Host hinterlassen hat, ALS er
            # noch lief. Genau dieser Fall ist der Grund für die Historie.
            from_cache, history = await self._from_history(ip, warnings)
            if from_cache is not None:
                arp = {"mac": from_cache["mac"], "provenance": "cache",
                       "device": from_cache.get("device"),
                       "vdom": from_cache.get("vdom"),
                       "interface": from_cache.get("interface")}
                warnings.append(
                    f"{ip} antwortet gerade nicht — keine der Live-Quellen kennt "
                    f"eine MAC dazu. Verwendet wird die zuletzt aufgezeichnete "
                    f"Bindung {from_cache['mac']} vom "
                    f"{_when(from_cache.get('last_seen'), from_cache.get('age_s'))}. "
                    "Die Portangaben unten beschreiben damit den letzten bekannten "
                    "Stand, nicht den aktuellen Aufenthalt."
                )
        elif self.store is not None:
            try:
                history = await self.store.by_ip(ip)
            except Exception as exc:
                log.warning("ARP-Historie nicht lesbar: %s", exc)

        if arp is None:
            warnings.append(
                f"Für {ip} ließ sich keine MAC-Adresse ermitteln — weder über die "
                "FortiGate noch über LibreNMS noch aus der aufgezeichneten "
                "Historie. Ohne MAC ist keine Portsuche möglich."
            )
            return {
                "ip": ip, "mac": None, "mac_readable": None, "arp": None,
                "best": None, "candidates": [], "confidence": "none",
                "self_device": self_device, "aliases": sorted(aliases),
                "from_cache": None, "ip_history": [], "warnings": warnings,
            }

        mac = normalize_mac(arp["mac"])
        cands = await fdb_librenms.candidates(
            self.librenms, librenms_cfg, mac, warnings,
            aliases=aliases, self_device_id=(self_device or {}).get("device_id"),
        )
        ranked = fdb_librenms.rank(cands)
        conf = fdb_librenms.confidence(ranked, librenms_cfg)
        if from_cache is not None and conf == "high":
            # Die Portsuche mag eindeutig sein — die MAC stammt trotzdem aus
            # einer Aufzeichnung. 'Hoch' würde eine Gegenwart behaupten, für die
            # es keinen Beleg gibt.
            conf = "medium"

        if not ranked:
            warnings.append(
                f"MAC {readable_mac(mac)} steht in keiner FDB-Tabelle in LibreNMS. "
                "Entweder ist der Zugangsswitch nicht eingebunden, oder seine "
                "FDB-Discovery liefert nichts (bei MOXA siehe Wiki-Seite)."
            )
        elif ranked[0]["match_reason"] == "lldp_peer":
            warnings.append(
                f"Direkter Treffer: der LLDP-Nachbar von {ranked[0]['hostname']} / "
                f"{ranked[0]['if_name']} ist das gesuchte Gerät selbst "
                f"({ranked[0]['match_detail']}). Portklasse und MAC-Zahl spielen "
                "hier keine Rolle mehr."
            )
        elif ranked[0]["match_reason"] == "description":
            warnings.append(
                f"Treffer über die Port-Description „{ranked[0]['match_detail']}“ — "
                "sie benennt das gesuchte Gerät. Namenskonventionen können aber "
                "veralten, ein Blick auf den Port schadet nicht."
            )
        elif self_device is None and all(c["port_kind"] == "uplink" for c in ranked):
            warnings.append(
                "Die MAC wurde ausschließlich auf echten Switch-zu-Switch-Uplinks "
                "gesehen — der Switch, an dem das Gerät wirklich hängt, fehlt in "
                "LibreNMS."
            )
        elif ranked[0]["port_kind"] == "trunk":
            warnings.append(
                f"Der beste Treffer liegt auf einem Port mit {ranked[0]['mac_count']} "
                "MACs und ohne LLDP-Nachbarn. Das ist entweder ein Ring-Uplink oder "
                "ein Trunk zu einem Hypervisor — bei einer VM also durchaus richtig."
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
            "self_device": self_device,
            # Sichtbar machen, wogegen abgeglichen wurde — sonst ist ein
            # Description-Treffer für den Benutzer nicht nachvollziehbar.
            "aliases": sorted(aliases),
            # Gesetzt, wenn die MAC aus der Historie kam statt von einer
            # Live-Quelle — die Anzeige muss das kenntlich machen.
            "from_cache": from_cache,
            "ip_history": history,
            "warnings": warnings,
        }
