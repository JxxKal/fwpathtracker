"""Egress-Interface-Klassifikation: LOCAL | VDOM_LINK | OVERLAY | ROUTED | DEFAULT.

Entscheidet, wie es nach einem Hop weitergeht. Reihenfolge der Prüfungen:
  1. LOCAL     – connected Subnet des Egress enthält das Ziel → letzter Hop
  2. VDOM_LINK – Egress ist ein vdom-link (Typ/Name) → Peer-VDOM, gleiches Gerät
  3. OVERLAY   – Tunnel-/SD-WAN-Interface (Typ oder Name-Pattern) → nächster Hop =
                 Ziel-Site-Firewall via PrefixTable
  4. Routing   – Egress ist kein Overlay → nächsten Hop aus dem Routing ableiten:
                 (a) Next-Hop-Gateway == Interface-IP eines anderen VDOM/Geräts,
                 (b) anderer VDOM/andere FW im selben Transit-Segment.
                 Selbes Gerät → VDOM_LINK (172.16er Inter-VDOM, geräte-lokal
                 matchen!), anderes Gerät → ROUTED. Fallback: bekanntes Ziel-
                 Präfix via PrefixTable; die Path-Engine wählt dort als EINTRITTS-
                 VDOM den, an dem SD-WAN/Overlay terminiert (Router-VDOM), NICHT den
                 erstbesten mit Route zur Quelle — sonst Lookup im falschen VDOM.
                 Danach ketten die VDOM-Links weiter, sodass alle durchlaufenen
                 VDOM-Policies geprüft werden.
  5. DEFAULT   – Ziel gehört keinem gemanagten Gerät → Richtung Internet/unbekannt
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field

from inventory.prefixes import PrefixTable
from inventory.store import Inventory

_TUNNEL_TYPES = {"tunnel", "ipsec", "vdom-link", "npu-vlink"}


@dataclass
class Classification:
    egress_class: str                       # LOCAL | VDOM_LINK | OVERLAY | DEFAULT
    next_device: str | None = None
    next_vdom: str | None = None
    next_srcintf: str | None = None
    warnings: list[str] = field(default_factory=list)
    # Entscheidungs-Protokoll: welche Regel in welcher Reihenfolge geprüft wurde,
    # mit den Rohdaten (Egress-Interface, Gateway-Auflösung, Transit-Segment,
    # Präfix-Tabelle). Landet als hop.debug['classification'] im Trace-Ergebnis.
    debug: dict = field(default_factory=dict)


def _is_overlay(intf_info: dict | None, intf_name: str, overlay_re: re.Pattern) -> bool:
    if intf_info and intf_info.get("type") in ("tunnel", "ipsec"):
        return True
    return bool(overlay_re.search(intf_name))


def _remote_overlay_intf(inv: Inventory, device: str, vdom: str,
                         overlay_re: re.Pattern) -> tuple[str | None, list[str]]:
    """Overlay-Interface der Gegenseite (remote srcintf). Heuristik:
    Tunnel-Interfaces des Ziel-(Device,VDOM); bei Mehrdeutigkeit Warning."""
    candidates = sorted(
        name for name, info in (inv.interfaces.get(device) or {}).items()
        if info.get("vdom") == vdom and _is_overlay(info, name, overlay_re)
    )
    if not candidates:
        return None, [f"Kein Overlay-Interface auf {device}/{vdom} gefunden — "
                      "remote srcintf unbekannt."]
    warnings = []
    if len(candidates) > 1:
        warnings.append(
            f"Mehrere Overlay-Interfaces auf {device}/{vdom} "
            f"({', '.join(candidates)}) — nehme '{candidates[0]}'."
        )
    return candidates[0], warnings


def _intf_facts(inv: Inventory, device: str, name: str | None) -> dict:
    """Rohdaten eines Interfaces fürs Debug-Protokoll (JSON-serialisierbar)."""
    if not name:
        return {"name": None, "known": False}
    info = inv.interface(device, name)
    if info is None:
        return {"name": name, "known": False}
    ip = info.get("ip")
    return {
        "name": name,
        "known": True,
        "vdom": info.get("vdom"),
        "type": info.get("type"),
        "enabled": info.get("enabled", True),
        "ip": str(ip) if ip is not None else None,
        "network": str(ip.network) if ip is not None else None,
        "secondary_ips": [str(s) for s in info.get("secondary_ips", [])],
    }


def _prefix_facts(entry) -> dict | None:
    """PrefixEntry → Debug-Dict."""
    if entry is None:
        return None
    return {
        "network": str(entry.network),
        "source": entry.source,
        "device": entry.device,
        "vdom": entry.vdom,
        "interface": entry.interface,
        "site_name": entry.site_name,
    }


def classify_egress(inv: Inventory, prefixes: PrefixTable, overlay_pattern: str,
                    device: str, vdom: str, egress_intf: str,
                    dst_ip: str, gateway: str | None = None) -> Classification:
    overlay_re = re.compile(overlay_pattern)
    dst = ipaddress.IPv4Address(dst_ip)
    intf_info = inv.interface(device, egress_intf)

    # Debug-Protokoll: die Fakten, auf denen die Hop-Entscheidung beruht. Jeder
    # geprüfte Schritt landet in 'checks' — auch die, die NICHT gegriffen haben,
    # damit ein falscher Pfad rückwärts nachvollziehbar ist.
    owner = prefixes.lookup_owner(dst_ip)
    dbg: dict = {
        "from": f"{device}/{vdom}",
        "dst": dst_ip,
        "egress_intf": _intf_facts(inv, device, egress_intf),
        "gateway": gateway,
        "overlay_pattern": overlay_pattern,
        "checks": [],
        # Was die PrefixTable über das ZIEL weiß — unabhängig davon, ob die
        # Owner-Regel (Schritt 5) überhaupt zum Zug kommt. Zeigt sofort, hinter
        # welchem Gerät das Ziel laut Inventar hängt.
        "dst_prefix_matches": [_prefix_facts(e) for e in prefixes.lookup_all(dst_ip)[:10]],
        "dst_owner": _prefix_facts(owner),
    }

    routing_dbg: dict = {}

    def _done(cls: Classification) -> Classification:
        """Ergebnis annotieren: gewählter nächster Hop + Owner-Abgleich."""
        cls.debug = dbg
        dbg["result"] = {
            "egress_class": cls.egress_class,
            "next_device": cls.next_device,
            "next_vdom": cls.next_vdom,
            "next_srcintf": cls.next_srcintf,
        }
        # Plausibilitätsprüfung: Der nächste Hop widerspricht dem Präfix-Besitzer
        # des Ziels. Nur relevant, wenn der Pfad auf ein ANDERES Gerät springt —
        # beim VDOM-Link innerhalb desselben Geräts ist der Ziel-Besitzer
        # naturgemäß ein anderer und die Warnung wäre reines Rauschen.
        if (cls.next_device and owner is not None
                and owner.device not in (cls.next_device, device)):
            source = routing_dbg.get("matched_by")
            dbg["owner_conflict"] = {
                "chosen": cls.next_device,
                "owner": owner.device,
                "owner_prefix": str(owner.network),
                "owner_source": owner.source,
                "matched_by": source,
            }
            if cls.next_device != device:
                how = ("dem gemeinsamen Transit-Segment" if source == "segment"
                       else f"der Gateway-IP {gateway}" if source == "gateway_global"
                       else "dem Routing")
                cls.warnings.append(
                    f"Nächster Hop {cls.next_device} stammt aus {how}, laut "
                    f"Präfix-Tabelle liegt {dst_ip} aber hinter {owner.device} "
                    f"({owner.network}, {owner.source}) — {cls.next_device} ist "
                    "entweder Transit-Hop oder ein Standort-Nachbar mit derselben "
                    "Transfer-IP (Pfad ab hier prüfen)."
                )
        return cls

    # 1. LOCAL: connected Subnet (inkl. Secondary-IPs) des Egress enthält das Ziel
    if intf_info is not None:
        nets = [intf_info["ip"].network] if intf_info.get("ip") is not None else []
        nets += [s.network for s in intf_info.get("secondary_ips", [])]
        hit = next((n for n in nets if dst in n), None)
        dbg["checks"].append({"rule": "LOCAL", "hit": hit is not None,
                              "networks": [str(n) for n in nets],
                              "detail": f"{dst_ip} in {hit}" if hit else
                                        f"{dst_ip} in keinem connected Netz des Egress"})
        if hit is not None:
            return _done(Classification(egress_class="LOCAL"))
    else:
        dbg["checks"].append({"rule": "LOCAL", "hit": False,
                              "detail": f"Egress '{egress_intf}' nicht im Inventar "
                                        "(Sync veraltet?)"})

    # 2. VDOM-LINK
    peer = inv.vdom_link_peer(device, egress_intf)
    is_link = (intf_info or {}).get("type") in ("vdom-link", "npu-vlink") \
        or _looks_like_vdom_link(egress_intf)
    dbg["checks"].append({"rule": "VDOM_LINK", "hit": bool(peer and is_link),
                          "peer": list(peer) if peer else None,
                          "type_or_name_match": is_link})
    if peer is not None and is_link:
        peer_intf, peer_vdom = peer
        return _done(Classification(
            egress_class="VDOM_LINK",
            next_device=device, next_vdom=peer_vdom, next_srcintf=peer_intf,
        ))

    # 3. OVERLAY: nächste Site-Firewall über die PrefixTable
    is_overlay = _is_overlay(intf_info, egress_intf, overlay_re)
    dbg["checks"].append({"rule": "OVERLAY", "hit": is_overlay,
                          "detail": f"Typ={(intf_info or {}).get('type')} / "
                                    f"Name-Pattern {overlay_pattern}"})
    if is_overlay:
        cls = Classification(egress_class="OVERLAY")
        entry = owner
        if entry is None or (entry.device == device and entry.vdom == vdom):
            cls.warnings.append(
                f"Ziel {dst_ip} hinter Overlay '{egress_intf}', aber keine "
                "Ziel-Site in der PrefixTable — Pfad endet hier."
            )
            cls.egress_class = "DEFAULT"
            return _done(cls)
        remote_intf, warns = _remote_overlay_intf(inv, entry.device, entry.vdom, overlay_re)
        cls.warnings.extend(warns)
        cls.next_device, cls.next_vdom = entry.device, entry.vdom
        cls.next_srcintf = remote_intf
        return _done(cls)

    # 4. Nächsten Hop direkt aus dem Routing ableiten (keine Owner-Tabelle nötig):
    #    a) Next-Hop-Gateway == Interface-IP eines anderen VDOM/Geräts
    #    b) sonst: anderer VDOM/andere FW im selben Transit-Segment wie der Egress
    #    Landet der Hop auf demselben Gerät (anderer VDOM) → VDOM_LINK (z.B. der
    #    172.16er Inter-VDOM-Link Richtung Router-VDOM), sonst ROUTED.
    nxt = _next_hop_via_routing(inv, device, vdom, egress_intf, gateway, routing_dbg)
    dbg["checks"].append({"rule": "ROUTING", "hit": nxt is not None, **routing_dbg})
    if nxt is not None:
        nd, nv, nintf = nxt
        same_dev = nd == device
        cls = Classification(
            egress_class="VDOM_LINK" if same_dev else "ROUTED",
            next_device=nd, next_vdom=nv, next_srcintf=nintf,
            warnings=[
                (f"Nächster VDOM {nd}/{nv} via '{egress_intf}'"
                 if same_dev else
                 f"Nächster Hop {nd}/{nv} via '{egress_intf}' "
                 f"(Gateway {gateway or '—'}) — geroutete Standortkopplung.")
            ],
        )
        return _done(cls)

    # Das Gateway zeigt auf ein nicht gemanagtes Gerät (SD-WAN/Provider-Router):
    # Nachbarn im selben Underlay-Netz sind dann NICHT der nächste Hop — der
    # Verkehr verlässt hier die gemanagte Kette. Sichtbar machen, sonst wirkt der
    # (über die Owner-Regel gefundene) Sprung wie ein direkter Link.
    gw_note: str | None = None
    skipped = routing_dbg.get("segment_skipped")
    if skipped == "gateway_unresolved":
        neighbours = ", ".join(sorted({
            f"{m['device']}/{m['vdom']}" for m in routing_dbg.get("segment_members") or []
            if m["device"] != device
        }))
        gw_note = (
            f"Gateway {gateway} gehört zu keinem gemanagten FortiGate-Interface "
            f"(SD-WAN-Appliance/Provider-Router) — der Verkehr geht über die "
            f"Standardrouting-Kopplung, nicht zu einem Nachbarn im Transit-Netz "
            f"{routing_dbg.get('segment')}"
            + (f" ({neighbours} als nächster Hop verworfen)." if neighbours else ".")
        )
    elif skipped == "gateway_ambiguous":
        # Dieselbe Gateway-IP auf mehreren Geräten: Transfernetze sind pro Standort
        # wiederverwendet. Ein Treffer wäre geraten — und würde eine standortfremde
        # Firewall in den Pfad ziehen, deren implizites Deny den Trace blockt.
        gw_note = (
            f"Gateway {gateway} trägt im FMG-Inventar mehrere Geräte "
            f"({', '.join(routing_dbg.get('gateway_ambiguous') or [])}) — "
            "Transfernetze sind pro Standort wiederverwendet, der nächste Hop ist "
            "daraus NICHT bestimmbar. Kein Gerät daraus in den Pfad übernommen; "
            "es entscheidet die Präfix-Zuordnung des Ziels."
        )

    # 5. Fallback: BESITZER des Ziels (connected/override schlägt static — eine
    #    statische Transit-Route zu einer anderen FW macht diese NICHT zum Owner).
    #    next_vdom=None ⇒ Path-Engine wählt den EINTRITTS-VDOM (Router-VDOM) per
    #    Reverse-Route zur Quelle, damit auch dessen Policy geprüft wird.
    dbg["checks"].append({"rule": "OWNER", "hit": owner is not None and owner.device != device,
                          "owner": _prefix_facts(owner)})
    if owner is not None and owner.device != device:
        site = f" ({owner.site_name})" if owner.site_name else ""
        warnings = [gw_note] if gw_note else []
        warnings.append(
            f"Ziel {dst_ip} liegt hinter {owner.device}{site} "
            "(Präfix-Zuordnung) — geroutete Standortkopplung, verfolge weiter."
        )
        return _done(Classification(
            egress_class="ROUTED",
            next_device=owner.device, next_vdom=None, next_srcintf=None,
            warnings=warnings,
        ))

    # 6. DEFAULT
    dbg["checks"].append({"rule": "DEFAULT", "hit": True,
                          "detail": "Kein gemanagtes Ziel-Gerät bestimmbar — "
                                    "Richtung Internet/unbekannt."})
    cls = Classification(egress_class="DEFAULT")
    if gw_note:
        cls.warnings.append(gw_note)
        cls.warnings.append(
            f"Ziel {dst_ip} ist keinem gemanagten Gerät zuzuordnen — Pfad endet "
            "hinter dem SD-WAN/Uplink. Fehlt das Ziel-Präfix im Inventar "
            "(FMG-Sync) oder braucht es einen Site-Override?"
        )
    return _done(cls)


def _next_hop_via_routing(inv: Inventory, device: str, vdom: str, egress_intf: str,
                          gateway: str | None,
                          dbg: dict | None = None) -> tuple[str, str, str] | None:
    """Nächsten Hop (VDOM oder Firewall) aus dem Routing bestimmen.

    Reihenfolge: erst SELBES Gerät (Inter-VDOM-Link — dessen 172.16er Netze sind
    pro Gerät wiederverwendet und dürfen NICHT global gematcht werden), dann
    andere Geräte. a) Gateway == Interface-IP; b) gemeinsames Transit-Segment.
    Rückgabe: (next_device, next_vdom, next_srcintf) oder None; das gefundene
    Interface ist zugleich der Ingress des nächsten Hops.

    Das Segment (b) ist nur dann ein gültiges Signal, wenn die Route KEIN
    verwertbares Gateway hat (connected/Point-to-Point). Steht dort ein Gateway,
    das keinem gemanagten Interface gehört (SD-WAN-Appliance, Provider-Router),
    geht das Paket genau dorthin — NICHT zu einer anderen Firewall, die zufällig
    im selben Underlay-Netz hängt. Dann greift stattdessen die Owner-Regel.

    `dbg` (optional) wird mit dem Entscheidungsweg gefüllt: Gateway-Auflösung,
    Segment und ALLE Segment-Mitglieder — nur so ist nachvollziehbar, warum
    ausgerechnet dieser Nachbar gewählt wurde (oder eben keiner).
    """
    d = dbg if dbg is not None else {}
    has_gw = bool(gateway) and gateway not in ("0.0.0.0", "::", "")
    d["gateway"] = gateway
    d["gateway_usable"] = has_gw
    skip: str | None = None
    if has_gw:
        local = inv.interface_by_ip(gateway, device=device)   # selbes Gerät (VDOM-Link)
        d["gateway_match_local"] = list(local) if local else None
        if local is not None and local[1] != vdom:
            d["matched_by"] = "gateway_local"
            return local
        # ALLE Geräte mit dieser Gateway-IP — Transfernetze (SD-WAN, Inter-VDOM)
        # sind pro Standort wiederverwendet, ein Treffer ist also nicht
        # automatisch eindeutig.
        matches = inv.interfaces_by_ip(gateway)
        d["gateway_candidates"] = [list(m) for m in matches]
        others = [m for m in matches if (m[0], m[1]) != (device, vdom)]
        hit_devices = sorted({m[0] for m in others})
        # Kein Interface trägt diese IP ⇒ der echte Next-Hop ist kein gemanagtes
        # Gerät (SD-WAN-Appliance, Provider-Router, L3-Switch).
        d["gateway_unresolved"] = not matches
        if len(hit_devices) > 1:
            # Mehrere Geräte tragen dieselbe Gateway-IP → welches davon der Hop
            # ist, sagt die IP nicht. Raten hieße: fremde Firewall im Pfad.
            d["gateway_ambiguous"] = hit_devices
            skip = "gateway_ambiguous"
        elif others:
            d["gateway_match_global"] = list(others[0])
            d["matched_by"] = "gateway_global"
            return others[0]
        elif not matches:
            d["gateway_match_global"] = None
            skip = "gateway_unresolved"
    eg = inv.interface(device, egress_intf)
    if eg is not None and eg.get("ip") is not None:
        net = eg["ip"].network
        d["segment"] = str(net)
        members = inv.interfaces_in_network(net)
        d["segment_members"] = [
            {"device": dev, "vdom": vd, "interface": intf,
             "ip": str((inv.interface(dev, intf) or {}).get("ip"))}
            for dev, vd, intf in members
        ]
        # Gateway nicht auflösbar (fremdes Gerät) oder nicht eindeutig (geteiltes/
        # wiederverwendetes Transfernetz) → Segment-Nachbarn sind KEIN Next-Hop.
        if skip:
            d["segment_skipped"] = skip
            return None
        for dev, vd, intf in inv.interfaces_in_network(net, device=device):
            if vd != vdom:
                d["matched_by"] = "segment_same_device"
                return dev, vd, intf
        for dev, vd, intf in members:
            if (dev, vd) != (device, vdom):
                d["matched_by"] = "segment"
                return dev, vd, intf
    else:
        d["segment"] = None
        if skip:
            d["segment_skipped"] = skip
    return None


def _looks_like_vdom_link(name: str) -> bool:
    """ASSUMPTION (Lab): vdom-link-Enden heißen <base>0/<base>1 und enthalten
    typischerweise 'vlink'/'vdlink'. Gegen system/vdom-link verifizieren."""
    return bool(re.search(r"(?i)(vlink|vd-?link|vdom)", name))
