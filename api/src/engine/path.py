"""Path-Engine: Hop-Loop mit Live-Lookups (router/lookup + firewall/policy-lookup).

Pro Hop laufen genau zwei Live-Aufrufe gegen die FortiGate (via FMG-Proxy);
alles andere (Kandidaten, Zonen, Namen) kommt aus dem Inventory-Cache.
Gerät offline ⇒ Degraded Mode: Route aus dem Cache, Verdict UNKNOWN.
"""
from __future__ import annotations

import ipaddress
import logging
import re

from engine.classify import classify_egress
from engine.verdict import Candidate, Hop
from fmg.client import FmgClient, FmgError, FmgTargetOffline
from fmg.proxy import fortios_results, monitor_get
from inventory.prefixes import PrefixTable
from inventory.store import Inventory

log = logging.getLogger("engine.path")

PROTO_NUMBERS = {"tcp": 6, "udp": 17, "icmp": 1}


class TraceError(Exception):
    """Harter Fehler, der den Trace verhindert (z.B. Quelle unbekannt)."""


def find_ingress(prefixes: PrefixTable, inv: Inventory, src_ip: str) -> tuple[str, str, str]:
    """Start-(Device, VDOM, srcintf) aus der PrefixTable (connected bevorzugt)."""
    entries = prefixes.lookup_all(src_ip)
    if not entries:
        raise TraceError(
            f"Quelle {src_ip} liegt in keinem bekannten Standort-Prefix. "
            "FMG-Sync aktuell? Site-Override unter Einstellungen → Standorte möglich."
        )
    entry = next((e for e in entries if e.source in ("override", "connected")), entries[0])
    srcintf = entry.interface
    if not srcintf:
        # Override ohne Interface: connected Netz der Quelle auf dem Gerät suchen
        addr = ipaddress.IPv4Address(src_ip)
        for net, intf in inv.connected_networks(entry.device, entry.vdom):
            if addr in net:
                srcintf = intf
                break
    if not srcintf:
        raise TraceError(
            f"Kein Quell-Interface für {src_ip} auf {entry.device}/{entry.vdom} bestimmbar."
        )
    return entry.device, entry.vdom, srcintf


async def _live_route(client: FmgClient, adom: str, device: str, vdom: str,
                      dst_ip: str) -> dict | None:
    """router/lookup → {interface, gateway, ...} oder None (kein Treffer).

    ASSUMPTION (Lab): Feldnamen der Antwort variieren (interface/oif/gateway) —
    Parser ist tolerant, gegen Lab-Mitschnitt verifizieren.
    """
    resp = await monitor_get(client, adom, device, vdom, "router/lookup",
                             {"destination": dst_ip})
    results = fortios_results(resp)
    if isinstance(results, list):
        results = results[0] if results else None
    if not isinstance(results, dict):
        return None
    interface = results.get("interface") or results.get("oif") or results.get("intf")
    if not interface:
        return None
    return {
        "interface": interface,
        "gateway": results.get("gateway") or results.get("gw"),
        "raw": results,
        "source": "live",
    }


def cached_route(inv: Inventory, device: str, vdom: str, dst_ip: str) -> dict | None:
    """Degraded Mode: LPM über connected + statische Routen aus dem Cache."""
    addr = ipaddress.IPv4Address(dst_ip)
    best: tuple[int, dict] | None = None
    for net, intf in inv.connected_networks(device, vdom):
        if addr in net and (best is None or net.prefixlen >= best[0]):
            best = (net.prefixlen, {"interface": intf, "gateway": None,
                                    "source": "cache-connected"})
    for rt in inv.static_routes.get((device, vdom), []):
        if addr in rt["network"] and rt.get("interface"):
            if best is None or rt["network"].prefixlen > best[0]:
                best = (rt["network"].prefixlen,
                        {"interface": rt["interface"], "gateway": rt.get("gateway"),
                         "source": "cache-static"})
    return best[1] if best else None


def _router_vdom(inv: Inventory, device: str, router_re: re.Pattern) -> str | None:
    """VDOM, dessen NAME auf den Router-/Edge-VDOM hindeutet (z.B. 'Router').
    Zuverlässigstes Signal bei konsistenter Benennung — greift auch dann, wenn die
    Default-Route dynamisch (BGP übers SD-WAN) und damit nicht in router/static
    sichtbar ist. Pattern konfigurierbar (router_vdom_pattern).
    """
    for vdom in (inv.devices.get(device) or {}).get("vdoms", []):
        if router_re.search(vdom):
            return vdom
    return None


def _edge_vdom(inv: Inventory, device: str) -> str | None:
    """VDOM, dessen Default-Route (0/0) über ein echtes (Nicht-VDOM-Link-)
    Interface geht — der WAN/SD-WAN-Edge- bzw. Router-VDOM, an dem inter-site
    Traffic eintritt. Funktioniert auch bei GEROUTETEM Underlay (kein Tunnel):
    interne VDOMs (root, L3) default-routen per VDOM-Link zum Router-VDOM und
    scheiden aus. None bei 0 oder >1 Kandidaten (dann weitere Signale/Fallback).
    """
    hits = []
    for vdom in (inv.devices.get(device) or {}).get("vdoms", []):
        for rt in inv.static_routes.get((device, vdom), []):
            if (rt["network"].prefixlen == 0 and rt.get("interface")
                    and not inv.is_vdom_link(device, rt["interface"])):
                hits.append(vdom)
                break
    return hits[0] if len(hits) == 1 else None


def _overlay_vdom(inv: Inventory, device: str, overlay_re: re.Pattern) -> str | None:
    """VDOM des Geräts, das ein Overlay/SD-WAN-Interface terminiert — der Router-/
    Eintritts-VDOM, an dem inter-site Traffic ankommt. None, wenn keins vorhanden
    ODER über mehrere VDOMs verteilt (dann Fallback auf die Reverse-Route-Heuristik).
    """
    vdoms = {info["vdom"]
             for name, info in (inv.interfaces.get(device) or {}).items()
             if info.get("type") in ("tunnel", "ipsec") or overlay_re.search(name)}
    return next(iter(vdoms)) if len(vdoms) == 1 else None


async def _resolve_ingress(client: FmgClient, inv: Inventory, adom: str | None,
                           device: str, vdom: str | None, src_ip: str,
                           overlay_re: re.Pattern,
                           router_re: re.Pattern) -> tuple[str | None, str | None]:
    """Eintritts-(VDOM, Interface) einer Firewall Richtung Quelle bestimmen.

    vdom gesetzt → Reverse-Route auf diesem VDOM → dessen Interface zur Quelle.
    vdom None    → Eintritts-VDOM = der, an dem SD-WAN/Overlay terminiert (dort
                   kommt inter-site Traffic an). Sonst würde der Lookup im falschen
                   VDOM laufen (z.B. 'root', das L2-Transfer0 hält, aber wo das
                   Paket nie ankommt → fälschlich Deny). Fällt das Overlay-Signal
                   aus, den VDOM wählen, dessen Weg zur Quelle NICHT über einen
                   VDOM-Link geht. Danach kettet die VDOM-Link-Logik weiter, sodass
                   alle durchlaufenen VDOM-Policies geprüft werden.
    Live bevorzugt, sonst Cache (symmetrisches Routing angenommen).
    """
    if vdom is None:
        # Router-/Edge-VDOM bestimmen — zuerst per Name (robust, auch bei
        # dynamischem Routing), dann Default-Route-Edge, dann Overlay/SD-WAN.
        vdom = (_router_vdom(inv, device, router_re)
                or _edge_vdom(inv, device)
                or _overlay_vdom(inv, device, overlay_re))
    vdoms = [vdom] if vdom is not None else (
        (inv.devices.get(device) or {}).get("vdoms") or ["root"])
    fallback: tuple[str, str] | None = None
    for vd in vdoms:
        route = None
        if adom is not None:
            try:
                route = await _live_route(client, adom, device, vd, src_ip)
            except (FmgError, FmgTargetOffline):
                route = None
        if route is None:
            route = cached_route(inv, device, vd, src_ip)
        if route is None:
            continue
        intf = route["interface"]
        if fallback is None:
            fallback = (vd, intf)
        if not inv.is_vdom_link(device, intf):   # Router-/Eintritts-VDOM gefunden
            return vd, intf
    return fallback if fallback is not None else (vdom, None)


async def _live_policy_lookup(client: FmgClient, adom: str, device: str, vdom: str,
                              srcintf: str, src_ip: str, dst_ip: str, protocol: str,
                              dst_port: int | None, src_port: int | None,
                              icmp_type: int | None, icmp_code: int | None) -> dict:
    """firewall/policy-lookup → {success, policy_id}.

    ASSUMPTION (Lab): exakte Form des Erfolgs-Payloads verifizieren
    (success/policy_id vs. results-verschachtelt).
    """
    params: dict = {
        "srcintf": srcintf,
        "sourceip": src_ip,
        "dest": dst_ip,
        "protocol": protocol.lower(),
    }
    if protocol.lower() == "icmp":
        if icmp_type is not None:
            params["icmptype"] = icmp_type
        if icmp_code is not None:
            params["icmpcode"] = icmp_code
    else:
        if dst_port is not None:
            params["destport"] = dst_port
        if src_port is not None:
            params["sourceport"] = src_port
    resp = await monitor_get(client, adom, device, vdom, "firewall/policy-lookup", params)
    results = fortios_results(resp)
    if not isinstance(results, dict):
        results = resp if isinstance(resp, dict) else {}
    success = bool(results.get("success"))
    policy_id = results.get("policy_id", results.get("policyid"))
    return {"success": success, "policy_id": policy_id}


async def run_trace(*, src_ip: str, dst_ip: str, protocol: str,
                    dst_port: int | None = None, src_port: int | None = None,
                    icmp_type: int | None = None, icmp_code: int | None = None,
                    inv: Inventory, prefixes: PrefixTable, client: FmgClient,
                    overlay_pattern: str, max_hops: int = 8,
                    router_vdom_pattern: str = "(?i)(router|wan.?edge)") -> list[Hop]:
    device, vdom, srcintf = find_ingress(prefixes, inv, src_ip)
    overlay_re = re.compile(overlay_pattern)
    router_re = re.compile(router_vdom_pattern)

    hops: list[Hop] = []
    visited: set[tuple[str, str]] = set()
    deny_seen = False

    while len(hops) < max_hops:
        if (device, vdom) in visited:
            if hops:
                hops[-1].warnings.append(
                    f"Routing-Schleife erkannt: {device}/{vdom} bereits besucht — Abbruch."
                )
            break
        visited.add((device, vdom))
        adom = inv.adom_of(device)
        hop = Hop(index=len(hops), device=device, vdom=vdom, adom=adom,
                  srcintf=srcintf, src_zone=inv.zone_of(device, vdom, srcintf),
                  after_deny=deny_seen)

        # ── a) Route (live, sonst Cache) ─────────────────────────────────────
        route = None
        if adom is None:
            hop.warnings.append(f"Gerät {device} nicht im FMG-Snapshot — Sync nötig.")
        else:
            try:
                route = await _live_route(client, adom, device, vdom, dst_ip)
            except FmgTargetOffline as exc:
                hop.degraded = True
                hop.warnings.append(f"{exc} — nutze gecachte Routen (Degraded Mode).")
            except FmgError as exc:
                hop.degraded = True
                hop.warnings.append(f"Route-Lookup fehlgeschlagen: {exc}")
        if route is None:
            route = cached_route(inv, device, vdom, dst_ip)
            if route is not None and not hop.degraded and adom is not None:
                hop.warnings.append("Live-Route ohne Treffer — Cache-Route verwendet.")
        hop.route = route
        if route is None:
            hop.egress_class = "DEFAULT"
            hop.warnings.append(
                f"Keine Route zu {dst_ip} auf {device}/{vdom} — Ziel unerreichbar?"
            )
            hop.verdict = "UNKNOWN"
            hops.append(hop)
            break
        hop.egress = route["interface"]
        hop.egress_zone = inv.zone_of(device, vdom, hop.egress)

        # ── b) Klassifikation ────────────────────────────────────────────────
        cls = classify_egress(inv, prefixes, overlay_pattern, device, vdom,
                              hop.egress, dst_ip, gateway=route.get("gateway"))
        hop.egress_class = cls.egress_class
        hop.warnings.extend(cls.warnings)

        # ── c) Policy-Lookup (live) ──────────────────────────────────────────
        lookup = None
        if not hop.degraded and adom is not None:
            try:
                lookup = await _live_policy_lookup(
                    client, adom, device, vdom, srcintf, src_ip, dst_ip,
                    protocol, dst_port, src_port, icmp_type, icmp_code)
            except FmgTargetOffline as exc:
                hop.degraded = True
                hop.warnings.append(f"{exc} — Verdict UNKNOWN.")
            except FmgError as exc:
                hop.warnings.append(f"Policy-Lookup fehlgeschlagen: {exc}")

        # ── d) Kandidaten + Verdict ──────────────────────────────────────────
        candidates = [Candidate(**p) for p in
                      inv.candidate_policies(device, vdom, srcintf, hop.egress)]
        pid = lookup["policy_id"] if lookup else None
        if lookup is None:
            hop.verdict = "UNKNOWN"
        elif not lookup["success"] or pid in (0, "0", None):
            # Implizites Deny: keine Regel greift live. FortiOS liefert dafür
            # policy_id 0 (bzw. success=false).
            hop.verdict = "DENY"
            if lookup["success"] and pid in (0, "0"):
                hop.warnings.append(
                    "Implizites Deny (Policy 0): keine Regel greift auf dem Gerät. "
                    "Falls A38 gerade gesynct wurde, ist das Policy-Package im "
                    "FortiManager evtl. nicht auf das Gerät installiert — "
                    "Policy-Install/-Sync im FortiManager prüfen."
                )
        else:
            match = next((c for c in candidates if c.policyid == pid), None)
            if match is None:
                # Nicht in den Kandidaten (Zonen-Filter oder Cache stale) →
                # in der vollen Policy-Liste suchen
                full = next((Candidate(**p) for p in inv.policies.get((device, vdom), [])
                             if p.get("policyid") == pid), None)
                if full is not None:
                    match = full
                    candidates.insert(0, full)
                    hop.warnings.append(
                        f"Treffer-Regel #{pid} wurde live bestätigt, fehlt aber in "
                        "der nach Zonen gefilterten Kandidatenliste — die Zonen-/"
                        "Interface-Zuordnung im Sync ist evtl. unvollständig "
                        "(Kandidaten-Anzeige lückenhaft, Verdict bleibt korrekt)."
                    )
            if match is not None:
                match.hit = True
                hop.matched_policy = match
                hop.verdict = "ALLOW" if match.action == "accept" else "DENY"
            else:
                hop.verdict = "UNKNOWN"
                hop.warnings.append(
                    f"Policy #{pid} matcht live, ist aber in A38 nicht bekannt — "
                    "A38-Sync veraltet oder Policy-Package im FortiManager nicht "
                    "synchronisiert (Aktion unbekannt)."
                )
        hop.candidates = candidates
        if hop.verdict == "DENY":
            deny_seen = True
        hops.append(hop)

        # ── e) Nächster Hop ──────────────────────────────────────────────────
        if cls.egress_class in ("LOCAL", "DEFAULT"):
            break
        if cls.next_device is None:   # next_vdom=None ⇒ Eintritts-VDOM wird ermittelt
            break
        next_device = cls.next_device
        next_vdom = cls.next_vdom
        next_srcintf = cls.next_srcintf
        if next_vdom is None or next_srcintf is None:
            # Eintritts-VDOM (Router-VDOM) und/oder Ingress-Interface Richtung
            # Quelle ermitteln — für ROUTED (Site-Eintritt) wie für den internen
            # VDOM-Handoff (Ziel gehört Nachbar-VDOM), wo next_srcintf offen ist.
            rv, rintf = await _resolve_ingress(
                client, inv, inv.adom_of(next_device), next_device, next_vdom,
                src_ip, overlay_re, router_re)
            next_vdom = next_vdom or rv
            next_srcintf = next_srcintf or rintf
            if next_srcintf is None:
                hop.warnings.append(
                    f"Ingress auf {next_device}/{next_vdom or '?'} nicht bestimmbar "
                    "(Reverse-Route zur Quelle fehlt) — 'any'."
                )
        device, vdom = next_device, next_vdom or "root"
        srcintf = next_srcintf or "any"
    else:
        if hops:
            hops[-1].warnings.append(f"max_hops={max_hops} erreicht — Trace abgebrochen.")

    return hops
