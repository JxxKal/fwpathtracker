"""Debug-Protokoll der Pfad-Engine: pro Hop muss nachvollziehbar sein, WARUM der
nächste Hop gewählt wurde (Ingress-Herkunft, Route, Klassifikations-Checks,
Übergang) — inklusive der Warnungen für den Feld-Fall 'geteiltes SD-WAN-Underlay'.
"""
from __future__ import annotations

import pytest

from engine.path import run_trace
from fmg.client import FmgClient
from fmg.transport import FixtureTransport
from fmg_fixtures import ADOM, add_policy_lookup, add_route, tcp_params
from inventory.store import Inventory

OVERLAY = "(?i)(vpn|ovl|sdwan|tun|ipsec)"


def make_client() -> tuple[FmgClient, FixtureTransport]:
    t = FixtureTransport()
    return FmgClient(t, auth_mode="token"), t


async def _trace(inventory, prefixes, client, src, dst, port=443):
    return await run_trace(
        src_ip=src, dst_ip=dst, protocol="tcp", dst_port=port,
        inv=inventory, prefixes=prefixes, client=client,
        overlay_pattern=OVERLAY, max_hops=8,
    )


async def test_debug_trace_per_hop(inventory, prefixes):
    """Standardpfad (Gateway = Interface-IP der Gegenseite): jeder Hop trägt sein
    Entscheidungs-Protokoll — Ingress-Herkunft, Route, geprüfte Regeln, Übergang."""
    client, t = make_client()
    add_route(t, "fw-a", "root", "10.2.1.30", "xlink1", gateway="10.99.0.2")
    add_policy_lookup(t, "fw-a", "root",
                      tcp_params("lan1", "10.1.1.10", "10.2.1.30", 443), 100)
    add_route(t, "fw-b", "root", "10.2.1.30", "lan1")
    add_policy_lookup(t, "fw-b", "root",
                      tcp_params("xlink1", "10.1.1.10", "10.2.1.30", 443), 200)

    hops = await _trace(inventory, prefixes, client, "10.1.1.10", "10.2.1.30")

    dbg0 = hops[0].debug
    # Start-Hop: woher der Ingress stammt (Präfix-Treffer der Quelle)
    assert dbg0["ingress"]["chosen"] == {"device": "fw-a", "vdom": "root",
                                         "srcintf": "lan1"}
    assert any(m["network"] == "10.1.1.0/24" and m["source"] == "connected"
               for m in dbg0["ingress"]["src_prefix_matches"])
    # Route: Interface + Gateway + Herkunft (live/cache)
    assert dbg0["route"]["interface"] == "xlink1"
    assert dbg0["route"]["gateway"] == "10.99.0.2"
    assert dbg0["route"]["source"] == "live"
    # Klassifikation: geprüfte Regeln in Reihenfolge, inkl. der nicht greifenden
    cls = dbg0["classification"]
    assert [c["rule"] for c in cls["checks"]] == ["LOCAL", "VDOM_LINK", "OVERLAY",
                                                  "ROUTING"]
    assert [c["hit"] for c in cls["checks"]] == [False, False, False, True]
    routing = cls["checks"][-1]
    assert routing["matched_by"] == "gateway_global"
    assert routing["gateway_match_global"] == ["fw-b", "root", "xlink1"]
    assert cls["egress_intf"]["network"] == "10.99.0.0/30"
    assert cls["dst_owner"]["device"] == "fw-b"
    assert cls["result"] == {"egress_class": "ROUTED", "next_device": "fw-b",
                             "next_vdom": "root", "next_srcintf": "xlink1"}
    assert "owner_conflict" not in cls
    # Übergang zum nächsten Hop
    assert dbg0["next_hop"]["entering"] == {"device": "fw-b", "vdom": "root",
                                            "srcintf": "xlink1"}
    # Die Live-Lookups bleiben erhalten (Reproduzieren per Proxy-Request)
    assert "router_lookup" in dbg0 and "policy_lookup" in dbg0

    # Letzter Hop: LOCAL → Pfad endet, Grund im Debug
    assert hops[1].debug["classification"]["checks"][0]["hit"] is True
    assert "stop" in hops[1].debug["next_hop"]


async def test_ingress_resolution_debug(inventory, prefixes):
    """Fällt die Routing-Discovery aus und greift die Owner-Regel, dokumentiert
    das Debug, mit welchem Signal der Eintritts-VDOM gewählt wurde."""
    client, t = make_client()
    add_route(t, "fw-a", "root", "10.5.9.20", "wan", gateway="203.0.113.2")
    add_policy_lookup(t, "fw-a", "root",
                      tcp_params("lan1", "10.1.1.10", "10.5.9.20", 443), 100)
    add_route(t, "fw-e", "root", "10.1.1.10", "L2-Transfer0")   # Falle: root hat Route
    add_route(t, "fw-e", "Router", "10.1.1.10", "wan-e")
    add_route(t, "fw-e", "Router", "10.5.9.20", "lan-e")
    add_policy_lookup(t, "fw-e", "Router",
                      tcp_params("wan-e", "10.1.1.10", "10.5.9.20", 443), 600)

    hops = await _trace(inventory, prefixes, client, "10.1.1.10", "10.5.9.20")

    cls = hops[0].debug["classification"]
    assert [c["rule"] for c in cls["checks"]][-1] == "OWNER"
    assert cls["dst_owner"]["device"] == "fw-e"
    res = hops[0].debug["next_hop"]["ingress_resolution"]
    assert res["vdom_chosen_by"] == "router_name"      # VDOM heißt 'Router'
    assert res["vdom_signals"]["router_name"] == "Router"
    assert res["result"] == {"vdom": "Router", "srcintf": "wan-e", "via": "non-vdom-link"}


# ── Feld-Fall: geteiltes SD-WAN-Underlay ─────────────────────────────────────

def _underlay_rows() -> list[dict]:
    """Drei Firewalls im SELBEN Underlay-/24 (10.180.32.0/24), Next-Hop-Gateway
    10.180.32.1 = SD-WAN-Appliance (KEIN gemanagtes Gerät). Ziel 10.124.48.0/24
    hängt connected an xsh001 — die anderen beiden sind nur Segment-Nachbarn.
    """
    def row(kind: str, key: str, data) -> dict:
        return {"adom": ADOM, "kind": kind, "key": key, "data": data}

    return [
        row("device", "xha002", {"name": "xha002", "vdom": [{"name": "Router"}]}),
        row("interface", "xha002", [
            {"name": "lan", "ip": ["10.180.42.1", "255.255.255.0"], "vdom": ["Router"]},
            {"name": "wan1", "ip": ["10.180.32.2", "255.255.255.0"], "vdom": ["Router"]},
        ]),
        row("device", "xha001", {"name": "xha001", "vdom": [{"name": "Router"}]}),
        row("interface", "xha001", [
            {"name": "wan1", "ip": ["10.180.32.3", "255.255.255.0"], "vdom": ["Router"]},
        ]),
        row("device", "xsh001", {"name": "xsh001", "vdom": [{"name": "Router"}]}),
        row("interface", "xsh001", [
            {"name": "wan1", "ip": ["10.180.32.4", "255.255.255.0"], "vdom": ["Router"]},
            {"name": "lan", "ip": ["10.124.48.1", "255.255.255.0"], "vdom": ["Router"]},
        ]),
    ]


@pytest.fixture
def underlay_inv() -> Inventory:
    return Inventory.build(_underlay_rows(), synced_at="2026-08-13T00:00:00+00:00")


@pytest.fixture
def underlay_prefixes(underlay_inv: Inventory):
    return underlay_inv.build_prefix_table()


async def test_shared_underlay_skips_segment_neighbour(underlay_inv, underlay_prefixes):
    """Der Egress hängt in einem geteilten Underlay und das Gateway (SD-WAN)
    gehört keinem gemanagten Interface: dann ist der Nachbar im selben Netz NICHT
    der nächste Hop. Der Trace folgt dem Präfix-Besitzer (xsh001) statt zum
    Segment-Nachbarn xha001 abzubiegen (und dort in eine Schleife zu laufen)."""
    client, t = make_client()
    add_route(t, "xha002", "Router", "10.124.48.140", "wan1", gateway="10.180.32.1")
    add_policy_lookup(t, "xha002", "Router",
                      tcp_params("lan", "10.180.42.208", "10.124.48.140", 443), 17)
    add_route(t, "xsh001", "Router", "10.180.42.208", "wan1")   # Reverse → Ingress
    add_route(t, "xsh001", "Router", "10.124.48.140", "lan")
    add_policy_lookup(t, "xsh001", "Router",
                      tcp_params("wan1", "10.180.42.208", "10.124.48.140", 443), 42)

    hops = await _trace(underlay_inv, underlay_prefixes, client,
                        "10.180.42.208", "10.124.48.140")

    assert [(h.device, h.vdom) for h in hops] == [("xha002", "Router"),
                                                  ("xsh001", "Router")]
    cls = hops[0].debug["classification"]
    routing = next(c for c in cls["checks"] if c["rule"] == "ROUTING")
    # Gateway keiner FortiGate zuzuordnen → Segment-Heuristik übersprungen …
    assert routing["gateway_unresolved"] is True
    assert routing["segment"] == "10.180.32.0/24"
    assert routing["segment_skipped"] == "gateway_unresolved"
    assert "matched_by" not in routing
    # … die Nachbarn bleiben aber als Beleg im Debug stehen
    assert {m["device"] for m in routing["segment_members"]} == {"xha002", "xha001",
                                                                 "xsh001"}
    # … und die Owner-Regel übernimmt
    assert cls["checks"][-1]["rule"] == "OWNER"
    assert cls["dst_owner"]["device"] == "xsh001"
    assert cls["result"]["next_device"] == "xsh001"
    assert "owner_conflict" not in cls

    warn = " ".join(hops[0].warnings)
    assert "10.180.32.1" in warn and "SD-WAN" in warn
    assert "xha001/Router" in warn and "verworfen" in warn
    assert "xsh001" in warn
    # Eintritt am Ziel-Gerät per Reverse-Route; dort liegt das Ziel connected
    assert hops[1].srcintf == "wan1" and hops[1].egress_class == "LOCAL"


def _reused_transfer_rows() -> list[dict]:
    """Pro Standort dasselbe SD-WAN-Transfernetz (10.180.56.16/29 → Gateway .17):
    das Gateway trägt an JEDEM Standort eine eigene FortiGate. Ein globaler
    IP-Treffer ist damit keine Wegaussage — Feld-Fall Open-Systems-SD-WAN.
    """
    def row(kind: str, key: str, data) -> dict:
        return {"adom": ADOM, "kind": kind, "key": key, "data": data}

    def site(name: str, lan: str) -> list[dict]:
        return [
            row("device", name, {"name": name, "vdom": [{"name": "Router"}]}),
            row("interface", name, [
                {"name": "lan", "ip": [lan, "255.255.255.0"], "vdom": ["Router"]},
                # gleiche Transfer-IP an jedem Standort (Gateway = .17 = Appliance)
                {"name": "Open-Systems", "ip": ["10.180.56.17", "255.255.255.248"],
                 "vdom": ["Router"]},
            ]),
        ]

    rows = site("EUGEBT1", "10.124.44.1") + site("EUGERN1", "10.130.0.1")
    # Ziel-Standort: hier hängt 10.180.20.0/24 (statisch hinter dem Gerät)
    rows += [
        row("device", "xvo001-1", {"name": "xvo001-1", "vdom": [{"name": "Router"}]}),
        row("interface", "xvo001-1", [
            {"name": "Open-Systems", "ip": ["10.180.56.17", "255.255.255.248"],
             "vdom": ["Router"]},
            {"name": "M2M-Telekom1", "ip": ["10.180.30.1", "255.255.255.0"],
             "vdom": ["Router"]},
        ]),
        row("route", "xvo001-1|Router", [
            {"dst": ["10.180.20.0", "255.255.255.0"], "device": ["M2M-Telekom1"],
             "gateway": "10.180.30.2"},
        ]),
    ]
    return rows


@pytest.fixture
def reused_inv() -> Inventory:
    return Inventory.build(_reused_transfer_rows(), synced_at="2026-08-14T00:00:00+00:00")


@pytest.fixture
def reused_prefixes(reused_inv: Inventory):
    return reused_inv.build_prefix_table()


async def test_reused_transfer_net_gateway_is_ambiguous(reused_inv, reused_prefixes):
    """Dieselbe Gateway-IP an mehreren Standorten: daraus darf KEIN Next-Hop
    abgeleitet werden — sonst zieht es eine standortfremde Firewall in den Pfad,
    deren implizites Deny den ganzen Trace blockt. Stattdessen entscheidet der
    Präfix-Besitzer des Ziels."""
    client, t = make_client()
    add_route(t, "EUGEBT1", "Router", "10.180.20.148", "Open-Systems",
              gateway="10.180.56.17")
    add_policy_lookup(t, "EUGEBT1", "Router",
                      tcp_params("lan", "10.124.44.169", "10.180.20.148", 105), 20)
    add_route(t, "xvo001-1", "Router", "10.124.44.169", "Open-Systems")   # Reverse
    add_route(t, "xvo001-1", "Router", "10.180.20.148", "M2M-Telekom1",
              gateway="10.180.30.2")
    add_policy_lookup(t, "xvo001-1", "Router",
                      tcp_params("Open-Systems", "10.124.44.169", "10.180.20.148", 105), 29)

    hops = await run_trace(
        src_ip="10.124.44.169", dst_ip="10.180.20.148", protocol="tcp", dst_port=105,
        inv=reused_inv, prefixes=reused_prefixes, client=client,
        overlay_pattern=OVERLAY, max_hops=8)

    # EUGERN1 (fremder Standort mit derselben Transfer-IP) darf NICHT auftauchen
    assert [h.device for h in hops] == ["EUGEBT1", "xvo001-1"]
    routing = next(c for c in hops[0].debug["classification"]["checks"]
                   if c["rule"] == "ROUTING")
    assert routing["gateway_ambiguous"] == ["EUGERN1", "xvo001-1"]
    assert routing["segment_skipped"] == "gateway_ambiguous"
    assert "matched_by" not in routing
    assert len(routing["gateway_candidates"]) == 3      # inkl. eigenem Interface
    warn = " ".join(hops[0].warnings)
    assert "10.180.56.17" in warn and "EUGERN1" in warn
    assert "wiederverwendet" in warn


async def test_shared_underlay_without_owner_ends_at_sdwan(
        underlay_inv, underlay_prefixes):
    """Gleiches Underlay, aber das Ziel steht in keinem Präfix: der Pfad endet
    ehrlich am SD-WAN (DEFAULT) statt einen Segment-Nachbarn zu erfinden."""
    client, t = make_client()
    add_route(t, "xha002", "Router", "10.99.99.5", "wan1", gateway="10.180.32.1")
    add_policy_lookup(t, "xha002", "Router",
                      tcp_params("lan", "10.180.42.208", "10.99.99.5", 443), 17)

    hops = await _trace(underlay_inv, underlay_prefixes, client,
                        "10.180.42.208", "10.99.99.5")

    assert len(hops) == 1
    assert hops[0].egress_class == "DEFAULT"
    warn = " ".join(hops[0].warnings)
    assert "keinem gemanagten Gerät zuzuordnen" in warn
    assert "Site-Override" in warn
