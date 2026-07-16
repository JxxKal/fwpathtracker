"""Path-Engine gegen die Lab-Matrix (deterministisch via FixtureTransport):
intra-site allow · cross-site allow / implizit-deny / explizit-deny ·
VDOM-Link-Pfad · Ziel=Internet · Gerät offline · Quelle unbekannt · Loop-Guard.
"""
from __future__ import annotations

import pytest

from engine.path import (
    TraceError, _ingress_ambiguity, find_ingress, run_port_trace, run_trace,
)
from engine.verdict import aggregate_verdict
from fmg.client import FmgClient
from fmg.transport import FixtureTransport
from fmg_fixtures import add_policy_lookup, add_route, tcp_params
from inventory.prefixes import PrefixTable

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


async def test_intra_site_allow(inventory, prefixes):
    client, t = make_client()
    add_route(t, "fw-a", "root", "10.1.2.20", "lan2")
    add_policy_lookup(t, "fw-a", "root",
                      tcp_params("lan1", "10.1.1.10", "10.1.2.20", 443), 100)

    hops = await _trace(inventory, prefixes, client, "10.1.1.10", "10.1.2.20")
    assert len(hops) == 1
    hop = hops[0]
    assert (hop.device, hop.vdom, hop.srcintf, hop.egress) == ("fw-a", "root", "lan1", "lan2")
    assert hop.egress_class == "LOCAL"
    assert hop.verdict == "ALLOW"
    assert hop.matched_policy.policyid == 100 and hop.matched_policy.hit
    assert hop.src_zone == "inside-a"
    assert aggregate_verdict(hops) == "ALLOW"


async def test_cross_site_allow(inventory, prefixes):
    client, t = make_client()
    add_route(t, "fw-a", "root", "10.2.1.30", "vpn-to-b")
    add_policy_lookup(t, "fw-a", "root",
                      tcp_params("lan1", "10.1.1.10", "10.2.1.30", 443), 100)
    add_route(t, "fw-b", "root", "10.2.1.30", "lan1")
    add_policy_lookup(t, "fw-b", "root",
                      tcp_params("vpn-to-a", "10.1.1.10", "10.2.1.30", 443), 200)

    hops = await _trace(inventory, prefixes, client, "10.1.1.10", "10.2.1.30")
    assert len(hops) == 2
    assert hops[0].egress_class == "OVERLAY"
    assert (hops[1].device, hops[1].srcintf) == ("fw-b", "vpn-to-a")
    assert hops[1].egress_class == "LOCAL"
    assert [h.verdict for h in hops] == ["ALLOW", "ALLOW"]
    assert aggregate_verdict(hops) == "ALLOW"


async def test_cross_site_implicit_deny(inventory, prefixes):
    client, t = make_client()
    add_route(t, "fw-a", "root", "10.2.1.30", "vpn-to-b")
    add_policy_lookup(t, "fw-a", "root",
                      tcp_params("lan1", "10.1.1.10", "10.2.1.30", 443), 100)
    add_route(t, "fw-b", "root", "10.2.1.30", "lan1")
    add_policy_lookup(t, "fw-b", "root",
                      tcp_params("vpn-to-a", "10.1.1.10", "10.2.1.30", 443), None)

    hops = await _trace(inventory, prefixes, client, "10.1.1.10", "10.2.1.30")
    assert [h.verdict for h in hops] == ["ALLOW", "DENY"]
    assert hops[1].matched_policy is None  # implizites Deny: keine Policy
    assert aggregate_verdict(hops) == "DENY"


async def test_explicit_deny(inventory, prefixes):
    client, t = make_client()
    add_route(t, "fw-a", "root", "10.2.1.30", "vpn-to-b")
    add_policy_lookup(t, "fw-a", "root",
                      tcp_params("lan1", "10.1.1.10", "10.2.1.30", 443), 110)
    # Nach dem Deny läuft der Trace best-effort weiter (UI graut spätere Hops aus)
    add_route(t, "fw-b", "root", "10.2.1.30", "lan1")
    add_policy_lookup(t, "fw-b", "root",
                      tcp_params("vpn-to-a", "10.1.1.10", "10.2.1.30", 443), 200)

    hops = await _trace(inventory, prefixes, client, "10.1.1.10", "10.2.1.30")
    assert hops[0].verdict == "DENY"
    assert hops[0].matched_policy.policyid == 110
    assert hops[0].matched_policy.action == "deny"
    assert not hops[0].after_deny and hops[1].after_deny
    assert aggregate_verdict(hops) == "DENY"


async def test_vdom_link_path(inventory, prefixes):
    client, t = make_client()
    add_route(t, "fw-a", "root", "10.1.8.20", "vlink0")
    add_policy_lookup(t, "fw-a", "root",
                      tcp_params("lan1", "10.1.1.10", "10.1.8.20", 443), 100)
    add_route(t, "fw-a", "dmz", "10.1.8.20", "dmz-lan")
    add_policy_lookup(t, "fw-a", "dmz",
                      tcp_params("vlink1", "10.1.1.10", "10.1.8.20", 443), 100)

    hops = await _trace(inventory, prefixes, client, "10.1.1.10", "10.1.8.20")
    assert len(hops) == 2
    assert hops[0].egress_class == "VDOM_LINK"
    assert (hops[1].device, hops[1].vdom, hops[1].srcintf) == ("fw-a", "dmz", "vlink1")
    assert hops[1].egress_class == "LOCAL"
    assert aggregate_verdict(hops) == "ALLOW"


async def test_internet_default_route(inventory, prefixes):
    client, t = make_client()
    add_route(t, "fw-a", "root", "8.8.8.8", "wan")
    add_policy_lookup(t, "fw-a", "root",
                      tcp_params("lan1", "10.1.1.10", "8.8.8.8", 443), 100)

    hops = await _trace(inventory, prefixes, client, "10.1.1.10", "8.8.8.8")
    assert len(hops) == 1
    assert hops[0].egress_class == "DEFAULT"
    assert hops[0].verdict == "ALLOW"


async def test_cross_site_routed_gateway(inventory, prefixes):
    """Routing-Discovery OHNE Owner-Tabelle: fw-a routet zum Ziel über das
    Transit-/30, Next-Hop-Gateway = fw-b-Interface-IP (10.99.0.2) → nächster Hop
    per Gateway-Match, Ingress = fw-b/xlink1 (kein Reverse-Lookup nötig)."""
    client, t = make_client()
    add_route(t, "fw-a", "root", "10.2.1.30", "xlink1", gateway="10.99.0.2")
    add_policy_lookup(t, "fw-a", "root",
                      tcp_params("lan1", "10.1.1.10", "10.2.1.30", 443), 100)
    add_route(t, "fw-b", "root", "10.2.1.30", "lan1")
    add_policy_lookup(t, "fw-b", "root",
                      tcp_params("xlink1", "10.1.1.10", "10.2.1.30", 443), 200)

    hops = await _trace(inventory, prefixes, client, "10.1.1.10", "10.2.1.30")
    assert len(hops) == 2
    assert hops[0].egress == "xlink1"
    assert hops[0].egress_class == "ROUTED"
    assert (hops[1].device, hops[1].vdom, hops[1].srcintf) == ("fw-b", "root", "xlink1")
    assert hops[1].egress_class == "LOCAL"
    assert [h.verdict for h in hops] == ["ALLOW", "ALLOW"]
    assert aggregate_verdict(hops) == "ALLOW"


async def test_cross_site_routed_transit_segment(inventory, prefixes):
    """Routing-Discovery via gemeinsames Transit-Segment (Gateway 0.0.0.0,
    connected Route): fw-a-Egress 'xlink1' liegt im selben /30 wie fw-b/xlink1
    → nächster Hop ohne Gateway-IP."""
    client, t = make_client()
    add_route(t, "fw-a", "root", "10.2.1.30", "xlink1")  # gateway 0.0.0.0
    add_policy_lookup(t, "fw-a", "root",
                      tcp_params("lan1", "10.1.1.10", "10.2.1.30", 443), 100)
    add_route(t, "fw-b", "root", "10.2.1.30", "lan1")
    add_policy_lookup(t, "fw-b", "root",
                      tcp_params("xlink1", "10.1.1.10", "10.2.1.30", 443), 200)

    hops = await _trace(inventory, prefixes, client, "10.1.1.10", "10.2.1.30")
    assert len(hops) == 2
    assert hops[0].egress_class == "ROUTED"
    assert (hops[1].device, hops[1].srcintf) == ("fw-b", "xlink1")
    assert aggregate_verdict(hops) == "ALLOW"


async def test_cross_site_routed_prefix_fallback(inventory, prefixes):
    """Fallback: Routing-Discovery greift nicht (Egress 'wan', kein FW-Peer im
    Segment, Gateway extern), aber das Ziel-Präfix gehört fw-b (connected) →
    ROUTED via PrefixTable, Ingress per Reverse-Route zur Quelle."""
    client, t = make_client()
    add_route(t, "fw-a", "root", "10.2.1.30", "wan", gateway="203.0.113.2")
    add_policy_lookup(t, "fw-a", "root",
                      tcp_params("lan1", "10.1.1.10", "10.2.1.30", 443), 100)
    add_route(t, "fw-b", "root", "10.1.1.10", "wan")  # Reverse-Route → Ingress
    add_route(t, "fw-b", "root", "10.2.1.30", "lan1")
    add_policy_lookup(t, "fw-b", "root",
                      tcp_params("wan", "10.1.1.10", "10.2.1.30", 443), 200)

    hops = await _trace(inventory, prefixes, client, "10.1.1.10", "10.2.1.30")
    assert len(hops) == 2
    assert hops[0].egress == "wan"
    assert hops[0].egress_class == "ROUTED"
    assert (hops[1].device, hops[1].srcintf) == ("fw-b", "wan")
    assert aggregate_verdict(hops) == "ALLOW"


async def test_cross_site_multi_vdom_router_then_protect(inventory, prefixes):
    """Zielstandort mit Router-VDOM → VDOM-Link → Schutz-VDOM: der Trace tritt am
    Router-VDOM ein (Reverse-Route zur Quelle geht über 'wan', KEIN VDOM-Link) und
    läuft per VDOM-Link zum Schutz-VDOM. BEIDE VDOM-Policies werden geprüft — der
    Deny auf der Router-VDOM (Policy 220) wird erkannt, nicht erst am Ziel-VDOM."""
    client, t = make_client()
    # fw-a: Ziel via wan, Gateway extern → Routing-Discovery greift nicht → Fallback
    add_route(t, "fw-a", "root", "10.2.9.20", "wan", gateway="203.0.113.2")
    add_policy_lookup(t, "fw-a", "root",
                      tcp_params("lan1", "10.1.1.10", "10.2.9.20", 443), 100)
    # fw-b/root (Router-VDOM): Reverse-Route zur Quelle (Ingress) + Vorwärts-Route
    # über den VDOM-Link vlb0 + DENY-Policy 220
    add_route(t, "fw-b", "root", "10.1.1.10", "wan")
    add_route(t, "fw-b", "root", "10.2.9.20", "vlb0")
    add_policy_lookup(t, "fw-b", "root",
                      tcp_params("wan", "10.1.1.10", "10.2.9.20", 443), 220)
    # fw-b/prot (Schutz-VDOM): Ziel connected hinter vlb1
    add_route(t, "fw-b", "prot", "10.2.9.20", "lan-prot")
    add_policy_lookup(t, "fw-b", "prot",
                      tcp_params("vlb1", "10.1.1.10", "10.2.9.20", 443), 300)

    hops = await _trace(inventory, prefixes, client, "10.1.1.10", "10.2.9.20")
    assert len(hops) == 3
    assert (hops[1].device, hops[1].vdom, hops[1].srcintf) == ("fw-b", "root", "wan")
    assert hops[1].egress_class == "VDOM_LINK"       # Router-VDOM → Schutz-VDOM
    assert hops[1].verdict == "DENY" and hops[1].matched_policy.policyid == 220
    assert (hops[2].device, hops[2].vdom, hops[2].srcintf) == ("fw-b", "prot", "vlb1")
    assert hops[2].egress_class == "LOCAL"
    assert hops[2].after_deny                        # best-effort weiter nach Deny
    assert aggregate_verdict(hops) == "DENY"


async def test_multi_vdom_entry_prefers_sdwan_vdom(inventory, prefixes):
    """Eintritts-VDOM bei Multi-VDOM-Ziel: der Lookup MUSS im VDOM laufen, an dem
    das SD-WAN/Overlay terminiert ('Router'), NICHT im ersten VDOM mit irgendeiner
    Route zur Quelle ('root' via L2-Transfer0). Sonst Lookup im falschen VDOM →
    fälschlich Deny. Regression zum Feld-Report (fw-c: Router/root/L3)."""
    client, t = make_client()
    add_route(t, "fw-a", "root", "10.3.9.20", "wan", gateway="203.0.113.2")
    add_policy_lookup(t, "fw-a", "root",
                      tcp_params("lan1", "10.1.1.10", "10.3.9.20", 443), 100)
    # Ziel-FW: Eintritt über sdwan-c (Router-VDOM) — Reverse-Route zur Quelle dort,
    # KEINE Fixture für 'root' nötig (Overlay-VDOM wird gezielt gewählt).
    add_route(t, "fw-c", "Router", "10.1.1.10", "sdwan-c")
    add_route(t, "fw-c", "Router", "10.3.9.20", "lan-c")
    add_policy_lookup(t, "fw-c", "Router",
                      tcp_params("sdwan-c", "10.1.1.10", "10.3.9.20", 443), 400)

    hops = await _trace(inventory, prefixes, client, "10.1.1.10", "10.3.9.20")
    assert len(hops) == 2
    assert (hops[1].device, hops[1].vdom, hops[1].srcintf) == ("fw-c", "Router", "sdwan-c")
    assert hops[1].egress_class == "LOCAL"
    assert hops[1].verdict == "ALLOW"
    assert aggregate_verdict(hops) == "ALLOW"


async def test_multi_vdom_entry_prefers_edge_vdom_routed(inventory, prefixes):
    """Gerouteter Underlay (kein Tunnel): der Eintritts-VDOM ist der mit der
    Default-Route über ein echtes WAN-Interface ('Router'), NICHT 'root' (das via
    L2-Transfer0 eine Route zur Quelle hat, wo das Paket aber nie ankommt).
    Regression zum Feld-Report 'Lookup lief in der falschen VDOM (root)'."""
    client, t = make_client()
    add_route(t, "fw-a", "root", "10.4.9.20", "wan", gateway="203.0.113.2")
    add_policy_lookup(t, "fw-a", "root",
                      tcp_params("lan1", "10.1.1.10", "10.4.9.20", 443), 100)
    add_route(t, "fw-d", "Router", "10.1.1.10", "wan-d")
    add_route(t, "fw-d", "Router", "10.4.9.20", "lan-d")
    add_policy_lookup(t, "fw-d", "Router",
                      tcp_params("wan-d", "10.1.1.10", "10.4.9.20", 443), 500)

    hops = await _trace(inventory, prefixes, client, "10.1.1.10", "10.4.9.20")
    assert len(hops) == 2
    assert (hops[1].device, hops[1].vdom, hops[1].srcintf) == ("fw-d", "Router", "wan-d")
    assert hops[1].egress_class == "LOCAL"
    assert hops[1].verdict == "ALLOW"
    assert aggregate_verdict(hops) == "ALLOW"


async def test_multi_vdom_entry_prefers_named_router_vdom(inventory, prefixes):
    """Dynamisches Routing (keine statische Default-Route): der Eintritts-VDOM
    wird über den NAMEN 'Router' bestimmt, nicht 'root' (das via L2-Transfer0 eine
    Route zur Quelle hat). Deckt den Feld-Fall ab (BGP übers SD-WAN)."""
    client, t = make_client()
    add_route(t, "fw-a", "root", "10.5.9.20", "wan", gateway="203.0.113.2")
    add_policy_lookup(t, "fw-a", "root",
                      tcp_params("lan1", "10.1.1.10", "10.5.9.20", 443), 100)
    add_route(t, "fw-e", "Router", "10.1.1.10", "wan-e")
    add_route(t, "fw-e", "Router", "10.5.9.20", "lan-e")
    add_policy_lookup(t, "fw-e", "Router",
                      tcp_params("wan-e", "10.1.1.10", "10.5.9.20", 443), 600)

    hops = await _trace(inventory, prefixes, client, "10.1.1.10", "10.5.9.20")
    assert len(hops) == 2
    assert (hops[1].device, hops[1].vdom, hops[1].srcintf) == ("fw-e", "Router", "wan-e")
    assert hops[1].egress_class == "LOCAL"
    assert hops[1].verdict == "ALLOW"
    assert aggregate_verdict(hops) == "ALLOW"


async def test_policy_zero_is_implicit_deny(inventory, prefixes):
    """FortiOS policy-lookup mit policy_id 0 = implizites Deny (keine Regel greift
    live, z.B. Policy-Package im FortiManager nicht installiert) → DENY + Hinweis,
    NICHT UNKNOWN/'nicht im Cache'."""
    client, t = make_client()
    add_route(t, "fw-a", "root", "10.1.2.20", "lan2")
    add_policy_lookup(t, "fw-a", "root",
                      tcp_params("lan1", "10.1.1.10", "10.1.2.20", 443), 0)

    hops = await _trace(inventory, prefixes, client, "10.1.1.10", "10.1.2.20")
    assert len(hops) == 1
    assert hops[0].verdict == "DENY"
    assert hops[0].matched_policy is None
    assert any("Policy 0" in w for w in hops[0].warnings)
    assert aggregate_verdict(hops) == "DENY"


async def test_device_offline_degraded(inventory, prefixes):
    client, t = make_client()
    add_route(t, "fw-a", "root", "10.2.1.30", "vpn-to-b", offline=True)
    # Hop 2 antwortet normal
    add_route(t, "fw-b", "root", "10.2.1.30", "lan1")
    add_policy_lookup(t, "fw-b", "root",
                      tcp_params("vpn-to-a", "10.1.1.10", "10.2.1.30", 443), 200)

    hops = await _trace(inventory, prefixes, client, "10.1.1.10", "10.2.1.30")
    assert hops[0].degraded
    # Cache-Route (static 10.2.0.0/20 via vpn-to-b) trägt den Pfad weiter
    assert hops[0].route["source"] == "cache-static"
    assert hops[0].egress == "vpn-to-b"
    assert hops[0].verdict == "UNKNOWN"
    assert len(hops) == 2 and hops[1].verdict == "ALLOW"
    assert aggregate_verdict(hops) == "DEGRADED"


async def test_unknown_source_raises(inventory, prefixes):
    client, _ = make_client()
    with pytest.raises(TraceError, match="keinem bekannten Standort-Prefix"):
        await _trace(inventory, prefixes, client, "172.16.99.1", "10.1.1.10")


def test_ingress_ambiguity_flags_multiple_owners():
    """Ist dieselbe Quelle gleich spezifisch auf zwei VDOMs connected, warnt der
    Trace (Start kann an der falschen Firewall beginnen) — Feld-Fall xha001/xha002."""
    t = PrefixTable()
    t.add("10.180.42.0/24", "connected", "xha001", "L3", "OT")
    t.add("10.180.42.0/24", "connected", "xha002", "root", "OT")
    warn = _ingress_ambiguity(t, "10.180.42.208", "xha001", "L3")
    assert warn is not None and "xha002/root" in warn

    unique = PrefixTable()
    unique.add("10.180.42.0/24", "connected", "xha002", "root", "OT")
    assert _ingress_ambiguity(unique, "10.180.42.208", "xha002", "root") is None


def test_find_ingress_prefers_connected(inventory, prefixes):
    assert find_ingress(prefixes, inventory, "10.1.1.10") == ("fw-a", "root", "lan1")
    assert find_ingress(prefixes, inventory, "10.2.1.30") == ("fw-b", "root", "lan1")


async def _port_trace(inventory, prefixes, client, src, dst):
    return await run_port_trace(
        src_ip=src, dst_ip=dst, inv=inventory, prefixes=prefixes, client=client,
        overlay_pattern=OVERLAY, max_hops=8)


async def test_port_trace_intra_allow_all(inventory, prefixes):
    """Deep-Tracker teilt den Pfad mit run_trace (nur router/lookup, KEIN
    policy-lookup) und liest die Ports statisch aus dem Cache."""
    client, t = make_client()
    add_route(t, "fw-a", "root", "10.1.2.20", "lan2")
    res = await _port_trace(inventory, prefixes, client, "10.1.1.10", "10.1.2.20")
    assert res["reachable"] is True
    assert len(res["hops"]) == 1 and res["hops"][0]["egress_class"] == "LOCAL"
    # Policy 100 (allow inside-a, service ALL) → alles offen
    assert res["tcp"] == [[1, 65535]] and res["udp"] == [[1, 65535]]
    assert res["limits"]["tcp"] == [] and res["limits"]["udp"] == []


async def test_port_trace_cross_site_two_hops(inventory, prefixes):
    """Zwei-Hop-Pfad (Overlay) → Schnittmenge über beide Hops; kein
    policy-lookup nötig, funktioniert also auch offline aus dem Cache."""
    client, t = make_client()
    add_route(t, "fw-a", "root", "10.2.1.30", "vpn-to-b")
    add_route(t, "fw-b", "root", "10.2.1.30", "lan1")
    res = await _port_trace(inventory, prefixes, client, "10.1.1.10", "10.2.1.30")
    assert res["reachable"] is True
    assert [h["label"] for h in res["hops"]] == ["fw-a/root", "fw-b/root"]
    assert res["tcp"] == [[1, 65535]]        # beide Hops allow ALL


async def test_candidates_ordered_with_hit(inventory, prefixes):
    client, t = make_client()
    add_route(t, "fw-a", "root", "10.1.2.20", "lan2")
    add_policy_lookup(t, "fw-a", "root",
                      tcp_params("lan1", "10.1.1.10", "10.1.2.20", 443), 100)
    hops = await _trace(inventory, prefixes, client, "10.1.1.10", "10.1.2.20")
    cand = hops[0].candidates
    # Reihenfolge wie im Package; Treffer markiert
    assert [c.policyid for c in cand] == [100, 110]
    assert [c.hit for c in cand] == [True, False]
