"""Session-Probe (firewall/session): Normalisierung, Nachfilter, Warnungen —
und die Integration in run_trace (opt-in, darf einen Trace nie kippen).
"""
from __future__ import annotations

from engine.path import run_trace
from engine.sessions import (
    normalize_session, probe_sessions, session_matches, session_params,
    session_warnings,
)
from fmg.client import FmgClient
from fmg.transport import FixtureTransport
from fmg_fixtures import (
    add_policy_lookup, add_route, add_sessions, session_entry, tcp_params,
)

OVERLAY = "(?i)(vpn|ovl|sdwan|tun|ipsec)"


def make_client() -> tuple[FmgClient, FixtureTransport]:
    t = FixtureTransport()
    return FmgClient(t, auth_mode="token"), t


async def _trace(inventory, prefixes, client, src, dst, port=443, sessions=False):
    return await run_trace(
        src_ip=src, dst_ip=dst, protocol="tcp", dst_port=port,
        inv=inventory, prefixes=prefixes, client=client,
        overlay_pattern=OVERLAY, max_hops=8, probe_sessions=sessions,
    )


# ── Bausteine ────────────────────────────────────────────────────────────────

def test_session_params_are_readonly_query():
    p = session_params("10.1.1.10", "10.1.2.20", "tcp", 443)
    assert p["srcaddr"] == "10.1.1.10" and p["dstaddr"] == "10.1.2.20"
    assert p["protocol"] == 6 and p["dstport"] == 443
    assert p["ip_version"] == "ipv4"


def test_normalize_accepts_field_aliases():
    a = normalize_session({"src": "10.1.1.10", "dst": "10.1.2.20", "proto": 6,
                           "srcport": 51001, "dstport": 443, "policyid": 100})
    b = normalize_session({"srcip": "10.1.1.10", "dstip": "10.1.2.20",
                           "protocol": "tcp", "sport": 51001, "dport": 443,
                           "policy_id": "100"})
    for s in (a, b):
        assert (s["src"], s["dst"], s["protocol"], s["dstport"], s["policyid"]) == \
            ("10.1.1.10", "10.1.2.20", "tcp", 443, 100)


def test_matching_is_direction_and_port_aware():
    sess = normalize_session(session_entry("10.1.1.10", "10.1.2.20", dport=443))
    assert session_matches(sess, "10.1.1.10", "10.1.2.20", "tcp", 443)
    # Gegenrichtung ist eine ANDERE Session
    assert not session_matches(sess, "10.1.2.20", "10.1.1.10", "tcp", 443)
    assert not session_matches(sess, "10.1.1.10", "10.1.2.20", "tcp", 22)
    assert not session_matches(sess, "10.1.1.10", "10.1.2.20", "udp", 443)


def test_matching_follows_dnat_to_the_mapped_ip():
    sess = normalize_session({**session_entry("10.1.1.10", "203.0.113.50"),
                              "nat_dst": "10.1.2.20"})
    assert session_matches(sess, "10.1.1.10", "10.1.2.20", "tcp", 443)


def test_warning_when_traffic_flows_despite_deny():
    probe = {"match_count": 2, "returned": 2, "truncated": False,
             "server_filtered": True, "policy_ids": [100]}
    warns = session_warnings(probe, verdict="DENY", policy_id=None)
    assert len(warns) == 1 and "DENY" in warns[0] and "#100" in warns[0]


def test_warning_when_live_rule_differs_from_lookup():
    probe = {"match_count": 1, "returned": 1, "truncated": False,
             "server_filtered": True, "policy_ids": [100]}
    warns = session_warnings(probe, verdict="ALLOW", policy_id=200)
    assert len(warns) == 1 and "#100" in warns[0] and "#200" in warns[0]


def test_no_warning_when_theory_and_reality_agree():
    probe = {"match_count": 1, "returned": 1, "truncated": False,
             "server_filtered": True, "policy_ids": [100]}
    assert session_warnings(probe, verdict="ALLOW", policy_id=100) == []
    # Kein Verkehr bei vollständiger Liste ist der Normalfall — keine Warnung.
    empty = {"match_count": 0, "returned": 0, "truncated": False,
             "server_filtered": None, "policy_ids": []}
    assert session_warnings(empty, verdict="ALLOW", policy_id=100) == []


def test_truncated_negative_is_flagged_as_inconclusive():
    probe = {"match_count": 0, "returned": 1000, "truncated": True,
             "server_filtered": False, "policy_ids": []}
    warns = session_warnings(probe, verdict="ALLOW", policy_id=100)
    assert len(warns) == 1 and "kein Beweis" in warns[0]


async def test_probe_filters_client_side_when_device_ignores_filters():
    """Ältere Builds liefern ALLE Sessions — der Nachfilter muss greifen und die
    Antwort als ungefiltert kennzeichnen."""
    client, t = make_client()
    add_sessions(t, "fw-a", "root", src="10.1.1.10", dst="10.1.2.20", dst_port=443,
                 sessions=[
                     session_entry("10.9.9.9", "10.8.8.8", dport=80, policyid=1),
                     session_entry("10.1.1.10", "10.1.2.20", dport=443, policyid=100),
                     session_entry("10.1.1.10", "10.1.2.20", dport=22, policyid=101),
                 ])
    probe = await probe_sessions(client, "corp", "fw-a", "root",
                                 src_ip="10.1.1.10", dst_ip="10.1.2.20",
                                 protocol="tcp", dst_port=443)
    assert probe["match_count"] == 1 and probe["returned"] == 3
    assert probe["server_filtered"] is False
    assert probe["policy_ids"] == [100]
    assert probe["samples"][0]["dstport"] == 443


# ── Integration in den Trace ─────────────────────────────────────────────────

async def test_trace_without_flag_does_not_query_sessions(inventory, prefixes):
    """Ohne Opt-in darf KEIN Session-Call rausgehen — der FixtureTransport
    würde einen unregistrierten Request sofort quittieren."""
    client, t = make_client()
    add_route(t, "fw-a", "root", "10.1.2.20", "lan2")
    add_policy_lookup(t, "fw-a", "root",
                      tcp_params("lan1", "10.1.1.10", "10.1.2.20", 443), 100)

    hops = await _trace(inventory, prefixes, client, "10.1.1.10", "10.1.2.20")
    assert hops[0].sessions is None
    assert "session_probe" not in hops[0].debug


async def test_trace_with_sessions_confirms_the_allow(inventory, prefixes):
    client, t = make_client()
    add_route(t, "fw-a", "root", "10.1.2.20", "lan2")
    add_policy_lookup(t, "fw-a", "root",
                      tcp_params("lan1", "10.1.1.10", "10.1.2.20", 443), 100)
    add_sessions(t, "fw-a", "root", src="10.1.1.10", dst="10.1.2.20", dst_port=443,
                 sessions=[session_entry("10.1.1.10", "10.1.2.20", dport=443,
                                         policyid=100, srcintf="lan1",
                                         dstintf="lan2")])

    hops = await _trace(inventory, prefixes, client, "10.1.1.10", "10.1.2.20",
                        sessions=True)
    hop = hops[0]
    assert hop.verdict == "ALLOW"
    assert hop.sessions is not None
    assert hop.sessions.match_count == 1 and hop.sessions.policy_ids == [100]
    assert hop.sessions.server_filtered is True
    assert hop.warnings == []
    # Debug trägt die Abfrage zum Nachstellen, aber nicht die Session-Liste.
    assert hop.debug["session_probe"]["summary"]["match_count"] == 1
    assert "samples" not in hop.debug["session_probe"]["summary"]


async def test_trace_reports_traffic_that_contradicts_the_deny(inventory, prefixes):
    client, t = make_client()
    add_route(t, "fw-a", "root", "10.1.2.20", "lan2")
    add_policy_lookup(t, "fw-a", "root",
                      tcp_params("lan1", "10.1.1.10", "10.1.2.20", 443), None)
    add_sessions(t, "fw-a", "root", src="10.1.1.10", dst="10.1.2.20", dst_port=443,
                 sessions=[session_entry("10.1.1.10", "10.1.2.20", dport=443,
                                         policyid=100)])

    hops = await _trace(inventory, prefixes, client, "10.1.1.10", "10.1.2.20",
                        sessions=True)
    hop = hops[0]
    assert hop.verdict == "DENY"
    assert hop.sessions.match_count == 1
    assert any("DENY" in w and "#100" in w for w in hop.warnings)


async def test_trace_reports_rule_mismatch(inventory, prefixes):
    client, t = make_client()
    add_route(t, "fw-a", "root", "10.1.2.20", "lan2")
    add_policy_lookup(t, "fw-a", "root",
                      tcp_params("lan1", "10.1.1.10", "10.1.2.20", 443), 100)
    add_sessions(t, "fw-a", "root", src="10.1.1.10", dst="10.1.2.20", dst_port=443,
                 sessions=[session_entry("10.1.1.10", "10.1.2.20", dport=443,
                                         policyid=110)])

    hops = await _trace(inventory, prefixes, client, "10.1.1.10", "10.1.2.20",
                        sessions=True)
    assert any("#110" in w and "#100" in w for w in hops[0].warnings)


async def test_failed_probe_does_not_break_the_trace(inventory, prefixes):
    client, t = make_client()
    add_route(t, "fw-a", "root", "10.1.2.20", "lan2")
    add_policy_lookup(t, "fw-a", "root",
                      tcp_params("lan1", "10.1.1.10", "10.1.2.20", 443), 100)
    add_sessions(t, "fw-a", "root", src="10.1.1.10", dst="10.1.2.20", dst_port=443,
                 offline=True)

    hops = await _trace(inventory, prefixes, client, "10.1.1.10", "10.1.2.20",
                        sessions=True)
    hop = hops[0]
    assert hop.verdict == "ALLOW"           # Verdict bleibt unberührt
    assert hop.sessions is None
    assert any("Session-Abfrage" in w for w in hop.warnings)
