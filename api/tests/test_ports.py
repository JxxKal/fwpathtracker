"""Deep-Tracker-Kern: Intervall-Algebra, Service-/Adress-Resolver (rekursiv über
Gruppen), First-Match-Portmenge pro Hop und Pfad-Schnitt inkl. limitierendem Hop.
Rein aus dem Cache — kein FMG nötig."""
from __future__ import annotations

from engine.ports import combine, hop_allowed, intersect, merge, subtract
from inventory.store import Inventory

ADOM = "corp"


def _row(kind, key, data):
    return {"adom": ADOM, "kind": kind, "key": key, "data": data}


def _inv(policies: list[dict]) -> Inventory:
    """Minimales Lab: eine FW/VDOM, ein Package, Objekte + Gruppen."""
    rows = [
        _row("device", "fw", {"name": "fw", "vdom": [{"name": "root"}]}),
        _row("interface", "fw", [
            {"name": "lan", "ip": ["10.0.0.1", "255.255.255.0"], "vdom": ["root"]},
            {"name": "wan", "ip": ["10.0.9.1", "255.255.255.0"], "vdom": ["root"]},
        ]),
        _row("package", "pkg", {"name": "pkg", "scope member": [{"name": "fw", "vdom": "root"}]}),
        _row("policy", "pkg", policies),
        # Adress-Objekte + Gruppe
        _row("address", "host-a", {"name": "host-a", "subnet": ["10.0.0.10", "255.255.255.255"]}),
        _row("address", "srv-1", {"name": "srv-1", "subnet": ["10.0.9.10", "255.255.255.255"]}),
        _row("address", "srv-2", {"name": "srv-2", "subnet": ["10.0.9.11", "255.255.255.255"]}),
        _row("addrgrp", "srv-grp", {"name": "srv-grp", "member": ["srv-1", "srv-2"]}),
        # Service-Objekte + Gruppe
        _row("service", "HTTPS", {"name": "HTTPS", "tcp-portrange": ["443"]}),
        _row("service", "HTTP", {"name": "HTTP", "tcp-portrange": ["80"]}),
        _row("service", "DNS", {"name": "DNS", "tcp-portrange": ["53"], "udp-portrange": ["53"]}),
        _row("service", "RANGE", {"name": "RANGE", "tcp-portrange": ["8000-8100"]}),
        _row("service", "SRC", {"name": "SRC", "tcp-portrange": ["22:1024-65535"]}),
        _row("servicegrp", "web", {"name": "web", "member": ["HTTP", "HTTPS"]}),
    ]
    return Inventory.build(rows)


def _pol(pid, action, src, dst, svc, **extra):
    p = {"policyid": pid, "name": f"p{pid}", "action": action, "status": 1,
         "srcintf": ["any"], "dstintf": ["any"], "srcaddr": src, "dstaddr": dst, "service": svc}
    p.update(extra)
    return p


# ── Intervall-Algebra ─────────────────────────────────────────────────────────

def test_merge_adjacent_and_overlap():
    assert merge([(80, 80), (81, 90), (85, 100)]) == [(80, 100)]
    assert merge([(1, 10), (20, 30)]) == [(1, 10), (20, 30)]
    assert merge([(5, 5), (1, 3)]) == [(1, 3), (5, 5)]


def test_intersect():
    assert intersect([(1, 100)], [(50, 200)]) == [(50, 100)]
    assert intersect([(1, 10), (20, 30)], [(5, 25)]) == [(5, 10), (20, 25)]
    assert intersect([(1, 10)], [(20, 30)]) == []


def test_subtract():
    assert subtract([(1, 100)], [(50, 60)]) == [(1, 49), (61, 100)]
    assert subtract([(1, 100)], [(1, 100)]) == []
    assert subtract([(1, 100)], []) == [(1, 100)]
    assert subtract([(1, 10), (20, 30)], [(5, 25)]) == [(1, 4), (26, 30)]


# ── Resolver ──────────────────────────────────────────────────────────────────

def test_service_intervals_all_and_objects():
    inv = _inv([])
    assert inv.service_intervals(ADOM, ["ALL"]) == {"tcp": [(1, 65535)], "udp": [(1, 65535)]}
    assert inv.service_intervals(ADOM, ["ALL_TCP"]) == {"tcp": [(1, 65535)], "udp": []}
    assert inv.service_intervals(ADOM, ["HTTPS"]) == {"tcp": [(443, 443)], "udp": []}
    assert inv.service_intervals(ADOM, ["DNS"]) == {"tcp": [(53, 53)], "udp": [(53, 53)]}
    assert inv.service_intervals(ADOM, ["RANGE"]) == {"tcp": [(8000, 8100)], "udp": []}
    # 'dst:src' → nur dst-Port zählt
    assert inv.service_intervals(ADOM, ["SRC"]) == {"tcp": [(22, 22)], "udp": []}


def test_service_group_recursion():
    inv = _inv([])
    got = inv.service_intervals(ADOM, ["web"])
    assert merge(got["tcp"]) == [(80, 80), (443, 443)]
    assert got["udp"] == []


def test_addr_matches_all_object_group():
    inv = _inv([])
    assert inv.addr_matches(ADOM, ["all"], "10.0.0.10") is True
    assert inv.addr_matches(ADOM, ["host-a"], "10.0.0.10") is True
    assert inv.addr_matches(ADOM, ["host-a"], "10.0.0.11") is False
    # Gruppe rekursiv
    assert inv.addr_matches(ADOM, ["srv-grp"], "10.0.9.11") is True
    assert inv.addr_matches(ADOM, ["srv-grp"], "10.0.9.99") is False


# ── Pro-Hop-Portmenge (First-Match) ───────────────────────────────────────────

def test_hop_allowed_single_allow():
    inv = _inv([_pol(1, 1, ["all"], ["all"], ["web"])])
    pols = inv.candidate_policies("fw", "root", "lan", "wan")
    r = hop_allowed(inv, ADOM, pols, "10.0.0.10", "10.0.9.10")
    assert r["tcp"] == [(80, 80), (443, 443)] and r["udp"] == []


def test_hop_allowed_deny_shadows_later_allow():
    # First-Match: Deny auf 443 gewinnt gegen späteres allow-ALL
    inv = _inv([
        _pol(1, 0, ["all"], ["all"], ["HTTPS"]),
        _pol(2, 1, ["all"], ["all"], ["ALL"]),
    ])
    pols = inv.candidate_policies("fw", "root", "lan", "wan")
    r = hop_allowed(inv, ADOM, pols, "10.0.0.10", "10.0.9.10")
    assert (443, 443) not in r["tcp"]
    assert intersect(r["tcp"], [(443, 443)]) == []
    assert intersect(r["tcp"], [(80, 80)]) == [(80, 80)]      # 80 offen
    assert r["udp"] == [(1, 65535)]                            # UDP komplett offen


def test_hop_allowed_dst_address_filters():
    # Allow nur für srv-1; Anfrage an srv-2 → keine passende Policy → nichts offen
    inv = _inv([_pol(1, 1, ["all"], ["srv-1"], ["ALL"])])
    pols = inv.candidate_policies("fw", "root", "lan", "wan")
    assert hop_allowed(inv, ADOM, pols, "10.0.0.10", "10.0.9.11")["tcp"] == []
    assert hop_allowed(inv, ADOM, pols, "10.0.0.10", "10.0.9.10")["tcp"] == [(1, 65535)]


def test_candidate_policies_matches_any_interface_alias():
    """FMG-Wurzelursache (#816): ein lokales Interface kann local-intf MEHRERER
    dynamischer Interfaces/Zonen sein. Eine Policy, die einen ANDEREN Alias
    desselben Interfaces referenziert, muss trotzdem als Kandidat gelten — sonst
    ist der Zonenfilter zu streng und Deep-Tracker vs. Einzel-Dienst inkonsistent."""
    rows = [
        _row("device", "fw", {"name": "fw", "vdom": [{"name": "root"}]}),
        _row("interface", "fw", [
            {"name": "port5", "ip": ["10.0.0.1", "255.255.255.0"], "vdom": ["root"]},
            {"name": "port6", "ip": ["10.0.9.1", "255.255.255.0"], "vdom": ["root"]},
        ]),
        # port5 ist local-intf ZWEIER dynamischer Interfaces (AdminSrv + Transfer)
        _row("zone", "AdminSrv", {"name": "AdminSrv", "dynamic_mapping": [
            {"_scope": [{"name": "fw", "vdom": "root"}], "local-intf": ["port5"]}]}),
        _row("zone", "Transfer", {"name": "Transfer", "dynamic_mapping": [
            {"_scope": [{"name": "fw", "vdom": "root"}], "local-intf": ["port5"]}]}),
        _row("zone", "AD", {"name": "AD", "dynamic_mapping": [
            {"_scope": [{"name": "fw", "vdom": "root"}], "local-intf": ["port6"]}]}),
        _row("package", "pkg", {"name": "pkg", "scope member": [{"name": "fw", "vdom": "root"}]}),
        _row("policy", "pkg", [
            {"policyid": 816, "name": "WD-OT-2-AD", "action": 1, "status": 1,
             "srcintf": ["Transfer"], "dstintf": ["AD"],   # anderer Alias als zone_of
             "srcaddr": ["all"], "dstaddr": ["all"], "service": ["ALL"]},
        ]),
    ]
    inv = Inventory.build(rows)
    assert inv.zones_of("fw", "root", "port5") == {"port5", "AdminSrv", "Transfer"}
    # Trotz zone_of=erster Alias matcht die Policy über den Transfer-Alias:
    cands = inv.candidate_policies("fw", "root", "port5", "port6")
    assert [p["policyid"] for p in cands] == [816]
    # → jetzt schon strict, kein Widen nötig
    _, widened = inv.flow_policies("fw", "root", "port5", "port6", ADOM, "10.0.0.10", "10.0.9.10")
    assert widened is False


def test_zones_of_resolves_default_mapping():
    """obj/dynamic/interface kann statt per-Gerät dynamic_mapping ein
    geräteübergreifendes Default-Mapping (defmap-intf) tragen — dann muss zones_of
    das normalisierte Interface trotzdem als Alias des physischen Egress liefern.
    Genau das fehlte (Feld-Fall Transfer/WD_OT_AD ↔ L3-WAN0)."""
    rows = [
        _row("device", "fw", {"name": "fw", "vdom": [{"name": "L3"}]}),
        _row("interface", "fw", [
            {"name": "L3-WAN0", "ip": ["10.0.0.1", "255.255.255.0"], "vdom": ["L3"]},
        ]),
        # 'Transfer' hat KEIN per-Gerät-Mapping, nur ein Default-Mapping auf L3-WAN0
        _row("zone", "Transfer", {"name": "Transfer", "default-mapping": "enable",
                                  "defmap-intf": "L3-WAN0"}),
        _row("package", "pkg", {"name": "pkg", "scope member": [{"name": "fw", "vdom": "L3"}]}),
        _row("policy", "pkg", [
            {"policyid": 816, "name": "WD-OT-2-AD", "action": 1, "status": 1,
             "srcintf": ["any"], "dstintf": ["Transfer"],   # normalisiertes Ziel-Interface
             "srcaddr": ["all"], "dstaddr": ["all"], "service": ["ALL"]},
        ]),
    ]
    inv = Inventory.build(rows)
    assert inv.dyn_default.get("Transfer") == ["L3-WAN0"]
    assert "Transfer" in inv.zones_of("fw", "L3", "L3-WAN0")
    # → Policy matcht jetzt strikt über den Default-Mapping-Alias, kein Widen nötig
    cands = inv.candidate_policies("fw", "L3", "any", "L3-WAN0")
    assert [p["policyid"] for p in cands] == [816]


def test_flow_policies_widens_on_incomplete_zone_data():
    """Feld-Fall: die erlaubende Policy matcht per Adresse + Ziel-Interface, ihr
    Quell-Interface (Zone) fehlt aber im Cache → strict verwirft sie, flow_policies
    schaltet auf die breitere Auswahl (widened=True) und nimmt sie mit."""
    inv = _inv([
        # Policy erlaubt host-a → srv-1 (HTTPS), aber srcintf ist eine Zone, die auf
        # diesem VDOM im Cache NICHT dem Ingress 'lan' zugeordnet ist.
        _pol(816, 1, ["host-a"], ["srv-1"], ["HTTPS"],
             srcintf=["OT-Restrict-Zone"], dstintf=["wan"]),
    ])
    strict = inv.candidate_policies("fw", "root", "lan", "wan")
    assert strict == []                                   # Quell-Zone matcht nicht
    pols, widened = inv.flow_policies("fw", "root", "lan", "wan", ADOM,
                                      "10.0.0.10", "10.0.9.10")
    assert widened is True
    assert [p["policyid"] for p in pols] == [816]
    r = hop_allowed(inv, ADOM, pols, "10.0.0.10", "10.0.9.10")
    assert r["tcp"] == [(443, 443)]                       # nun konsistent erlaubt


def test_flow_policies_widens_on_egress_interface_mismatch():
    """Feld-Fall Transit (#816/#249): die live greifende Regel hat ein anderes
    (normalisiertes) ZIEL-Interface als der Routing-Egress — weder Quell- noch
    Ziel-Interface matchen den Hop. Der adressbasierte Widen findet sie trotzdem,
    sonst zeigt der Deep-Tracker fälschlich 'keine Ports' (≠ Einzel-Dienst)."""
    inv = _inv([
        _pol(816, 1, ["host-a"], ["srv-1"], ["DNS"],
             srcintf=["Transfer"], dstintf=["WD_OT_AD"]),
    ])
    assert inv.candidate_policies("fw", "root", "lan", "wan") == []
    pols, widened = inv.flow_policies("fw", "root", "lan", "wan", ADOM,
                                      "10.0.0.10", "10.0.9.10")
    assert widened is True and [p["policyid"] for p in pols] == [816]
    r = hop_allowed(inv, ADOM, pols, "10.0.0.10", "10.0.9.10")
    assert r["tcp"] == [(53, 53)] and r["udp"] == [(53, 53)]


def test_flow_policies_strict_when_zone_matches():
    """Passt der Zonenfilter (srcintf 'any'), bleibt es bei der präzisen strict-
    Auswahl (widened=False) — kein Über-Melden."""
    inv = _inv([_pol(1, 1, ["host-a"], ["srv-1"], ["HTTPS"], dstintf=["wan"])])
    pols, widened = inv.flow_policies("fw", "root", "lan", "wan", ADOM,
                                      "10.0.0.10", "10.0.9.10")
    assert widened is False
    assert [p["policyid"] for p in pols] == [1]


def test_hop_allowed_warns_on_isdb_and_negate():
    inv = _inv([
        _pol(1, 1, ["all"], ["all"], ["ALL"], **{"internet-service": "enable"}),
        _pol(2, 1, ["all"], ["all"], ["ALL"], **{"service-negate": 1}),
    ])
    pols = inv.candidate_policies("fw", "root", "lan", "wan")
    r = hop_allowed(inv, ADOM, pols, "10.0.0.10", "10.0.9.10")
    assert any("ISDB" in w for w in r["warnings"])
    assert any("negier" in w for w in r["warnings"])


# ── Pfad-Schnitt + limitierender Hop ──────────────────────────────────────────

def test_combine_intersection_and_limit():
    hops = [
        {"label": "fw-a/root", "tcp": [(1, 65535)], "udp": [(1, 65535)]},
        {"label": "fw-b/Router", "tcp": [(80, 80), (443, 443)], "udp": []},
    ]
    out = combine(hops)
    assert out["tcp"] == [(80, 80), (443, 443)]
    assert out["udp"] == []
    # Alles außer 80/443 stirbt an fw-b/Router
    assert {l["hop"] for l in out["limits"]["tcp"]} == {"fw-b/Router"}
    assert any(l["range"] == [1, 79] for l in out["limits"]["tcp"])
    assert {l["hop"] for l in out["limits"]["udp"]} == {"fw-b/Router"}
