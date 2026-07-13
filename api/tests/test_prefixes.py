"""PrefixTable: LPM, Quellen-Priorität, Default-Routen-Ausschluss."""
from __future__ import annotations

import ipaddress

from inventory.prefixes import PrefixTable
from inventory.store import Inventory


def test_longest_prefix_wins():
    t = PrefixTable()
    t.add("10.1.0.0/20", "static", "fw-a", "root", "vpn")
    t.add("10.1.1.0/24", "connected", "fw-b", "root", "lan1")
    hit = t.lookup("10.1.1.10")
    assert hit.device == "fw-b" and hit.source == "connected"


def test_source_priority_on_tie():
    t = PrefixTable()
    t.add("10.1.1.0/24", "static", "fw-a", "root", "vpn")
    t.add("10.1.1.0/24", "connected", "fw-b", "root", "lan1")
    t.add("10.1.1.0/24", "override", "fw-c", "root", None, site_name="Site C")
    hits = t.lookup_all("10.1.1.10")
    assert [h.source for h in hits] == ["override", "connected", "static"]
    assert t.lookup("10.1.1.10").device == "fw-c"


def test_default_route_excluded():
    t = PrefixTable()
    t.add("0.0.0.0/0", "static", "fw-a", "root", "wan")
    assert t.lookup("8.8.8.8") is None
    assert t.entries == []


def test_no_match_returns_none():
    t = PrefixTable()
    t.add("10.1.0.0/20", "connected", "fw-a", "root", "lan1")
    assert t.lookup("192.168.99.1") is None


def test_lab_inventory_prefixes(inventory, prefixes):
    # Site A connected schlägt die Site-A-Static-Route von fw-b
    hit = prefixes.lookup("10.1.1.10")
    assert (hit.device, hit.vdom, hit.interface) == ("fw-a", "root", "lan1")
    # Site B aus Sicht der Tabelle: connected auf fw-b gewinnt (LPM /24 > /20)
    hit = prefixes.lookup("10.2.1.30")
    assert (hit.device, hit.source) == ("fw-b", "connected")
    # DMZ-Subnetz liegt auf fw-a/dmz
    hit = prefixes.lookup("10.1.8.20")
    assert (hit.device, hit.vdom) == ("fw-a", "dmz")


def test_lookup_owner_prefers_connected_over_specific_static():
    """Besitz: connected/override schlägt static UNABHÄNGIG von der Maske. Eine
    spezifischere statische Transit-Route darf das connected-Netz nicht überstimmen
    (sonst falscher Owner-Hop) — Feld-Fall xha001(static /26) vs xha002(connected /25)."""
    t = PrefixTable()
    t.add("10.180.42.192/26", "static", "xha001", "Router", "wan1")  # spezifischer, nur Transit
    t.add("10.180.42.128/25", "connected", "xha002", "L3", "lan")    # echter Owner
    owner = t.lookup_owner("10.180.42.208")
    assert (owner.device, owner.source) == ("xha002", "connected")

    # Kein connected/override → längste static (Ziel hinter L3-Switch/Downstream)
    only_static = PrefixTable()
    only_static.add("10.9.0.0/24", "static", "fw-x", "root", "lan")
    assert only_static.lookup_owner("10.9.0.5").device == "fw-x"
    assert only_static.lookup_owner("192.168.1.1") is None


def test_secondary_ip_becomes_connected():
    """Secondary-IPs eines Interfaces landen als connected-Netz im Inventory und
    in der PrefixTable — sonst fehlt das Ziel-/Quell-Netz (Feld-Fall WD-OT-HQ)."""
    rows = [
        {"adom": "corp", "kind": "device", "key": "fw-s",
         "data": {"name": "fw-s", "vdom": [{"name": "root"}]}},
        {"adom": "corp", "kind": "interface", "key": "fw-s", "data": [
            {"name": "port1", "ip": ["10.7.0.1", "255.255.255.0"], "vdom": ["root"],
             "secondaryip": [{"ip": ["10.7.9.1", "255.255.255.128"]}]},
        ]},
    ]
    inv = Inventory.build(rows, synced_at="2026-07-13T00:00:00+00:00")
    nets = {n for n, _ in inv.connected_networks("fw-s", "root")}
    assert ipaddress.IPv4Network("10.7.0.0/24") in nets
    assert ipaddress.IPv4Network("10.7.9.0/25") in nets  # Secondary
    owner = inv.build_prefix_table().lookup_owner("10.7.9.20")
    assert (owner.device, owner.source) == ("fw-s", "connected")


def test_site_override_wins(inventory):
    table = inventory.build_prefix_table(
        [{"name": "Sonderfall", "cidr": "10.1.1.0/24", "device": "fw-x", "vdom": "root"}]
    )
    assert table.lookup("10.1.1.10").device == "fw-x"
