"""Gemeinsame Test-Fixtures: synthetisches Lab mit 2 Sites + VDOM-Link.

Topologie:
  Site A (10.1.0.0/20) — fw-a (VDOMs root + dmz, ADOM corp)
    root: lan1 10.1.1.1/24, lan2 10.1.2.1/24, vpn-to-b (tunnel), wan,
          xlink1 10.99.0.1/30 (Transit zu fw-b, geroutet), vlink0
    dmz:  vlink1, dmz-lan 10.1.8.1/24
  Site B (10.2.0.0/20) — fw-b (VDOM root, ADOM corp)
    root: lan1 10.2.1.1/24, vpn-to-a (tunnel), wan, xlink1 10.99.0.2/30
  Full-Mesh: statische Routen über die vpn-Tunnel; Default-Route via wan;
  gerouteter Underlay-Transit fw-a↔fw-b über xlink1 (10.99.0.0/30).
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from inventory.store import Inventory  # noqa: E402

ADOM = "corp"


def _row(kind: str, key: str, data) -> dict:
    return {"adom": ADOM, "kind": kind, "key": key, "data": data}


def lab_snapshot_rows() -> list[dict]:
    return [
        _row("device", "fw-a", {"name": "fw-a", "vdom": [{"name": "root"}, {"name": "dmz"}]}),
        _row("device", "fw-b", {"name": "fw-b", "vdom": [{"name": "root"}, {"name": "prot"}]}),

        _row("interface", "fw-a", [
            {"name": "lan1", "ip": ["10.1.1.1", "255.255.255.0"], "vdom": ["root"]},
            {"name": "lan2", "ip": ["10.1.2.1", "255.255.255.0"], "vdom": ["root"]},
            {"name": "vpn-to-b", "type": "tunnel", "vdom": ["root"]},
            {"name": "wan", "ip": ["203.0.113.1", "255.255.255.252"], "vdom": ["root"]},
            {"name": "xlink1", "ip": ["10.99.0.1", "255.255.255.252"], "vdom": ["root"]},
            {"name": "vlink0", "type": "vdom-link", "vdom": ["root"]},
            {"name": "vlink1", "type": "vdom-link", "vdom": ["dmz"]},
            {"name": "dmz-lan", "ip": ["10.1.8.1", "255.255.255.0"], "vdom": ["dmz"]},
        ]),
        _row("interface", "fw-b", [
            {"name": "lan1", "ip": ["10.2.1.1", "255.255.255.0"], "vdom": ["root"]},
            {"name": "vpn-to-a", "type": "tunnel", "vdom": ["root"]},
            {"name": "wan", "ip": ["198.51.100.1", "255.255.255.252"], "vdom": ["root"]},
            {"name": "xlink1", "ip": ["10.99.0.2", "255.255.255.252"], "vdom": ["root"]},
            # Multi-VDOM: root=Router-VDOM → VDOM-Link vlb0/vlb1 → prot=Schutz-VDOM
            {"name": "vlb0", "type": "vdom-link", "vdom": ["root"]},
            {"name": "vlb1", "type": "vdom-link", "vdom": ["prot"]},
            {"name": "lan-prot", "ip": ["10.2.9.1", "255.255.255.0"], "vdom": ["prot"]},
        ]),

        _row("zone", "inside-a", {"name": "inside-a", "dynamic_mapping": [
            {"_scope": [{"name": "fw-a", "vdom": "root"}], "local-intf": ["lan1", "lan2"]},
        ]}),
        _row("zone", "overlay", {"name": "overlay", "dynamic_mapping": [
            {"_scope": [{"name": "fw-a", "vdom": "root"}], "local-intf": ["vpn-to-b"]},
            {"_scope": [{"name": "fw-b", "vdom": "root"}], "local-intf": ["vpn-to-a"]},
        ]}),

        _row("package", "pkg-a", {"name": "pkg-a", "scope member": [
            {"name": "fw-a", "vdom": "root"}, {"name": "fw-a", "vdom": "dmz"},
        ]}),
        _row("package", "pkg-b", {"name": "pkg-b", "scope member": [
            {"name": "fw-b", "vdom": "root"},
        ]}),
        _row("package", "pkg-b-prot", {"name": "pkg-b-prot", "scope member": [
            {"name": "fw-b", "vdom": "prot"},
        ]}),

        _row("policy", "pkg-a", [
            {"policyid": 100, "name": "allow-inside", "action": 1, "status": 1,
             "srcintf": ["inside-a"], "dstintf": ["any"],
             "srcaddr": ["all"], "dstaddr": ["all"], "service": ["ALL"]},
            {"policyid": 110, "name": "deny-guest", "action": 0, "status": 1,
             "srcintf": ["any"], "dstintf": ["any"],
             "srcaddr": ["all"], "dstaddr": ["all"], "service": ["ALL"]},
        ]),
        _row("policy", "pkg-b", [
            {"policyid": 200, "name": "allow-from-a", "action": 1, "status": 1,
             "srcintf": ["overlay"], "dstintf": ["any"],
             "srcaddr": ["all"], "dstaddr": ["all"], "service": ["ALL"]},
            {"policyid": 210, "name": "deny-legacy", "action": 0, "status": 1,
             "srcintf": ["any"], "dstintf": ["any"],
             "srcaddr": ["all"], "dstaddr": ["all"], "service": ["ALL"]},
            {"policyid": 220, "name": "deny-router-transit", "action": 0, "status": 1,
             "srcintf": ["any"], "dstintf": ["vlb0"],
             "srcaddr": ["all"], "dstaddr": ["all"], "service": ["ALL"]},
        ]),
        _row("policy", "pkg-b-prot", [
            {"policyid": 300, "name": "allow-to-server", "action": 1, "status": 1,
             "srcintf": ["vlb1"], "dstintf": ["lan-prot"],
             "srcaddr": ["all"], "dstaddr": ["all"], "service": ["ALL"]},
        ]),

        # Site C — Multi-VDOM wie im Feld: SD-WAN terminiert im 'Router'-VDOM,
        # 'L2-Transfer0' liegt im 'root'-VDOM (hat zwar eine Route zur Quelle, aber
        # dort kommt inter-site Traffic nie an → Eintritt muss 'Router' sein).
        _row("device", "fw-c", {"name": "fw-c", "vdom": [{"name": "root"}, {"name": "Router"}]}),
        _row("interface", "fw-c", [
            {"name": "L2-Transfer0", "ip": ["10.3.5.1", "255.255.255.0"], "vdom": ["root"]},
            {"name": "vlc1", "type": "vdom-link", "vdom": ["root"]},
            {"name": "sdwan-c", "type": "tunnel", "vdom": ["Router"]},
            {"name": "vlc0", "type": "vdom-link", "vdom": ["Router"]},
            {"name": "lan-c", "ip": ["10.3.9.1", "255.255.255.0"], "vdom": ["Router"]},
        ]),
        _row("package", "pkg-c-router", {"name": "pkg-c-router", "scope member": [
            {"name": "fw-c", "vdom": "Router"},
        ]}),
        _row("policy", "pkg-c-router", [
            {"policyid": 400, "name": "allow-inbound", "action": 1, "status": 1,
             "srcintf": ["sdwan-c"], "dstintf": ["lan-c"],
             "srcaddr": ["all"], "dstaddr": ["all"], "service": ["ALL"]},
        ]),

        # Site D — GEROUTETES Underlay (kein Tunnel): der 'Router'-VDOM hält die
        # Default-Route über ein echtes WAN-Interface; 'root' hat L2-Transfer0 mit
        # einer Route zur Quelle (aber dort kommt inter-site Traffic nie an) und
        # default-routet per VDOM-Link zum Router-VDOM.
        _row("device", "fw-d", {"name": "fw-d", "vdom": [{"name": "root"}, {"name": "Router"}]}),
        _row("interface", "fw-d", [
            {"name": "L2-Transfer0", "ip": ["10.4.5.1", "255.255.255.0"], "vdom": ["root"]},
            {"name": "vld1", "type": "vdom-link", "vdom": ["root"]},
            {"name": "wan-d", "ip": ["10.4.0.1", "255.255.255.252"], "vdom": ["Router"]},
            {"name": "vld0", "type": "vdom-link", "vdom": ["Router"]},
            {"name": "lan-d", "ip": ["10.4.9.1", "255.255.255.0"], "vdom": ["Router"]},
        ]),
        _row("route", "fw-d|root", [
            {"dst": ["10.1.0.0", "255.255.0.0"], "device": ["L2-Transfer0"], "gateway": "10.4.5.2"},
            {"dst": ["0.0.0.0", "0.0.0.0"], "device": ["vld1"], "gateway": "0.0.0.0"},
        ]),
        _row("route", "fw-d|Router", [
            {"dst": ["0.0.0.0", "0.0.0.0"], "device": ["wan-d"], "gateway": "10.4.0.2"},
        ]),
        _row("package", "pkg-d-router", {"name": "pkg-d-router", "scope member": [
            {"name": "fw-d", "vdom": "Router"},
        ]}),
        _row("policy", "pkg-d-router", [
            {"policyid": 500, "name": "allow-routed-in", "action": 1, "status": 1,
             "srcintf": ["wan-d"], "dstintf": ["lan-d"],
             "srcaddr": ["all"], "dstaddr": ["all"], "service": ["ALL"]},
        ]),

        # Site E — wie das Feld: dynamisches Routing (BGP), also KEINE statische
        # Default-Route sichtbar. Der Eintritts-VDOM ist über den Namen 'Router'
        # zu erkennen; 'root' hat L2-Transfer0 mit Route zur Quelle (Falle).
        _row("device", "fw-e", {"name": "fw-e", "vdom": [{"name": "root"}, {"name": "Router"}]}),
        _row("interface", "fw-e", [
            {"name": "L2-Transfer0", "ip": ["10.5.5.1", "255.255.255.0"], "vdom": ["root"]},
            {"name": "vle1", "type": "vdom-link", "vdom": ["root"]},
            {"name": "wan-e", "ip": ["10.5.0.1", "255.255.255.252"], "vdom": ["Router"]},
            {"name": "vle0", "type": "vdom-link", "vdom": ["Router"]},
            {"name": "lan-e", "ip": ["10.5.9.1", "255.255.255.0"], "vdom": ["Router"]},
        ]),
        _row("package", "pkg-e-router", {"name": "pkg-e-router", "scope member": [
            {"name": "fw-e", "vdom": "Router"},
        ]}),
        _row("policy", "pkg-e-router", [
            {"policyid": 600, "name": "allow-bgp-site", "action": 1, "status": 1,
             "srcintf": ["wan-e"], "dstintf": ["lan-e"],
             "srcaddr": ["all"], "dstaddr": ["all"], "service": ["ALL"]},
        ]),

        _row("address", "srv-db", {"name": "srv-db",
                                   "subnet": ["10.2.1.30", "255.255.255.255"]}),
        _row("address", "net-site-a", {"name": "net-site-a",
                                       "subnet": ["10.1.0.0", "255.255.240.0"]}),
        _row("service", "HTTPS", {"name": "HTTPS", "protocol": "TCP/UDP/SCTP",
                                  "tcp-portrange": ["443"]}),
        _row("vip", "vip-web", {"name": "vip-web", "extip": "203.0.113.10",
                                "mappedip": ["10.1.2.20"]}),

        _row("route", "fw-a|root", [
            {"dst": ["10.2.0.0", "255.255.240.0"], "device": ["vpn-to-b"], "gateway": "0.0.0.0"},
            {"dst": ["0.0.0.0", "0.0.0.0"], "device": ["wan"], "gateway": "203.0.113.2"},
        ]),
        _row("route", "fw-b|root", [
            {"dst": ["10.1.0.0", "255.255.240.0"], "device": ["vpn-to-a"], "gateway": "0.0.0.0"},
            {"dst": ["0.0.0.0", "0.0.0.0"], "device": ["wan"], "gateway": "198.51.100.2"},
        ]),
    ]


@pytest.fixture
def inventory() -> Inventory:
    return Inventory.build(lab_snapshot_rows(), synced_at="2026-07-10T00:00:00+00:00")


@pytest.fixture
def prefixes(inventory: Inventory):
    return inventory.build_prefix_table()
