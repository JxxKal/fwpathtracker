"""Netzplan: Modell aus dem Lab-Inventar, Detailstufen, draw.io-Ausgabe."""
from __future__ import annotations

import xml.etree.ElementTree as ET

import pytest

from diagram import drawio, model


async def _arp(cidr: str) -> list[dict]:
    if cidr == "10.1.1.0/24":
        return [{"ip": "10.1.1.77", "mac": "000c29aabbcc", "last_seen": "2026-09-01T10:00:00+00:00",
                 "age_s": 3600}]
    return []


ITOP_HOSTS = [
    {"name": "srv-web", "ip": "10.1.1.10", "description": "Webserver", "kind": "Server"},
    {"name": "sw-core", "ip": "10.1.1.2", "description": "", "kind": "NetworkDevice"},
]
ITOP_SUBNETS = [{"id": "5", "cidr": "10.1.1.0/24", "name": "Server-LAN", "gateway": "10.1.1.1"}]


async def _build(inventory, prefixes, **kw):
    args = dict(scope="vdom", device="fw-a", vdom="root", hosts="auto",
                itop_subnets=ITOP_SUBNETS, itop_hosts=ITOP_HOSTS,
                itop_addresses={"10.1.1.20": {"status": "allocated", "name": "plc-20"},
                                "10.1.1.21": {"status": "released", "name": "alt"}},
                arp=_arp)
    args.update(kw)
    return await model.build(inventory, prefixes, **args)


async def test_vdom_scope_has_networks_neighbors_and_hosts(inventory, prefixes):
    m = await _build(inventory, prefixes)
    assert [v["id"] for v in m["vdoms"]] == ["fw-a/root"]
    nets = {n["cidr"]: n for n in m["vdoms"][0]["networks"]}
    assert {"10.1.1.0/24", "10.1.2.0/24", "203.0.113.0/30", "10.99.0.0/30"} <= set(nets)
    lan1 = nets["10.1.1.0/24"]
    assert lan1["zone"] == "inside-a" and lan1["itop_name"] == "Server-LAN"
    ips = {h["ip"]: h for h in lan1["hosts"]}
    assert set(ips) == {"10.1.1.10", "10.1.1.2", "10.1.1.20", "10.1.1.77"}   # released fehlt, FW-IP fehlt
    assert ips["10.1.1.77"]["sources"] == ["arp"] and ips["10.1.1.77"]["mac"] == "000c29aabbcc"
    assert ips["10.1.1.2"]["kind"] == "NetworkDevice"
    kinds = {e["kind"] for e in m["edges"]}
    assert {"vdom-link", "overlay", "default"} <= kinds
    targets = {e["to"] for e in m["edges"]}
    assert "fw-a/dmz" in targets and "fw-b/root" in targets     # VDOM-Link + Route übers Overlay
    assert any(n["kind"] == "default" for n in m["neighbors"])
    assert m["hosts_mode"] == "all" and m["stats"]["hosts_shown"] == 4


async def test_netdev_mode_keeps_only_network_devices(inventory, prefixes):
    m = await _build(inventory, prefixes, hosts="netdev")
    lan1 = next(n for n in m["vdoms"][0]["networks"] if n["cidr"] == "10.1.1.0/24")
    assert [h["ip"] for h in lan1["hosts"]] == ["10.1.1.2"]


async def test_auto_falls_back_to_netdev_above_the_limit(inventory, prefixes):
    m = await _build(inventory, prefixes, max_hosts=2)
    assert m["hosts_mode"] == "netdev" and m["stats"]["hosts_reduced"]
    assert m["stats"]["hosts_found"] == 4 and m["stats"]["hosts_shown"] == 1


async def test_none_mode_draws_only_networks(inventory, prefixes):
    m = await _build(inventory, prefixes, hosts="none")
    assert all(not n["hosts"] for v in m["vdoms"] for n in v["networks"])
    assert m["stats"]["hosts_found"] == 0


async def test_firewall_scope_covers_all_vdoms(inventory, prefixes):
    m = await _build(inventory, prefixes, scope="firewall", vdom=None)
    assert [v["id"] for v in m["vdoms"]] == ["fw-a/root", "fw-a/dmz"]
    # Der VDOM-Link zwischen root und dmz ist jetzt scope-intern: kein Nachbar dafür.
    assert all(n["id"] != "fw-a/dmz" for n in m["neighbors"])


async def test_unknown_device_or_vdom_is_an_error(inventory, prefixes):
    with pytest.raises(ValueError):
        await _build(inventory, prefixes, device="fw-x")
    with pytest.raises(ValueError):
        await _build(inventory, prefixes, vdom="nope")


async def test_drawio_xml_is_well_formed_and_complete(inventory, prefixes):
    m = await _build(inventory, prefixes)
    xml = drawio.render(m)
    root = ET.fromstring(xml)
    assert root.tag == "mxfile"
    cells = root.findall(".//mxCell")
    objects = root.findall(".//object")
    labels = " ".join(o.get("label", "") for o in objects)
    assert "fw-a" in labels and "10.1.1.0/24" in labels and "srv-web" in labels
    tips = " ".join(o.get("tooltip", "") for o in objects)
    assert "000c29aabbcc" in tips and "Server-LAN" in tips
    edges = [c for c in cells if c.get("edge") == "1"]
    assert len(edges) >= 3
    # Symbole aus der draw.io-Network-Bibliothek: Server, Switch, Firewall, Wolke.
    styles = " ".join(c.get("style", "") for c in cells)
    for shape in ("mxgraph.networks.server", "mxgraph.cisco.switches.workgroup_switch",
                  "mxgraph.networks.firewall", "mxgraph.networks.cloud"):
        assert shape in styles, shape
    # Jede Kante zeigt auf existierende Zellen.
    ids = {o.get("id") for o in objects} | {c.get("id") for c in cells}
    assert all(e.get("source") in ids and e.get("target") in ids for e in edges)


async def test_many_hosts_collapse_the_network_box(inventory, prefixes):
    hosts = [{"name": f"h{i}", "ip": f"10.1.1.{i}", "description": "", "kind": "Server"}
             for i in range(10, 90)]
    m = await _build(inventory, prefixes, itop_hosts=hosts, itop_addresses={}, arp=_arp)
    xml = drawio.render(m)
    root = ET.fromstring(xml)
    collapsed = [c for c in root.findall(".//mxCell") if c.get("collapsed") == "1"]
    assert len(collapsed) == 1
    assert "+20 weitere" in " ".join(o.get("label", "") for o in root.findall(".//object"))
