"""Switch-Physik eines VLANs: FDB-Ports, LLDP-Baum zur Firewall, Transit-Switches."""
from __future__ import annotations

import xml.etree.ElementTree as ET

from diagram import segments, services, vlanphys
from test_diagram_segments import FAMILIES, ITOP_HOSTS, LINKS, SERVICES

MAC = {"10.4.5.10": "00:00:00:00:00:10", "10.4.5.20": "00:00:00:00:00:20",
       "10.4.5.99": "00:00:00:00:00:99"}


class Arp:
    async def __call__(self, cidr: str) -> list[dict]:
        if cidr != "10.4.5.0/24":
            return []
        return [{"ip": ip, "mac": m, "last_seen": None, "age_s": 60} for ip, m in MAC.items()]


LLDP = {
    "index": {"core": {"device_id": 1, "sysName": "sw-core", "ip": "10.4.5.2"},
              "acc": {"device_id": 2, "sysName": "sw-acc"},
              "far": {"device_id": 3, "sysName": "sw-far"},
              "fw": {"device_id": 9, "sysName": "fw-d-1", "os": "fortigate"}},
    "links": [
        {"local_device_id": 1, "local_port_id": 101, "remote_hostname": "fw-d-1",
         "remote_port": "port5", "remote_device_id": 9},
        {"local_device_id": 1, "local_port_id": 102, "remote_hostname": "sw-acc",
         "remote_port": "Gi1/0/49", "remote_device_id": 2},
        {"local_device_id": 2, "local_port_id": 249, "remote_hostname": "sw-core",
         "remote_port": "Te1/1/2", "remote_device_id": 1},
        {"local_device_id": 3, "local_port_id": 301, "remote_hostname": "sw-acc",
         "remote_port": "Gi1/0/50", "remote_device_id": 2},
    ],
    "vlans": [{"vlan_id": 5001, "device_id": 1, "vlan_vlan": 50},
              {"vlan_id": 5002, "device_id": 2, "vlan_vlan": 50},
              {"vlan_id": 5003, "device_id": 3, "vlan_vlan": 50},
              {"vlan_id": 6002, "device_id": 2, "vlan_vlan": 60}],
}
FDB = {
    "1": [{"port_id": 102, "vlan_id": 5001, "mac_address": "000000000010"}],   # Uplink: zählt nicht
    "2": [{"port_id": 205, "vlan_id": 5002, "mac_address": "000000000010"},
          {"port_id": 206, "vlan_id": 5002, "mac_address": "000000000099"},
          {"port_id": 207, "vlan_id": 5002, "mac_address": "0000000000aa"},   # unbekannt
          {"port_id": 208, "vlan_id": 5002, "mac_address": "000000000020"},
          # dieselbe MAC an einem Port mit drei MACs — verliert gegen 208
          {"port_id": 209, "vlan_id": 5002, "mac_address": "000000000020"},
          {"port_id": 209, "vlan_id": 5002, "mac_address": "0000000000bb"},
          {"port_id": 209, "vlan_id": 5002, "mac_address": "0000000000cc"},
          # anderes VLAN
          {"port_id": 210, "vlan_id": 6002, "mac_address": "000000000099"}],
    "3": [],
}
PORTS = {"1": [{"port_id": 101, "ifName": "Te1/1/1"}, {"port_id": 102, "ifName": "Te1/1/2"}],
         "2": [{"port_id": p, "ifName": f"Gi1/0/{p - 200}"} for p in range(201, 251)],
         "3": [{"port_id": 301, "ifName": "Gi1/0/1"}]}


async def fdb(did):
    return FDB[did]


async def ports(did):
    return PORTS[did]


async def _model(inventory, prefixes, **kw):
    fams = segments.find_service(FAMILIES, SERVICES, "Backup")
    nets, _ = services.place(inventory, fams, LINKS, ITOP_HOSTS, [])
    nid = next(n for n, v in nets.items() if v["device"] == "fw-d")
    nets[nid]["vlan"] = 50
    seg = await segments.build(inventory, prefixes, family=fams[0], nets=nets, selected=[nid],
                               itop_hosts=ITOP_HOSTS, arp=Arp())
    return await vlanphys.build(seg, inventory, lldp=kw.pop("lldp", LLDP), fdb=fdb, ports=ports,
                                **kw)


async def test_switches_with_hosts_and_the_transit_path_to_the_firewall(inventory, prefixes):
    m = await _model(inventory, prefixes)
    sws = {s["name"]: s for s in m["switches"]}
    assert set(sws) == {"sw-acc", "sw-core"}                 # sw-far ohne Hosts fehlt
    assert sws["sw-core"]["role"] == "transit" and sws["sw-core"]["level"] == 1
    assert sws["sw-acc"]["role"] == "hosts" and sws["sw-acc"]["level"] == 2
    rows = {r["host"]["ip"]: r["port"] for r in sws["sw-acc"]["hosts"]}
    assert rows == {"10.4.5.10": "Gi1/0/5", "10.4.5.99": "Gi1/0/6", "10.4.5.20": "Gi1/0/8"}
    assert sws["sw-acc"]["unknown"] == 1                     # 0000000000aa allein am Port
    assert m["links"] == [{"a": "1", "b": "2", "a_port": "Te1/1/2", "b_port": "Gi1/0/49"}]
    assert m["fw_links"] == [{"sw": "1", "sw_port": "Te1/1/1", "fw_port": "port5", "lldp": True}]
    assert m["unplaced"] == []


async def test_filters_apply_before_switches_are_chosen(inventory, prefixes):
    m = await _model(inventory, prefixes, hide_not_in_service=True, hide_not_in_itop=True)
    rows = [r["host"]["ip"] for s in m["switches"] for r in s["hosts"]]
    assert rows == ["10.4.5.10"]


async def test_without_librenms_every_host_is_unplaced(inventory, prefixes):
    m = await _model(inventory, prefixes, lldp=None)
    assert m["switches"] == [] and len(m["unplaced"]) == 3
    assert "LibreNMS" in m["warnings"][0]


async def test_render_has_firewall_switches_and_labelled_links(inventory, prefixes):
    m = await _model(inventory, prefixes)
    root = ET.fromstring(vlanphys.render(m))
    edges = [c for c in root.iter("mxCell") if c.get("edge") == "1"]
    values = [c.get("value") or "" for c in edges]
    assert "Te1/1/2 ↔ Gi1/0/49" in values and "port5 ↔ Te1/1/1" in values
    labels = " ".join(o.get("label") or "" for o in root.iter("object"))
    assert "sw-acc" in labels and "Gi1/0/5" in labels and "<i>Transit</i>" in labels
    ids = {o.get("id") for o in root.iter("object")} | {c.get("id") for c in root.iter("mxCell")}
    assert all(c.get("source") in ids and c.get("target") in ids for c in edges)
