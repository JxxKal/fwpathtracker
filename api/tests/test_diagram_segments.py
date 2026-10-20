"""Segmentplan: gewählte VLANs eines Service mit Switches, Hosts, Firewall-Kette und SD-WAN."""
from __future__ import annotations

import xml.etree.ElementTree as ET

import pytest

from diagram import segments, services

FAMILIES = [{"id": "1", "name": "Infrastruktur"}]
SERVICES = [{"id": "11", "name": "Backup", "family_id": "1", "family_name": "",
             "description": "", "status": ""}]
LINKS = [{"service_id": "11", "ci_id": "1", "ci_name": "bk-a"},
         {"service_id": "11", "ci_id": "2", "ci_name": "bk-c"},
         {"service_id": "11", "ci_id": "3", "ci_name": "bk-d"}]
ITOP_HOSTS = [
    {"id": "1", "name": "bk-a", "ip": "10.1.8.10", "kind": "Server", "description": ""},
    {"id": "2", "name": "bk-c", "ip": "10.3.9.10", "kind": "Server", "description": ""},
    {"id": "3", "name": "bk-d", "ip": "10.4.5.10", "kind": "Server", "description": ""},
    {"id": "4", "name": "fremd-d", "ip": "10.4.5.20", "kind": "Server", "description": ""},
]
LLDP = {
    "index": {"sw-d1": {"device_id": 1, "sysName": "sw-d1", "ip": "10.4.5.2", "os": "procurve"},
              "sw-d2": {"device_id": 2, "sysName": "sw-d2", "os": "procurve"},
              "sw-far": {"device_id": 3, "sysName": "sw-far", "os": "procurve"},
              "sw-other": {"device_id": 4, "sysName": "sw-other", "os": "procurve"},
              "fw-d": {"device_id": 9, "sysName": "fw-d", "os": "fortigate"}},
    "links": [
        {"local_device_id": 1, "remote_hostname": "fw-d.corp", "remote_device_id": 9},
        {"local_device_id": 2, "remote_hostname": "sw-d1", "remote_device_id": 1},
        {"local_device_id": 3, "remote_hostname": "sw-d2", "remote_device_id": 2},
        # Über die Firewall hinweg darf die Suche nicht laufen.
        {"local_device_id": 4, "remote_hostname": "fw-d", "remote_device_id": 9},
    ],
    "vlans": [{"device_id": 1, "vlan_vlan": 50}, {"device_id": 2, "vlan_vlan": "50"},
              {"device_id": 4, "vlan_vlan": 60}, {"device_id": 3, "vlan_vlan": 70}],
}


class Arp:
    async def __call__(self, cidr: str) -> list[dict]:
        if cidr == "10.4.5.0/24":
            return [{"ip": "10.4.5.99", "mac": "000c29aabbcc", "last_seen": None, "age_s": 60}]
        return []


def _placed(inventory):
    fams = segments.find_service(FAMILIES, SERVICES, "Backup")
    nets, _ = services.place(inventory, fams, LINKS, ITOP_HOSTS, [])
    return fams, nets


async def _build(inventory, prefixes, selected=None, **kw):
    fams, nets = _placed(inventory)
    args = dict(family=fams[0], nets=nets, selected=selected or [], itop_hosts=ITOP_HOSTS,
                arp=Arp())
    args.update(kw)
    return await segments.build(inventory, prefixes, **args)


def test_find_service_by_id_or_name():
    assert segments.find_service(FAMILIES, SERVICES, "11")[0]["services"][0]["name"] == "Backup"
    assert segments.find_service(FAMILIES, SERVICES, "backup")[0]["name"] == "Infrastruktur"
    with pytest.raises(ValueError):
        segments.find_service(FAMILIES, SERVICES, "Gibtsnicht")


def test_network_choices_list_every_vlan_of_the_service(inventory, prefixes):
    fams, nets = _placed(inventory)
    rows = segments.network_choices(inventory, prefixes, nets, fams[0]["services"][0], [])
    assert {r["fw_id"] for r in rows} == {"fw-a/dmz", "fw-c/Router", "fw-d/root"}
    assert all(r["cis"] == 1 for r in rows)


def test_switches_follow_lldp_from_the_firewall_and_must_carry_the_vlan():
    names = lambda sws: [s["name"] for s in sws]                     # noqa: E731
    fw = {"fw-d"}
    # sw-d1 hängt direkt, sw-d2 dahinter; sw-far führt das VLAN nicht.
    assert names(segments.vlan_switches("fw-d", 50, LLDP, fw)) == ["sw-d1", "sw-d2"]
    assert segments.vlan_switches("fw-d", 50, LLDP, fw)[0]["uplink"] is True
    # sw-other hängt auch an fw-d, aber in einem anderen VLAN.
    assert names(segments.vlan_switches("fw-d", 60, LLDP, fw)) == ["sw-other"]
    # Ungetaggt: nur die direkt angeschlossenen Switches.
    assert names(segments.vlan_switches("fw-d", None, LLDP, fw)) == ["sw-d1", "sw-other"]
    assert segments.vlan_switches("fw-d", 50, None, fw) == []


def test_firewall_found_by_interface_ip_and_switches_by_management_ip():
    lldp = {"index": {"fw": {"device_id": 9, "sysName": "FGT60F-SERIAL", "ip": "10.4.5.1",
                             "os": "fortigate"},
                      "a": {"device_id": 1, "sysName": "sw-a"},
                      "m": {"device_id": 2, "sysName": "sw-mgmt", "ip": "10.4.5.30"},
                      "x": {"device_id": 3, "sysName": "sw-anderer-standort", "ip": "10.9.9.9"}},
            "links": [{"local_device_id": 1, "remote_hostname": "FGT60F-SERIAL",
                       "remote_device_id": 9}],
            "vlans": [{"device_id": d, "vlan_vlan": 50} for d in (1, 2, 3)]}
    import ipaddress
    out = segments.vlan_switches("fw-d", 50, lldp, {"fw-d"}, {"10.4.5.1"},
                                 [ipaddress.IPv4Network("10.4.5.0/24")])
    assert [(s["name"], s["how"]) for s in out] == [("sw-a", "lldp"), ("sw-mgmt", "mgmt")]


async def test_sites_firewalls_and_the_vdom_chain_to_the_wan(inventory, prefixes):
    m = await _build(inventory, prefixes)
    fws = {fw["device"]: fw for s in m["sites"] for fw in s["firewalls"]}
    # fw-d: Router-VDOM am Namen, Segment-VDOM root koppelt per VDOM-Link.
    assert fws["fw-d"]["router"] == "Router" and fws["fw-d"]["vdoms"] == ["root"]
    assert fws["fw-d"]["links"] == {"root": "vld1 ↔ vld0"}
    assert fws["fw-d"]["uplinks"] == {"Router": "Default via wan-d"}
    # fw-c: Netz terminiert direkt im Router-VDOM, raus geht's übers Overlay.
    assert fws["fw-c"]["links"] == {} and fws["fw-c"]["uplinks"] == {"Router": "Overlay sdwan-c"}
    # fw-a: kein Router-Name — der VDOM mit echter Default-Route ist der Router.
    assert fws["fw-a"]["router"] == "root" and fws["fw-a"]["links"] == {"dmz": "vlink1 ↔ vlink0"}
    assert m["stats"]["segments"] == 3 and m["stats"]["firewalls"] == 3


async def test_hosts_are_marked_like_the_overview(inventory, prefixes):
    fams, nets = _placed(inventory)
    nid = next(n for n, v in nets.items() if v["device"] == "fw-d")
    m = await _build(inventory, prefixes, selected=[nid])
    seg = m["sites"][0]["segments"][0]
    by_ip = {h["ip"]: h for h in seg["hosts"]}
    assert by_ip["10.4.5.10"]["in_itop"] and by_ip["10.4.5.99"]["in_itop"] is False
    assert m["stats"]["hosts_not_in_service"] == 1                      # fremd-d
    assert m["stats"]["segments"] == 1


async def test_unknown_selection_is_rejected(inventory, prefixes):
    with pytest.raises(ValueError, match="gehören nicht"):
        await _build(inventory, prefixes, selected=["net:gibt/es/nicht"])


async def test_render_draws_segments_switches_hosts_and_one_cloud(inventory, prefixes):
    m = await _build(inventory, prefixes)
    xml = segments.render(m)
    root = ET.fromstring(xml)
    labels = [o.get("label") or "" for o in root.iter("object")]
    assert sum(1 for c in root.iter("mxCell") if "shape=cloud" in (c.get("style") or "")) == 1
    assert sum(1 for c in root.iter("mxCell")
               if (c.get("style") or "").startswith("rounded=1;arcSize=50")) == 3   # Leisten
    assert not any("sw-d1" in lb for lb in labels)            # Switches: eigene Ansicht
    assert any("bk-d" in lb for lb in labels)
    edges = [c for c in root.iter("mxCell") if c.get("edge") == "1"]
    assert any((c.get("value") or "") == "Default via wan-d" for c in edges)
    assert any("vld1 ↔ vld0" in (c.get("value") or "") for c in edges)
    # Jede Kante zeigt auf existierende Zellen.
    ids = {o.get("id") for o in root.iter("object")} | {c.get("id") for c in root.iter("mxCell")}
    assert all(c.get("source") in ids and c.get("target") in ids for c in edges)


async def test_hiding_foreign_hosts(inventory, prefixes):
    m = await _build(inventory, prefixes)
    xml = segments.render(m, hide_not_in_service=True, hide_not_in_itop=True)
    assert "fremd-d" not in xml and "10.4.5.99" not in xml and "bk-d" in xml
