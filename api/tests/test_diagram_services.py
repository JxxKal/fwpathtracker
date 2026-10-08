"""Service-Ansicht: Servicefamilie → Service → VLAN → Hosts, rot = nicht im iTop."""
from __future__ import annotations

import xml.etree.ElementTree as ET

import pytest

from diagram import services

FAMILIES = [{"id": "1", "name": "Global Tier-0 BU Germany"}, {"id": "2", "name": "PLS"}]
SERVICES = [
    {"id": "10", "name": "Tier-0 Core Infrastructure", "family_id": "1", "family_name": "",
     "description": "", "status": "production"},
    {"id": "11", "name": "Backup", "family_id": "1", "family_name": "", "description": "",
     "status": ""},
    {"id": "20", "name": "iFix", "family_id": "2", "family_name": "", "description": "", "status": ""},
    {"id": "30", "name": "Waise", "family_id": "0", "family_name": "", "description": "", "status": ""},
]
LINKS = [
    {"service_id": "10", "ci_id": "101", "ci_name": "srv-web"},
    {"service_id": "10", "ci_id": "102", "ci_name": "srv-ohne-ip"},
    {"service_id": "10", "ci_id": "103", "ci_name": "srv-fremd"},
    {"service_id": "11", "ci_id": "101", "ci_name": "srv-web"},
    {"service_id": "20", "ci_id": "104", "ci_name": "plc-1"},
]
ITOP_HOSTS = [
    {"id": "101", "name": "srv-web", "ip": "10.1.1.10", "description": "", "kind": "Server"},
    {"id": "103", "name": "srv-fremd", "ip": "192.0.2.5", "description": "", "kind": "Server"},
    {"id": "104", "name": "plc-1", "ip": "10.1.2.10", "description": "", "kind": "Server"},
]


class Arp:
    def __init__(self):
        self.calls: list[str] = []

    async def __call__(self, cidr: str) -> list[dict]:
        self.calls.append(cidr)
        if cidr == "10.1.1.0/24":
            return [{"ip": "10.1.1.77", "mac": "000c29aabbcc", "last_seen": None, "age_s": 60}]
        return []


async def _build(inventory, **kw):
    args = dict(families=FAMILIES, services=SERVICES, links=LINKS, itop_hosts=ITOP_HOSTS,
                itop_subnets=[], arp=Arp())
    args.update(kw)
    return await services.build(inventory, **args)


def _svc(m, name):
    return next(s for f in m["families"] for s in f["services"] if s["name"] == name)


async def test_service_networks_come_from_the_ci_ips(inventory):
    m = await _build(inventory)
    core = _svc(m, "Tier-0 Core Infrastructure")
    net = m["networks"][core["networks"][0]]
    assert net["cidr"] == "10.1.1.0/24" and net["fw_id"] == "fw-a/root"
    assert core["ips"] == ["10.1.1.10"]
    fam = m["families"][0]
    assert fam["name"] == "Global Tier-0 BU Germany" and fam["firewalls"] == ["fw-a/root"]


async def test_hosts_not_in_itop_are_flagged(inventory):
    m = await _build(inventory)
    net = next(n for n in m["networks"].values() if n["cidr"] == "10.1.1.0/24")
    by_ip = {h["ip"]: h for h in net["hosts"]}
    assert by_ip["10.1.1.10"]["in_itop"] is True
    assert by_ip["10.1.1.77"]["in_itop"] is False          # nur aus der ARP-Historie
    assert m["stats"]["hosts_not_in_itop"] >= 1


async def test_cis_without_network_are_listed_not_dropped(inventory):
    m = await _build(inventory)
    core = _svc(m, "Tier-0 Core Infrastructure")
    reasons = {u["name"]: u["reason"] for u in core["unplaced"]}
    assert reasons == {"srv-ohne-ip": "ohne Management-IP",
                       "srv-fremd": "IP in keinem Firewall-Netz"}
    assert m["stats"]["cis_unplaced"] == 2


async def test_a_shared_network_is_collected_once(inventory):
    arp = Arp()
    m = await _build(inventory, arp=arp)
    assert _svc(m, "Backup")["networks"] == _svc(m, "Tier-0 Core Infrastructure")["networks"]
    assert arp.calls.count("10.1.1.0/24") == 1


async def test_services_without_family_get_their_own_group(inventory):
    m = await _build(inventory)
    assert m["families"][-1]["name"] == services.NO_FAMILY
    assert [s["name"] for s in m["families"][-1]["services"]] == ["Waise"]


async def test_family_filter_by_name_or_id(inventory):
    m = await _build(inventory, family="pls")
    assert [f["name"] for f in m["families"]] == ["PLS"]
    m = await _build(inventory, family="1")
    assert [f["name"] for f in m["families"]] == ["Global Tier-0 BU Germany"]
    assert m["stats"]["networks"] == 1
    with pytest.raises(ValueError):
        await _build(inventory, family="gibt es nicht")


async def test_itop_addresses_are_asked_only_for_drawn_networks(inventory):
    asked: list[list[str]] = []

    async def addresses(cidrs):
        asked.append(sorted(cidrs))
        return {"10.1.1.30": {"status": "allocated", "name": "reserviert-30"}}

    m = await _build(inventory, addresses=addresses, family="1")
    assert asked == [["10.1.1.0/24"]]
    net = next(iter(m["networks"].values()))
    assert {h["ip"]: h["in_itop"] for h in net["hosts"]}["10.1.1.30"] is True


def _cells(xml: str):
    root = ET.fromstring(xml.split("\n", 1)[1])
    return root, root.findall(".//diagram")


async def test_render_one_page_per_family_with_red_hosts_and_firewall_edges(inventory):
    m = await _build(inventory)
    xml = services.render(m, title_block=None)
    root, pages = _cells(xml)
    assert [p.get("name") for p in pages] == ["Global Tier-0 BU Germany", "PLS",
                                              services.NO_FAMILY]
    first = pages[0]
    objs = {o.get("label"): o for o in first.iter("object")}
    assert any("Tier-0 Core Infrastructure" == k for k in objs)
    red = [o for o in first.iter("object") if "10.1.1.77" in (o.get("label") or "")]
    assert red and services.RED in red[0].find("mxCell").get("style")
    assert "NICHT IM iTOP" in red[0].get("tooltip")
    ok = next(o for o in first.iter("object") if "srv-web" in (o.get("label") or ""))
    assert services.RED not in ok.find("mxCell").get("style")
    edges = [c for c in first.iter("mxCell") if c.get("edge") == "1"]
    assert len(edges) == 2          # 10.1.1.0/24 in zwei Services → je ein Pfeil zur Firewall
    fw = next(o for o in first.iter("object") if "fw-a" in (o.get("label") or ""))
    assert all(e.get("target") == fw.get("id") for e in edges)


async def test_render_without_any_family_still_is_a_valid_file(inventory):
    m = await services.build(inventory, families=[], services=[], links=[], itop_hosts=[],
                             itop_subnets=[])
    _root, pages = _cells(services.render(m))
    assert len(pages) == 1
