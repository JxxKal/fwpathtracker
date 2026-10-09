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


async def _with_foreign_host(inventory, **kw):
    """10.1.1.30 steht im iTop (Adressobjekt), ist aber kein CI eines Service."""
    async def addresses(cidrs):
        return {"10.1.1.30": {"status": "allocated", "name": "fremd-30"}}
    return await _build(inventory, addresses=addresses, **kw)


def _row(page, ip):
    """(Host-Objekt, Rahmen-Zelle oder None) der Zeile mit dieser IP."""
    host = next(o for o in page.iter("object") if ip in (o.get("label") or ""))
    parent = host.find("mxCell").get("parent")
    tip = host.get("tooltip")
    frame = next((o for o in page.iter("object")
                  if o.get("label") == "" and o.get("tooltip") == tip
                  and o.find("mxCell").get("parent") == parent), None)
    return host, frame


async def test_red_means_in_itop_but_not_assigned_to_the_service(inventory):
    m = await _with_foreign_host(inventory, family="1")
    _root, pages = _cells(services.render(m))
    host, frame = _row(pages[0], "fremd-30")
    assert services.RED in host.find("mxCell").get("style") and frame is None
    assert "NICHT diesem Service" in host.get("tooltip")
    assert m["stats"]["hosts_not_in_service"] == 2       # dasselbe VLAN in zwei Services


async def test_hosts_outside_itop_are_framed_with_red_text(inventory):
    m = await _with_foreign_host(inventory, family="1")
    _root, pages = _cells(services.render(m))
    host, frame = _row(pages[0], "10.1.1.77")
    style = host.find("mxCell").get("style")
    assert f"fontColor={services.RED}" in style and f"fillColor={services.RED}" not in style
    assert frame is not None and f"strokeColor={services.RED}" in frame.find("mxCell").get("style")
    assert "NICHT IM iTOP" in host.get("tooltip")


async def test_service_cis_stay_unmarked(inventory):
    m = await _with_foreign_host(inventory, family="1")
    _root, pages = _cells(services.render(m))
    host, frame = _row(pages[0], "srv-web")
    assert services.RED not in host.find("mxCell").get("style") and frame is None
    assert host.get("tooltip").startswith("CI dieses Service")


def _fill(cell) -> str:
    return next(p for p in cell.get("style").split(";") if p.startswith("fillColor="))


async def test_render_one_page_per_family_without_lines(inventory):
    m = await _build(inventory)
    root, pages = _cells(services.render(m, title_block=None))
    assert [p.get("name") for p in pages] == ["Global Tier-0 BU Germany", "PLS",
                                              services.NO_FAMILY]
    first = pages[0]
    assert any(o.get("label") == "Tier-0 Core Infrastructure" for o in first.iter("object"))
    assert not [c for c in first.iter("mxCell") if c.get("edge") == "1"]


async def test_vlan_boxes_take_the_colour_of_their_firewall(inventory):
    m = await _build(inventory, family="1")
    _root, pages = _cells(services.render(m))
    objs = list(pages[0].iter("object"))
    fw = next(o for o in objs if "fw-a" in (o.get("label") or ""))
    nets = [o for o in objs if "10.1.1.0/24" in (o.get("label") or "")]
    assert len(nets) == 2                     # dasselbe VLAN in zwei Services
    fw_fill = _fill(fw.find("mxCell"))
    assert fw_fill == f"fillColor={services.PALETTE[0][0]}"
    assert all(_fill(n.find("mxCell")) == fw_fill for n in nets)
    # Das Firewall-Symbol sitzt im Kasten.
    assert any(o.find("mxCell").get("parent") == fw.get("id")
               and "mxgraph.networks.firewall" in o.find("mxCell").get("style") for o in objs)


async def test_vlans_stand_in_the_column_of_their_firewall(inventory):
    """fw-b ist die zweite Spalte: ihr VLAN steht unter ihr, auch im Service,
    der an fw-a nichts hat."""
    hosts = ITOP_HOSTS + [{"id": "105", "name": "srv-b", "ip": "10.2.1.10", "description": "",
                           "kind": "Server"}]
    links = LINKS + [{"service_id": "11", "ci_id": "105", "ci_name": "srv-b"}]
    m = await _build(inventory, itop_hosts=hosts, links=links, family="1")
    _root, pages = _cells(services.render(m))
    objs = {o.get("id"): o for o in pages[0].iter("object")}

    def x_in_family(o):
        cell = o.find("mxCell")
        x = float(cell.find("mxGeometry").get("x"))
        parent = objs.get(cell.get("parent"))
        if parent is not None and "startSize=32" in parent.find("mxCell").get("style"):
            x += float(parent.find("mxCell/mxGeometry").get("x"))
        return x

    fw_x = {fw: x_in_family(next(o for o in objs.values()
                                  if f"<b>{fw}</b>" in (o.get("label") or "")))
            for fw in ("fw-a", "fw-b")}
    assert fw_x["fw-a"] < fw_x["fw-b"]
    for cidr, fw in (("10.1.1.0/24", "fw-a"), ("10.2.1.0/24", "fw-b")):
        boxes = [o for o in objs.values() if cidr in (o.get("label") or "")]
        assert boxes and all(x_in_family(b) == fw_x[fw] for b in boxes)


def test_firewalls_of_a_family_get_distinct_colours():
    fws = {f"fw-{i}/root": {"id": f"fw-{i}/root", "device": f"fw-{i}", "vdom": "root",
                            "vdoms": 1, "ha": None} for i in range(3)}
    fam = {"id": "1", "name": "F", "services": [], "firewalls": sorted(fws)}
    xml = services.render({"families": [fam], "networks": {}, "firewalls": fws})
    _root, pages = _cells(xml)
    boxes = [o for o in pages[0].iter("object") if "fw-" in (o.get("label") or "")]
    assert len(boxes) == 3 and len({_fill(b.find("mxCell")) for b in boxes}) == 3


async def test_render_without_any_family_still_is_a_valid_file(inventory):
    m = await services.build(inventory, families=[], services=[], links=[], itop_hosts=[],
                             itop_subnets=[])
    _root, pages = _cells(services.render(m))
    assert len(pages) == 1


async def test_firewalls_can_be_left_out(inventory):
    m = await _build(inventory, family="1")
    xml = services.render(m, show_firewalls=False)
    _root, pages = _cells(xml)
    assert "mxgraph.networks.firewall" not in xml
    net = next(o for o in pages[0].iter("object") if "10.1.1.0/24" in (o.get("label") or ""))
    assert "an fw-a/root" in net.get("label")
    assert _fill(net.find("mxCell")) == "fillColor=#d5e8d4"     # ohne Firewalls: neutral


async def test_network_and_broadcast_address_are_not_hosts(inventory):
    async def addresses(cidrs):
        return {"10.1.1.0": {"status": "allocated", "name": "netz"},
                "10.1.1.255": {"status": "reserved", "name": "broadcast"},
                "10.1.1.30": {"status": "allocated", "name": "fremd-30"}}
    m = await _build(inventory, addresses=addresses, family="1")
    ips = {h["ip"] for n in m["networks"].values() for h in n["hosts"]}
    assert "10.1.1.0" not in ips and "10.1.1.255" not in ips and "10.1.1.30" in ips


async def test_hosts_outside_itop_can_be_hidden(inventory):
    m = await _with_foreign_host(inventory, family="1")
    xml = services.render(m, hide_not_in_itop=True)
    assert "10.1.1.77" not in xml and "fremd-30" in xml and "srv-web" in xml
    assert "2 Hosts" in xml                     # Kopf zählt nur die gezeigten


async def test_hosts_not_at_the_service_can_be_hidden(inventory):
    m = await _with_foreign_host(inventory, family="1")
    xml = services.render(m, hide_not_in_service=True)
    assert "fremd-30" not in xml and "10.1.1.77" in xml and "srv-web" in xml
    both = services.render(m, hide_not_in_itop=True, hide_not_in_service=True)
    assert "fremd-30" not in both and "10.1.1.77" not in both and "srv-web" in both
    assert m["networks"][next(iter(m["networks"]))]["host_count"] == 3   # Modell bleibt unberührt


async def test_hypervisors_are_left_out(inventory):
    """Ein Hypervisor hat keine eigene IP; über den Namen fiele er sonst auf den
    gleichnamigen Server oder landete als „CI ohne Netz" in der Liste."""
    links = LINKS + [
        {"service_id": "20", "ci_id": "201", "ci_name": "srv-web", "ci_class": "Hypervisor"},
        {"service_id": "20", "ci_id": "202", "ci_name": "esx-leer", "ci_class": "Hypervisor"}]
    m = await _build(inventory, links=links)
    ifix = _svc(m, "iFix")
    assert ifix["ci_count"] == 1 and ifix["ips"] == ["10.1.2.10"] and not ifix["unplaced"]


async def test_warning_names_every_firewall_that_holds_the_network(inventory):
    hosts = ITOP_HOSTS + [{"id": "106", "name": "xlink-ci", "ip": "10.99.0.2",
                           "description": "", "kind": "Server"}]
    links = LINKS + [{"service_id": "20", "ci_id": "106", "ci_name": "xlink-ci"}]
    m = await _build(inventory, itop_hosts=hosts, links=links)
    w = next(x for x in m["warnings"] if "xlink-ci" in x)
    assert "10.99.0.0/30" in w and "fw-a/root xlink1" in w and "fw-b/root xlink1" in w


async def test_the_firewall_holding_the_itop_gateway_owns_the_network(inventory):
    """Hängt die zweite Firewall nur als Teilnehmer im Netz (Management-Port),
    entscheidet das iTop-Gateway — ohne Warnung."""
    hosts = ITOP_HOSTS + [{"id": "106", "name": "xlink-ci", "ip": "10.99.0.2",
                           "description": "", "kind": "Server"}]
    links = LINKS + [{"service_id": "20", "ci_id": "106", "ci_name": "xlink-ci"}]
    gw_b = next(n["fw_ip"] for _c, n in services._network_index(inventory, [])
                if n["fw_id"] == "fw-b/root" and n["cidr"] == "10.99.0.0/30")
    subnets = [{"id": "1", "cidr": "10.99.0.0/30", "name": "xlink", "gateway": gw_b}]
    m = await _build(inventory, itop_hosts=hosts, links=links, itop_subnets=subnets)
    net = m["networks"][_svc(m, "iFix")["networks"][-1]]
    assert net["fw_id"] == "fw-b/root"
    assert not [w for w in m["warnings"] if "xlink-ci" in w]
