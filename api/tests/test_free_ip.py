"""Free-IP-Finder: Bestand scheidet aus, der Rest wird geprüft, Urteil je Quelle.

Nachgebautes Feldszenario in 10.180.5.0/29 (Hosts .1–.6):
  .1  Gateway (iTop gatewayip)             → gar nicht angefasst
  .2  iTop allocated                        → belegt
  .3  Management-IP eines Servers OHNE Adressobjekt → belegt (der Klassiker)
  .4  iTop released, antwortet aber auf Ping → in_use
  .5  still, aber PTR vorhanden             → suspect
  .6  still, nichts bekannt                 → free
"""
from __future__ import annotations

import ipaddress
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from ipam import free_ip  # noqa: E402
from ipam.tree import build_tree  # noqa: E402

NET = ipaddress.IPv4Network("10.180.5.0/29")


async def _ping(ip: str) -> bool | None:
    return ip == "10.180.5.4"


async def _dns(ip: str) -> str | None:
    return "ofen3.op-tech.com" if ip == "10.180.5.5" else None


async def _arp(ip: str) -> dict | None:
    return None


def _run(**kw):
    import asyncio
    args = dict(
        itop_addresses={"10.180.5.2": {"status": "allocated", "name": "srv-a"},
                        "10.180.5.4": {"status": "released", "name": ""}},
        ci_hosts={"10.180.5.3": "plc-3"}, fw_ips={}, dhcp_ranges=[],
        gateway="10.180.5.1", ping=_ping, dns=_dns, arp=_arp, want=10,
    )
    args.update(kw)
    return asyncio.run(free_ip.find_free(NET, **args))


def test_inventory_is_skipped_and_rest_is_judged():
    res = _run()
    by_ip = {r["ip"]: r for r in res["results"]}
    assert set(by_ip) == {"10.180.5.4", "10.180.5.5", "10.180.5.6"}
    assert by_ip["10.180.5.4"]["verdict"] == "in_use"
    assert by_ip["10.180.5.4"]["itop"] == {"status": "released", "name": ""}
    assert by_ip["10.180.5.5"]["verdict"] == "suspect"
    assert by_ip["10.180.5.5"]["dns"] == "ofen3.op-tech.com"
    assert by_ip["10.180.5.6"]["verdict"] == "free"
    s = res["stats"]
    assert (s["hosts"], s["gateway_skipped"], s["itop_used"], s["ci_used"]) == (6, 1, 1, 1)
    assert s["free"] == 1 and res["exhausted"] and res["ping_available"]


def test_arp_history_makes_a_silent_address_suspect():
    async def arp(ip):
        return {"mac": "000c29aabbcc", "age_s": 3600} if ip == "10.180.5.6" else None
    res = _run(arp=arp)
    v = {r["ip"]: r["verdict"] for r in res["results"]}
    assert v["10.180.5.6"] == "suspect"


def test_dhcp_range_and_firewall_ips_are_not_candidates():
    res = _run(dhcp_ranges=[(ipaddress.IPv4Address("10.180.5.5"),
                             ipaddress.IPv4Address("10.180.5.6"), "pool")],
               fw_ips={"10.180.5.4": "fw-a/root/lan1"})
    assert res["results"] == []
    assert res["stats"]["dhcp_skipped"] == 2 and res["stats"]["fw_used"] == 1


def test_without_ping_the_verdict_is_unknown_not_free():
    async def no_ping(ip):
        return None
    res = _run(ping=no_ping)
    v = {r["ip"]: r["verdict"] for r in res["results"]}
    assert v["10.180.5.6"] == "unknown" and v["10.180.5.5"] == "suspect"
    assert res["ping_available"] is False


def test_waves_stop_once_enough_free_are_found():
    net = ipaddress.IPv4Network("10.180.6.0/24")
    pinged: list[str] = []

    async def ping(ip):
        pinged.append(ip)
        return False
    import asyncio
    res = asyncio.run(free_ip.find_free(
        net, itop_addresses={}, ci_hosts={}, fw_ips={}, dhcp_ranges=[], gateway=None,
        ping=ping, dns=_arp, arp=_arp, want=3, concurrency=4))
    assert res["stats"]["free"] >= 3 and len(pinged) == 4   # eine Welle reicht
    assert not res["exhausted"]


def test_start_end_restricts_the_scan():
    net = ipaddress.IPv4Network("10.180.6.0/24")
    import asyncio
    res = asyncio.run(free_ip.find_free(
        net, itop_addresses={}, ci_hosts={}, fw_ips={}, dhcp_ranges=[], gateway=None,
        ping=_arp, dns=_arp, arp=_arp, want=50, start="10.180.6.100", end="10.180.6.102"))
    assert [r["ip"] for r in res["results"]] == ["10.180.6.100", "10.180.6.101", "10.180.6.102"]
    assert all(r["verdict"] == "unknown" for r in res["results"])


def test_slash31_has_no_network_or_broadcast():
    assert [str(a) for a in free_ip.host_addresses(ipaddress.IPv4Network("10.0.0.0/31"))] \
        == ["10.0.0.0", "10.0.0.1"]
    assert [str(a) for a in free_ip.host_addresses(ipaddress.IPv4Network("10.0.0.0/30"))] \
        == ["10.0.0.1", "10.0.0.2"]


def test_tree_nests_by_containment_and_hangs_ranges_under_subnets():
    sites = [{"name": "Holstein", "cidr": "10.180.0.0/20"}]
    subnets = [
        {"id": "7", "cidr": "10.180.5.0/24", "name": "Ofen", "gateway": "10.180.5.1"},
        {"id": "8", "cidr": "10.180.4.0/23", "name": "Werk", "gateway": None},
        {"id": "9", "cidr": "192.168.1.0/24", "name": "Fremd", "gateway": None},
    ]
    ranges = [{"subnet_id": "7", "first": "10.180.5.100", "last": "10.180.5.199",
               "name": "DHCP", "dhcp": True},
              {"subnet_id": "404", "first": "1.1.1.1", "last": "1.1.1.2", "name": "x", "dhcp": False}]
    roots = build_tree(sites, subnets, ranges)
    assert [r["name"] for r in roots] == ["Holstein", "Weitere Netze"]
    werk = roots[0]["children"][0]
    assert werk["cidr"] == "10.180.4.0/23"
    ofen = werk["children"][0]
    assert ofen["id"] == "7" and ofen["gateway"] == "10.180.5.1"
    assert ofen["children"][0]["kind"] == "range" and ofen["children"][0]["dhcp"]
    assert roots[1]["children"][0]["cidr"] == "192.168.1.0/24"
