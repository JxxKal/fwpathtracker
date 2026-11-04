"""iTop↔DNS-Abgleich: Einordnung, Domain-Zuordnung, Schreibschutz, Freigabe."""
from __future__ import annotations

import pytest

from dnssync import build, itop, service

DOMAINS = [{"_key": "3", "name": "corp.com"}, {"_key": "7", "name": "ot.corp.com"}]


def addr(key, ip, short="", dom="", status="allocated"):
    return {"_key": key, "ip": ip, "status": status, "short_name": short,
            "domain_id": "7" if dom == "ot.corp.com" else ("3" if dom else "0"),
            "domain_name": dom, "fqdn": f"{short}.{dom}" if short and dom else ""}


def dns_ok(ip, name):
    return {"ptr": [name], "forward": {name: [ip]}}


def test_split_fqdn_takes_longest_domain_and_rejects_dotted_short_names():
    d = {"corp.com": "3", "ot.corp.com": "7"}
    assert build.split_fqdn("SRV1.ot.corp.com.", d) == ("srv1", "ot.corp.com", "7")
    assert build.split_fqdn("srv2.corp.com", d) == ("srv2", "corp.com", "3")
    assert build.split_fqdn("a.b.corp.com", d) is None          # Kurzname mit Punkt
    assert build.split_fqdn("srv.other.org", d) is None


def test_items_sections_status_and_preselection():
    addresses = [addr("1", "10.0.0.1"), addr("2", "10.0.0.2"), addr("3", "10.0.0.3"),
                 addr("4", "10.0.0.4", "alt", "corp.com"), addr("5", "10.0.0.5"),
                 addr("6", "10.0.0.6", status="released"), addr("8", "10.0.0.8", "srv8", "corp.com"),
                 addr("9", "10.0.0.9")]
    cis = [{"class": "Server", "id": "11", "name": "srv1", "ip_id": "1"},
           {"class": "VirtualMachine", "id": "12", "name": "vm2", "ip_id": "2"},
           {"class": "Server", "id": "14", "name": "neu", "ip_id": "4"},
           {"class": "Server", "id": "15", "name": "x", "ip_id": "5"},
           {"class": "Server", "id": "18", "name": "srv8", "ip_id": "8"}]
    dns = {"10.0.0.1": dns_ok("10.0.0.1", "srv1.ot.corp.com"),
           "10.0.0.2": {"ptr": ["vm2.corp.com"], "forward": {"vm2.corp.com": ["10.9.9.9"]}},
           "10.0.0.3": dns_ok("10.0.0.3", "drucker3.corp.com"),
           "10.0.0.4": dns_ok("10.0.0.4", "neu.corp.com"),
           "10.0.0.5": dns_ok("10.0.0.5", "x.example.org"),
           "10.0.0.8": dns_ok("10.0.0.8", "srv8.corp.com"),
           "10.0.0.9": {"ptr": [], "forward": {}}}
    items, stats = build.items(addresses, cis, DOMAINS, dns, ignored=set())
    by = {i["ip"]: i for i in items}
    assert set(by) == {"10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4", "10.0.0.5"}
    one = by["10.0.0.1"]
    assert (one["section"], one["status"], one["selected"]) == ("missing", "confirmed", True)
    assert (one["short_name"], one["domain_id"], one["cis"][0]["name"]) == ("srv1", "7", "srv1")
    assert (by["10.0.0.2"]["status"], by["10.0.0.2"]["selected"]) == ("unconfirmed", False)
    assert by["10.0.0.2"]["selectable"] and "10.9.9.9" in by["10.0.0.2"]["reason"]
    assert by["10.0.0.3"]["section"] == "orphan" and by["10.0.0.3"]["selected"]
    # Abweichender Name: nie vorausgewählt.
    four = by["10.0.0.4"]
    assert (four["section"], four["itop_name"], four["selected"]) == ("mismatch", "alt.corp.com", False)
    assert by["10.0.0.5"]["status"] == "no_domain" and not by["10.0.0.5"]["selectable"]
    assert stats["ok"] == 1 and stats["no_ptr"] == 1 and stats["missing"] == 3
    # Dauerhaft ausgenommen → taucht nicht mehr auf.
    items2, stats2 = build.items(addresses, cis, DOMAINS, dns, ignored={"1"})
    assert "10.0.0.1" not in {i["ip"] for i in items2} and stats2["ignored"] == 1


def test_write_guard_allows_only_short_name_and_domain_on_ipv4address():
    itop.guard_write("IPv4Address", {"short_name": "a", "domain_id": 3})
    for cls, fields in [("Server", {"short_name": "a"}), ("IPv4Address", {"status": "x"}),
                        ("IPv4Address", {"short_name": "a", "ip": "1.2.3.4"}),
                        ("IPv4Address", {})]:
        with pytest.raises(itop.ItopWriteBlocked):
            itop.guard_write(cls, fields)


def test_toggle_respects_selectable():
    items = [{"id": "1", "selectable": True, "selected": False},
             {"id": "2", "selectable": False, "selected": False}]
    service.toggle(items, {"1", "2"}, True)
    assert [i["selected"] for i in items] == [True, False]


class FakeStore:
    def __init__(self):
        self.decided = None

    async def decide(self, rid, status, user, items, result):
        self.decided = (status, user, result)


async def test_apply_rechecks_itop_and_dns_before_writing(monkeypatch):
    cfgs = {"dnssync": {"write_enabled": True}, "itop": {"base_url": "https://itop", "user": "u",
                                                        "password": "p"}, "dns": {}}

    async def read_config(key):
        return cfgs[key]

    current = {"1": {"short_name": "", "domain_id": "0"},
               "2": {"short_name": "jemand", "domain_id": "3"},     # inzwischen gepflegt
               "3": {"short_name": "", "domain_id": "0"},
               "4": {"short_name": "", "domain_id": "0"}}
    written = []

    async def get_address(cfg, ip_id):
        return current.get(ip_id)

    async def update_address(cfg, ip_id, fields, comment):
        itop.guard_write("IPv4Address", fields)
        if ip_id == "4":
            raise RuntimeError("keine Rechte")
        written.append((ip_id, fields, comment))
        return {"fqdn": f"{fields['short_name']}.corp.com"}

    async def check(dns_cfg, ips):
        return {"10.0.0.1": {"ptr": ["a.corp.com"]}, "10.0.0.2": {"ptr": ["b.corp.com"]},
                "10.0.0.3": {"ptr": ["anders.corp.com"]}, "10.0.0.4": {"ptr": ["d.corp.com"]}}

    monkeypatch.setattr(itop, "get_address", get_address)
    monkeypatch.setattr(itop, "update_address", update_address)
    monkeypatch.setattr(service.lookup, "check", check)

    def it(i, name, selected=True):
        return {"id": i, "ip": f"10.0.0.{i}", "dns_name": name, "short_name": name.split(".")[0],
                "domain_id": "3", "itop_short": None, "itop_domain_id": "0",
                "selected": selected, "selectable": True}

    run = {"id": 9, "status": "open",
           "items": [it("1", "a.corp.com"), it("2", "b.corp.com"), it("3", "c.corp.com"),
                     it("4", "d.corp.com"), it("5", "e.corp.com", selected=False)]}
    store = FakeStore()
    res = await service.apply(store, read_config, run, "admin")
    assert written == [("1", {"short_name": "a", "domain_id": 3},
                        "A38 iTop-DNS-Abgleich #9, freigegeben von admin")]
    states = {i["id"]: (i.get("result") or {}).get("state") for i in run["items"]}
    assert states == {"1": "ok", "2": "skipped", "3": "skipped", "4": "error", "5": None}
    assert res["status"] == "partial" and store.decided[0] == "partial"

    cfgs["dnssync"]["write_enabled"] = False
    with pytest.raises(service.DnsSyncError):
        await service.apply(store, read_config, dict(run, status="open"), "admin")
