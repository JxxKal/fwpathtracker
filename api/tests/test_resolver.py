"""Resolver-Kette: FMG-Quelle, Fallback-Reihenfolge, Provenance, IPv6-Gate."""
from __future__ import annotations

import pytest

from resolver import dns_source, fmg_source
from resolver.chain import ResolverChain, is_ip, is_ipv6


def test_is_ip():
    assert is_ip("10.1.1.10")
    assert not is_ip("srv-db")
    assert is_ipv6("2001:db8::1")
    assert not is_ipv6("10.1.1.10")


def test_fmg_resolve_name(inventory):
    hit = fmg_source.resolve_name(inventory, "srv-db")
    assert hit == {"ip": "10.2.1.30", "name": "srv-db", "provenance": "fmg", "adom": "corp"}
    # /20-Objekte sind keine Host-Objekte → nicht auflösbar
    assert fmg_source.resolve_name(inventory, "net-site-a") is None


def test_fmg_resolve_ip(inventory):
    hit = fmg_source.resolve_ip(inventory, "10.2.1.30")
    assert hit["name"] == "srv-db" and hit["provenance"] == "fmg"
    assert fmg_source.resolve_ip(inventory, "10.9.9.9") is None


def test_fmg_search(inventory):
    hits = fmg_source.search(inventory, "srv")
    assert hits and hits[0]["name"] == "srv-db" and hits[0]["provenance"] == "fmg"


def _ot_inventory():
    from inventory.store import Inventory
    rows = [
        {"adom": "corp", "kind": "address", "key": n,
         "data": {"name": n, "type": "ipmask", "subnet": [ip, "255.255.255.255"]}}
        for n, ip in [
            ("SVO3101", "10.2.1.10"),           # exakter Treffer für "svo3101"
            ("SVO3101-MGMT", "10.2.1.11"),      # Präfix-Treffer
            ("WD-OT-L3-SVO3101", "10.2.1.31"),  # Teilstring-Treffer
            ("net-x", "10.9.0.0"),              # kein /32 → nicht durchsuchbar
        ]
    ]
    rows[-1]["data"]["subnet"] = ["10.9.0.0", "255.255.0.0"]
    return Inventory.build(rows)


def test_fmg_search_substring_and_ranking():
    inv = _ot_inventory()
    # Teilstring: 'svo3101' findet das lange OT-Objekt (Anforderung)
    names = [h["name"] for h in fmg_source.search(inv, "svo3101")]
    assert "WD-OT-L3-SVO3101" in names
    # Ranking: exakt < Präfix < Teilstring
    assert names == ["SVO3101", "SVO3101-MGMT", "WD-OT-L3-SVO3101"]
    # Subnet-Objekt (/16) ist keine Trace-fähige Quelle → nicht in der Suche
    assert all(h["name"] != "net-x" for h in fmg_source.search(inv, "net"))


async def test_chain_search_dns_fallback_only_when_empty(monkeypatch):
    inv = _ot_inventory()
    chain = ResolverChain()

    called = {"dns": 0}

    async def fake_a(cfg, name, timeout_s=3.0):
        called["dns"] += 1
        return {"ip": "10.5.5.5", "name": f"{name}.corp", "provenance": "dns"}
    monkeypatch.setattr(dns_source, "resolve_name", fake_a)

    # FMG trifft → DNS-Fallback bleibt aus
    hits = await chain.search("svo3101", inv, {}, {"resolvers": []})
    assert called["dns"] == 0 and hits[0]["provenance"] == "fmg"

    # Kein FMG-Treffer + dns_cfg → DNS identifiziert als letzter Schritt
    hits = await chain.search("host-nirgends", inv, {}, {"resolvers": []})
    assert called["dns"] == 1 and hits and hits[0]["provenance"] == "dns"


async def test_chain_ip_input_collects_names(inventory, monkeypatch):
    chain = ResolverChain()

    async def fake_ptr(cfg, ip):
        return {"name": "db01.corp.example", "provenance": "dns"}
    monkeypatch.setattr(dns_source, "resolve_ip", fake_ptr)

    result = await chain.resolve_endpoint("10.2.1.30", inventory, {}, {})
    assert result["ip"] == "10.2.1.30"
    provs = [n["provenance"] for n in result["names"]]
    assert provs == ["fmg", "dns"]  # iTop nicht konfiguriert → übersprungen


async def test_chain_name_fmg_first(inventory, monkeypatch):
    chain = ResolverChain()

    async def fail_dns(cfg, name):  # DNS darf gar nicht gefragt werden
        raise AssertionError("DNS gefragt obwohl FMG getroffen hat")
    monkeypatch.setattr(dns_source, "resolve_name", fail_dns)

    result = await chain.resolve_endpoint("srv-db", inventory, {}, {})
    assert result["ip"] == "10.2.1.30" and result["provenance"] == "fmg"


async def test_chain_name_dns_fallback(inventory, monkeypatch):
    chain = ResolverChain()

    async def fake_a(cfg, name):
        return {"ip": "10.1.2.20", "name": f"{name}.corp.example", "provenance": "dns"}
    monkeypatch.setattr(dns_source, "resolve_name", fake_a)

    result = await chain.resolve_endpoint("web01", inventory, {}, {})
    assert result["ip"] == "10.1.2.20" and result["provenance"] == "dns"


async def test_chain_unresolvable_raises(inventory, monkeypatch):
    chain = ResolverChain()

    async def no_a(cfg, name):
        return None
    monkeypatch.setattr(dns_source, "resolve_name", no_a)

    with pytest.raises(ValueError, match="keine Quelle"):
        await chain.resolve_endpoint("gibts-nicht", inventory, {}, {})
