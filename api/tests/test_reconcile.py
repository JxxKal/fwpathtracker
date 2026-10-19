"""Bestandsabgleich iTop ↔ ARP-Historie ↔ FortiAnalyzer ↔ DNS."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from ipam.reconcile import reconcile, short_name

NOW = datetime(2026, 10, 19, 12, 0, tzinfo=timezone.utc)


def _ago(**kw) -> str:
    return (NOW - timedelta(**kw)).isoformat()


def _arp(ip, mac, first, last):
    return {"ip": ip, "mac": mac, "first_seen": first, "last_seen": last,
            "device": "fw-a", "vdom": "root", "interface": "lan1"}


def _run(**kw):
    args = dict(itop_hosts=[], itop_addresses={}, arp_rows=[], faz_hosts=None,
                dns_names={}, librenms_devices={}, fmg_names={}, now=NOW)
    args.update(kw)
    out = reconcile("10.1.1.0/24", **args)
    return out, {r["ip"]: r for r in out["rows"]}


def codes(row):
    return [f["code"] for f in row["findings"]]


def test_short_name_ignores_domains_and_fake_names():
    assert short_name("SRV-01.corp.local.") == "srv-01"
    assert short_name("10.1.1.5") is None and short_name("00:0c:29:aa:bb:cc") is None
    assert short_name("Unknown") is None


def test_active_host_without_itop_entry():
    out, rows = _run(arp_rows=[_arp("10.1.1.20", "aa", _ago(days=3), _ago(hours=1))],
                     dns_names={"10.1.1.20": "kamera-7.corp"})
    assert codes(rows["10.1.1.20"]) == ["not_in_itop"]
    assert rows["10.1.1.20"]["display_name"] == "kamera-7.corp"
    assert out["counts"] == {"not_in_itop": 1}


def test_released_ip_object_that_is_in_use():
    _, rows = _run(itop_addresses={"10.1.1.21": {"status": "released", "name": ""}},
                   faz_hosts=[{"ip": "10.1.1.21", "name": "pc-21", "mac": "bb",
                               "last_seen": _ago(minutes=5), "os": "Windows"}])
    assert codes(rows["10.1.1.21"]) == ["itop_released"]
    assert rows["10.1.1.21"]["os"] == "Windows"


def test_stale_itop_entry_only_when_the_network_is_observed():
    ci = [{"ip": "10.1.1.30", "name": "alt-srv", "kind": "Server", "id": "5"}]
    _, rows = _run(itop_hosts=ci)
    assert codes(rows["10.1.1.30"]) == []                    # niemand schaut hin
    _, rows = _run(itop_hosts=ci, arp_rows=[
        _arp("10.1.1.30", "cc", _ago(days=200), _ago(days=60)),
        _arp("10.1.1.31", "dd", _ago(days=1), _ago(hours=1))])
    assert codes(rows["10.1.1.30"]) == ["stale_in_itop"]
    assert "60 Tagen" in rows["10.1.1.30"]["findings"][0]["text"]


def test_two_macs_at_once_is_a_conflict_one_after_the_other_a_swap():
    _, rows = _run(itop_hosts=[{"ip": "10.1.1.40", "name": "x", "kind": "Server"}], arp_rows=[
        _arp("10.1.1.40", "aa", _ago(days=5), _ago(hours=1)),
        _arp("10.1.1.40", "bb", _ago(days=2), _ago(hours=2))])
    assert codes(rows["10.1.1.40"]) == ["ip_conflict"]
    _, rows = _run(itop_hosts=[{"ip": "10.1.1.40", "name": "x", "kind": "Server"}], arp_rows=[
        _arp("10.1.1.40", "aa", _ago(days=6), _ago(days=4)),
        _arp("10.1.1.40", "bb", _ago(days=3), _ago(hours=1))])
    assert codes(rows["10.1.1.40"]) == ["mac_changed"]


def test_name_mismatch_against_dns_and_faz():
    _, rows = _run(itop_hosts=[{"ip": "10.1.1.50", "name": "SPS-50", "kind": "Server"}],
                   arp_rows=[_arp("10.1.1.50", "aa", _ago(days=1), _ago(hours=1))],
                   dns_names={"10.1.1.50": "sps-50.corp.local"},
                   faz_hosts=[{"ip": "10.1.1.50", "name": "DESKTOP-4711", "mac": "aa",
                               "last_seen": _ago(hours=1)}])
    f = rows["10.1.1.50"]["findings"]
    assert [x["code"] for x in f] == ["name_mismatch"]
    assert "DESKTOP-4711" in f[0]["text"] and "DNS" not in f[0]["text"]


def test_network_and_broadcast_are_never_hosts():
    out, rows = _run(itop_addresses={"10.1.1.0": {"status": "allocated", "name": "net"},
                                     "10.1.1.255": {"status": "allocated", "name": "bc"}})
    assert rows == {} and out["stats"]["hosts"] == 0


def test_firewall_interfaces_and_reserved_addresses_are_not_stale():
    _, rows = _run(itop_addresses={"10.1.1.1": {"status": "allocated", "name": "gw"},
                                   "10.1.1.9": {"status": "reserved", "name": "frei"}},
                   firewall_ips={"10.1.1.1": "fw-a/lan1"},
                   arp_rows=[_arp("10.1.1.31", "dd", _ago(days=1), _ago(hours=1))])
    assert rows["10.1.1.1"]["kind"] == "firewall" and codes(rows["10.1.1.1"]) == []
    assert codes(rows["10.1.1.9"]) == []
