"""FortiAnalyzer-Assets (Asset Identity Center) als Host-Quelle."""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import httpx
import pytest

from diagram import model as diagram_model
from faz.client import FazError, FazSource, normalize

NOW = datetime(2026, 10, 9, 12, 0, tzinfo=timezone.utc)
CFG = {"base_url": "https://10.0.17.40", "token": "tok", "adom": "root"}


def test_normalize_tolerates_field_spellings_and_several_ips():
    rec = {"epid": 7, "epname": "plc-7", "epip": "10.1.1.50, 10.1.2.50",
           "mac-addr": "00:0C:29:AA:BB:CC", "lastseen": int((NOW - timedelta(hours=2)).timestamp()),
           "os": "Linux"}
    hosts = normalize(rec, NOW)
    assert [h["ip"] for h in hosts] == ["10.1.1.50", "10.1.2.50"]
    h = hosts[0]
    assert (h["name"], h["mac"], h["os"], h["epid"]) == ("plc-7", "000c29aabbcc", "Linux", 7)
    assert h["age_s"] == 7200


def test_normalize_skips_records_without_ipv4():
    assert normalize({"epid": 1, "epname": "x", "epip": "fe80::1"}, NOW) == []
    assert normalize({"epid": 2, "epname": "y"}, NOW) == []


def _faz(body, status=200):
    seen = []

    def handler(request):
        seen.append(json.loads(request.content))
        return httpx.Response(status, json=body)

    return FazSource(transport=httpx.MockTransport(handler)), seen


async def test_endpoints_asks_ueba_and_drops_stale_ones():
    fresh = int(datetime.now(timezone.utc).timestamp()) - 3600
    stale = fresh - 30 * 86400
    body = {"result": [{"status": {"code": 0, "message": "OK"}, "data": [
        {"epid": 1, "epname": "live", "epip": "10.1.1.60", "lastseen": fresh},
        {"epid": 2, "epname": "alt", "epip": "10.1.1.61", "lastseen": stale},
        {"epid": 3, "epname": "ohne-zeit", "epip": "10.1.1.62"}]}]}
    faz, seen = _faz(body)
    hosts = await faz.endpoints(dict(CFG, max_age_days=7))
    assert {h["name"] for h in hosts} == {"live", "ohne-zeit"}
    p = seen[0]["params"][0]
    assert p["url"] == "/ueba/adom/root/endpoints" and p["apiver"] == 3
    await faz.endpoints(dict(CFG, max_age_days=7))
    assert len(seen) == 1                                  # gecacht


async def test_dict_shaped_result_is_read_too():
    faz, _ = _faz({"result": {"data": {"data": [{"epid": 1, "epip": "10.1.1.70"}]}}})
    assert [h["ip"] for h in await faz.endpoints(CFG)] == ["10.1.1.70"]


async def test_faz_error_status_is_raised():
    faz, _ = _faz({"result": [{"status": {"code": -11, "message": "No permission"}}]})
    with pytest.raises(FazError, match="No permission"):
        await faz.endpoints(CFG)


async def test_test_reports_the_fields_the_faz_really_sends():
    faz, _ = _faz({"result": [{"status": {"code": 0}, "data": [
        {"epid": 1, "epip": "10.1.1.70", "epname": "a", "mac": "000c29000001"}]}]})
    r = await faz.test(CFG)
    assert r["endpoints"] == 1 and r["with_mac"] == 1 and r["fields"] == ["epid", "epip", "epname", "mac"]


NET = {"cidr": "10.1.1.0/24", "fw_ip": "10.1.1.1"}


async def _hosts(inventory, *, arp_rows=(), faz=None, max_age=0):
    async def arp(_cidr):
        return list(arp_rows)
    return {h["ip"]: h for h in await diagram_model._collect_hosts(
        dict(NET), inventory, [], {}, arp, {}, faz, max_age)}


async def test_faz_adds_live_hosts_with_their_own_source(inventory):
    faz = [{"ip": "10.1.1.80", "name": "sensor-80", "mac": "000c29000080",
            "last_seen": NOW.isoformat(), "age_s": 60, "os": "RTOS", "epid": 9},
           {"ip": "10.9.9.9", "name": "woanders", "mac": None, "last_seen": None,
            "age_s": None, "os": None, "epid": 10}]
    hosts = await _hosts(inventory, faz=faz)
    assert list(hosts) == ["10.1.1.80"]
    h = hosts["10.1.1.80"]
    assert h["sources"] == ["faz"] and h["name"] == "sensor-80" and h["faz"]["os"] == "RTOS"


async def test_old_arp_bindings_are_left_out_but_faz_keeps_the_host(inventory):
    rows = [{"ip": "10.1.1.90", "mac": "000c29000090", "last_seen": "x", "age_s": 90 * 86400},
            {"ip": "10.1.1.91", "mac": "000c29000091", "last_seen": "y", "age_s": 3600}]
    faz = [{"ip": "10.1.1.90", "name": "lebt", "mac": None, "last_seen": "z", "age_s": 30,
            "os": None, "epid": 1}]
    hosts = await _hosts(inventory, arp_rows=rows, max_age=30 * 86400)
    assert "10.1.1.90" not in hosts and "10.1.1.91" in hosts
    hosts = await _hosts(inventory, arp_rows=rows, faz=faz, max_age=30 * 86400)
    assert hosts["10.1.1.90"]["sources"] == ["faz"] and hosts["10.1.1.90"]["age_s"] == 30
    assert (await _hosts(inventory, arp_rows=rows))["10.1.1.90"]["sources"] == ["arp"]  # 0 = alle
