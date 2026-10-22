"""Zabbix: JSON-RPC mit Bearer-Token, Zuordnung per IP/Name, Status-Punkte in den Plänen."""
from __future__ import annotations

import json
import xml.etree.ElementTree as ET

import httpx
import pytest

from diagram import segments, vlanphys
from test_diagram_segments import _build
from test_diagram_vlanphys import _model
from zabbix import client as zclient, status

CFG = {"base_url": "https://zabbix.example.net/", "token": "tok"}

HOSTS = [
    {"hostid": "1", "host": "bk-d", "name": "Backup D", "status": "0", "maintenance_status": "0",
     "interfaces": [{"ip": "10.4.5.10", "dns": "", "available": "1"}]},
    {"hostid": "2", "host": "fremd-d.corp.example", "name": "fremd-d.corp.example",
     "status": "0", "maintenance_status": "0",
     "interfaces": [{"ip": "10.9.9.9", "dns": "", "available": "2"}]},
    {"hostid": "3", "host": "sw-acc", "name": "sw-acc", "status": "0", "maintenance_status": "0",
     "interfaces": [{"ip": "10.4.5.3", "dns": "", "available": "1"}]},
    {"hostid": "4", "host": "alt", "name": "alt", "status": "1", "maintenance_status": "0",
     "interfaces": [{"ip": "10.4.5.10", "dns": "", "available": "0"}]},
]
TRIGGERS = [
    {"triggerid": "10", "description": "Disk / voll", "priority": "4", "lastchange": "100",
     "hosts": [{"hostid": "1"}], "lastEvent": {"acknowledged": "1", "suppressed": "0"}},
    {"triggerid": "11", "description": "Last hoch", "priority": "2", "lastchange": "200",
     "hosts": [{"hostid": "1"}], "lastEvent": {"acknowledged": "0", "suppressed": "0"}},
    {"triggerid": "12", "description": "unterdrückt", "priority": "5", "lastchange": "300",
     "hosts": [{"hostid": "3"}], "lastEvent": {"acknowledged": "0", "suppressed": "1"}},
]


def test_index_matches_by_ip_then_name_and_ranks_problems():
    idx = status.index(HOSTS, TRIGGERS)
    st = status.lookup(idx, "10.4.5.10")
    assert st["hostid"] == "1"                     # aktiver Host schlägt den deaktivierten
    assert st["state"] == "problem" and st["severity"] == 4
    assert [p["name"] for p in st["problems"]] == ["Disk / voll", "Last hoch"]
    # Name, auch ohne Domain, wenn die IP nicht passt.
    assert status.lookup(idx, "10.4.5.20", "fremd-d")["state"] == "down"
    assert status.lookup(idx, None, "sw-acc")["state"] == "ok"   # unterdrückt zählt nicht
    assert status.lookup(idx, "10.1.1.1", "unbekannt") is None
    assert "Hoch" in status.tooltip(st) and "(quittiert)" in status.tooltip(st)


def test_annotate_counts_and_leaves_unknown_hosts_without_status():
    idx = status.index(HOSTS, TRIGGERS)
    hosts = [{"ip": "10.4.5.10"}, {"ip": "10.4.5.20", "name": "fremd-d"}, {"ip": "10.4.5.77"}]
    counts = status.annotate(idx, hosts)
    assert counts == {"monitored": 2, "problems": 1, "down": 1, "unmonitored": 1}
    assert "zabbix" not in hosts[2]


async def test_client_sends_bearer_and_version_without_auth(monkeypatch):
    seen = []

    def handler(req: httpx.Request) -> httpx.Response:
        body = json.loads(req.content)
        seen.append((body["method"], req.headers.get("authorization")))
        assert str(req.url) == "https://zabbix.example.net/api_jsonrpc.php"
        result = {"apiinfo.version": "7.4.15", "host.get": HOSTS,
                  "trigger.get": TRIGGERS,
                  "hostgroup.get": [{"groupid": "2", "name": "Linux servers", "hosts": "3"},
                                    {"groupid": "7", "name": "Switches", "hosts": "1"}],
                  }[body["method"]]
        return httpx.Response(200, json={"jsonrpc": "2.0", "result": result, "id": 1})

    real = httpx.AsyncClient
    monkeypatch.setattr(zclient.httpx, "AsyncClient",
                        lambda **kw: real(transport=httpx.MockTransport(handler), **kw))
    monkeypatch.setattr(zclient, "guard_egress_url", lambda *a: None)
    c = zclient.ZabbixClient()
    out = await c.test(CFG)
    assert out["version"] == "7.4.15" and out["hosts"] == 4 and out["problems"] == 3
    assert out["groups"][0] == {"id": "2", "name": "Linux servers", "hosts": 3}
    assert not out["filtered"]
    assert seen[:3] == [("apiinfo.version", None), ("host.get", "Bearer tok"),
                        ("trigger.get", "Bearer tok")]
    await c.hosts(CFG)                                            # gecacht
    assert len(seen) == 4


async def test_client_raises_on_rpc_error(monkeypatch):
    def handler(req):
        return httpx.Response(200, json={"jsonrpc": "2.0", "id": 1, "error": {
            "code": -32602, "message": "Invalid params.", "data": "Not authorized."}})

    real = httpx.AsyncClient
    monkeypatch.setattr(zclient.httpx, "AsyncClient",
                        lambda **kw: real(transport=httpx.MockTransport(handler), **kw))
    monkeypatch.setattr(zclient, "guard_egress_url", lambda *a: None)
    with pytest.raises(zclient.ZabbixError, match="Not authorized"):
        await zclient.ZabbixClient().hosts(CFG)
    with pytest.raises(zclient.ZabbixNotConfigured):
        await zclient.ZabbixClient().hosts({"base_url": "https://x"})


def _dots(xml: str) -> list[str]:
    root = ET.fromstring(xml)
    out = []
    for c in root.iter("mxCell"):
        style = c.get("style") or ""
        if style.startswith("ellipse;html=1;aspect=fixed;fillColor="):
            out.append(style.split("fillColor=")[1].split(";")[0])
    return out


async def test_segment_plan_draws_a_dot_only_for_monitored_hosts(inventory, prefixes):
    m = await _build(inventory, prefixes)
    assert _dots(segments.render(m)) == []
    idx = status.index(HOSTS, TRIGGERS)
    status.annotate(idx, (h for s in m["sites"] for n in s["segments"] for h in n["hosts"]))
    m["zabbix"] = True
    xml = segments.render(m)
    assert status.SEVERITY_COLOR[4] in _dots(xml)                 # bk-d mit Problem „Hoch“
    assert "Zabbix: ok" in xml


async def test_switch_physics_marks_hosts_and_switches(inventory, prefixes):
    m = await _model(inventory, prefixes)
    idx = status.index(HOSTS, TRIGGERS)
    status.annotate(idx, (r["host"] for sw in m["switches"] for r in sw["hosts"]))
    for sw in m["switches"]:
        sw["zabbix"] = status.lookup(idx, sw.get("ip"), sw["name"])
    m["zabbix"] = True
    dots = _dots(vlanphys.render(m))
    assert status.SEVERITY_COLOR[4] in dots and status.OK_COLOR in dots
