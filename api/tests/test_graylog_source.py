"""Graylog als eigene Quelle: Zählen, Aggregation (Views-API), Winlogbeat-Erkennung,
Übernahme der Verbindung aus den Webdrive-Einstellungen."""
from __future__ import annotations

import json
from datetime import datetime, timezone

import httpx
import pytest

from graylog import config as gconfig, winlog
from graylog.client import DEFAULT_STREAM, GraylogClient, GraylogError

CFG = {"base_url": "http://10.0.0.5:9000", "token": "tok"}
NOW = datetime(2026, 10, 23, 6, 30, tzinfo=timezone.utc)


def views_reply(body: dict, rows: list[tuple[str, int]], errors=None) -> dict:
    q = body["queries"][0]
    sid = q["search_types"][0]["id"]
    leaf = [{"key": [k], "source": "leaf",
             "values": [{"key": ["count()"], "value": n, "rollup": True, "source": "row-leaf"}]}
            for k, n in rows]
    total = {"key": [], "source": "non-leaf",
             "values": [{"key": ["count()"], "value": sum(n for _, n in rows)}]}
    return {"results": {q["id"]: {"errors": errors or [],
                                  "search_types": {sid: {"rows": [total] + leaf}}}}}


def client(handler):
    return GraylogClient(transport=httpx.MockTransport(handler))


async def test_count_uses_total_results_and_the_default_stream():
    seen = []

    def handler(req):
        seen.append(req)
        return httpx.Response(200, json={"total_results": 4711, "messages": []})

    n = await client(handler).count(CFG, "x:1", NOW.replace(hour=0), NOW)
    assert n == 4711
    assert seen[0].url.params["limit"] == "1"
    assert seen[0].url.params["filter"] == f"streams:{DEFAULT_STREAM}"


async def test_aggregate_posts_a_pivot_and_reads_leaf_rows():
    seen = []

    def handler(req):
        body = json.loads(req.content)
        seen.append((req, body))
        return httpx.Response(200, json=views_reply(body, [("iFIX", 30), ("MSSQL", 120)]))

    out = await client(handler).aggregate(CFG, "winlog_channel:Application", NOW.replace(hour=0),
                                          NOW, "winlog_provider_name", 10)
    assert out == [("MSSQL", 120), ("iFIX", 30)]
    req, body = seen[0]
    assert req.method == "POST" and req.url.path == "/api/views/search/sync"
    assert req.headers["x-requested-by"] == "a38"
    st = body["queries"][0]["search_types"][0]
    assert st["type"] == "pivot" and st["row_groups"][0]["field"] == "winlog_provider_name"
    assert body["queries"][0]["filter"]["filters"][0]["id"] == DEFAULT_STREAM


async def test_aggregate_errors_are_loud():
    def handler(req):
        return httpx.Response(200, json=views_reply(json.loads(req.content), [],
                                                    errors=[{"description": "kaputt"}]))

    with pytest.raises(GraylogError, match="kaputt"):
        await client(handler).aggregate(CFG, "*", NOW, NOW, "f")


def test_role_queries_follow_the_field_prefix():
    assert winlog.role_query({}, "ad", "winlogbeat_") == "winlogbeat_winlog_channel:Security"
    assert winlog.role_query({}, "ad", "") == "winlog_channel:Security"
    cfg = {"roles": {"ifix": {"filter": "{p}winlog_provider_name:iFIX"}}}
    assert winlog.role_query(cfg, "ifix", "") == "winlog_provider_name:iFIX"
    assert winlog.prefix_of({"field_prefix": ""}, "winlogbeat_") == ""
    dcs = {"roles": {"ad": {"hosts": ["dc01", " dc02 ", "dc01"]}, "ifix": {"hosts": ["scada1"]}}}
    assert winlog.role_query(dcs, "ad", "") == \
        '(winlog_channel:Security) AND source:("dc01" OR "dc02")'
    assert winlog.role_query(dcs, "ifix", "") == 'source:("scada1")'
    assert winlog.prefix_of({}, None) == "winlogbeat_"


class FakeClient:
    def __init__(self, prefix: str, aggregate_fails: bool = False):
        self.prefix, self.fails = prefix, aggregate_fails

    async def test(self, cfg):
        return {"version": "5.0.13"}

    async def streams(self, cfg):
        return [{"id": DEFAULT_STREAM, "title": "All messages", "disabled": False,
                 "removes_from_default": False}]

    async def count(self, cfg, query, frm, to):
        if query.startswith("_exists_:"):
            return 5 if query == f"_exists_:{self.prefix}winlog_event_id" else 0
        return 1234 if "Security" in query else 0

    async def sample(self, cfg, query, frm, to, limit=50):
        return [{f"{self.prefix}winlog_computer_name": "dc01", "source": "dc01"},
                {f"{self.prefix}winlog_computer_name": "dc02"},
                {f"{self.prefix}winlog_computer_name": "dc01",
                 f"{self.prefix}winlog_provider_name": "iFIX"}]

    async def aggregate(self, cfg, query, frm, to, field, limit=20):
        if self.fails:
            raise GraylogError("403")
        if field == "source":
            return [("SCADA01", 900), ("dc01", 80)]
        assert field == f"{self.prefix}winlog_provider_name"
        return [("iFIX", 42)]


@pytest.mark.parametrize("prefix", ["winlogbeat_", ""])
async def test_diagnose_detects_prefix_counts_roles_and_suggests_providers(prefix):
    out = await winlog.diagnose(FakeClient(prefix), {}, NOW)
    assert out["version"] == "5.0.13" and out["winlogbeat"] and out["prefix"] == prefix
    assert out["roles"]["ad"]["hits"] == 1234
    assert out["roles"]["ad"]["computers"] == ["dc01", "dc02"]
    assert out["roles"]["ifix"]["error"] == "Weder Rechner noch Filter eingetragen."
    assert out["providers"] == [{"name": "iFIX", "hits": 42}]
    assert out["hosts"][0] == {"name": "SCADA01", "hits": 900}
    assert out["aggregation"] == {"ok": True, "error": None}


async def test_diagnose_falls_back_to_a_sample_without_views_rights():
    out = await winlog.diagnose(FakeClient("", aggregate_fails=True), {}, NOW)
    assert out["aggregation"]["ok"] is False and "403" in out["aggregation"]["error"]
    assert out["providers"] == [{"name": "iFIX", "hits": 1, "sampled": True}]
    assert out["hosts"] == [{"name": "dc01", "hits": 1, "sampled": True}]


def test_webdrive_keeps_its_own_connection_and_falls_back_to_graylog():
    gl = {"base_url": "https://gl", "token": "report", "ssl_verify": False}
    own = gconfig.merge({"base_url": "https://wd", "token": "wd", "stream_id": "s"}, gl)
    assert own["base_url"] == "https://wd" and own["token"] == "wd"
    shared = gconfig.merge({"stream_id": "s"}, gl)
    assert shared["base_url"] == "https://gl" and shared["token"] == "report"
    assert shared["ssl_verify"] is False and shared["stream_id"] == "s"


async def test_migration_copies_the_connection_once(monkeypatch):
    store = {"webdrive": {"base_url": "https://gl", "token": "t", "stream_id": "s"},
             "graylog": {}}

    async def read(key):
        return dict(store.get(key) or {})

    async def write(key, value):
        store[key] = value

    monkeypatch.setattr(gconfig, "read_config", read)
    monkeypatch.setattr(gconfig, "write_config", write)
    assert await gconfig.migrate() is True
    assert store["graylog"] == {"base_url": "https://gl", "token": "t"}
    assert store["webdrive"]["token"] == "t"                       # Webdrive bleibt unverändert
    assert await gconfig.migrate() is False
