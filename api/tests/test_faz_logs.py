"""FortiAnalyzer-Logsuche: „Gestern ging es noch", geblockte Flows."""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import httpx
import pytest

from faz import logs as faz_logs
from faz.client import FazSource

NOW = datetime(2026, 10, 19, 12, 0, tzinfo=timezone.utc)
UTC = timezone.utc
CFG = {"base_url": "https://10.0.17.40", "token": "tok", "adom": "root", "search_timeout_s": 5}


def _log(minutes_ago: float, action: str, *, dev="fw-a", vd="root", pid=12, **kw) -> dict:
    ts = NOW - timedelta(minutes=minutes_ago)
    return {"itime": int(ts.timestamp()), "action": action, "devname": dev, "vd": vd,
            "policyid": pid, "srcip": "10.1.1.10", "dstip": "10.2.1.20", "proto": 6,
            "dstport": 443, "srcintf": "lan1", "dstintf": "vpn-to-b",
            "sentbyte": 100, "rcvdbyte": 200, **kw}


def _names(dev, vd, pid):
    return {12: "lan-to-b", 40: "block-legacy"}.get(pid)


def _history(logs, hours=48):
    return faz_logs.flow_history(logs, hours=hours, tz=UTC, policy_name=_names, now=NOW)


def test_filters_only_take_valid_ips_and_known_protocols():
    assert faz_logs.flow_filter("10.1.1.10", "10.2.1.20", "TCP", 443) == \
        "srcip==10.1.1.10 and dstip==10.2.1.20 and proto==6 and dstport==443"
    assert faz_logs.flow_filter("10.1.1.10", "10.2.1.20", "icmp", 443) == \
        "srcip==10.1.1.10 and dstip==10.2.1.20 and proto==1"
    assert faz_logs.deny_filter("10.1.1.10", "dst") == "dstip==10.1.1.10 and action==deny"
    with pytest.raises(ValueError):
        faz_logs.flow_filter("10.1.1.10 or 1==1", "10.2.1.20")


def test_eventtime_in_nanoseconds_wins_over_date_and_time():
    ns = int(NOW.timestamp()) * 10**9
    assert faz_logs.log_time({"eventtime": ns, "date": "2001-01-01", "time": "00:00:00"},
                             UTC) == NOW
    assert faz_logs.log_time({"date": "2026-10-19", "time": "14:00:00"},
                             faz_logs.tz_of({"timezone": "Europe/Berlin"})) == NOW


def test_blocked_since_names_the_turning_point_and_the_blocker():
    logs = [_log(30, "deny", pid=40), _log(90, "deny", pid=40), _log(26 * 60, "close"),
            _log(27 * 60, "accept"), _log(28 * 60, "timeout", dev="fw-b")]
    r = _history(logs)
    assert r["verdict"] == "blocked_since"
    assert r["since"] == (NOW - timedelta(minutes=90)).isoformat()
    assert r["last_allow"] == (NOW - timedelta(hours=26)).isoformat()
    b = r["blocker"]
    assert (b["device"], b["policyid"], b["policy"], b["count"]) == ("fw-a", 40,
                                                                     "40 · block-legacy", 2)
    assert r["counts"] == {"allow": 3, "deny": 2, "other": 0, "lines": 5}
    # je Firewall/Regel/Ergebnis eine Zeile, jüngste zuerst
    assert [(h["device"], h["policyid"], h["outcome"]) for h in r["hops"]] == [
        ("fw-a", 40, "deny"), ("fw-a", 12, "allow"), ("fw-b", 12, "allow")]
    assert sum(s["deny"] for s in r["timeline"]) == 2 and r["bucket_s"] == 3600


def test_silence_is_its_own_verdict():
    r = _history([_log(5 * 60, "close"), _log(6 * 60, "close")])
    assert r["verdict"] == "silent_since"
    assert r["since"] == (NOW - timedelta(hours=5)).isoformat()


def test_allowed_and_implicit_deny_and_nothing():
    assert _history([_log(5, "close"), _log(60, "accept")])["verdict"] == "always_allowed"
    r = _history([_log(5, "deny", pid=0)])
    assert r["verdict"] == "always_blocked" and r["blocker"]["policy"] == "Implicit Deny"
    r = _history([_log(5, "close"), _log(60, "deny", pid=40)])
    assert r["verdict"] == "allowed_again"
    assert _history([])["verdict"] == "none"


def test_blocked_groups_by_peer_port_and_rule():
    logs = [_log(1, "deny", pid=0), _log(2, "deny", pid=0), _log(3, "deny", pid=0, dstport=22),
            _log(4, "close")]
    rows = faz_logs.blocked(logs, direction="src", tz=UTC, policy_name=_names)
    assert [(r["peer"], r["dst_port"], r["count"], r["policy"]) for r in rows] == [
        ("10.2.1.20", 443, 2, "Implicit Deny"), ("10.2.1.20", 22, 1, "Implicit Deny")]
    assert rows[0]["protocol"] == "tcp"
    assert rows[0]["last"] == (NOW - timedelta(minutes=1)).isoformat()


def _faz(pages: list[dict]):
    """FAZ-Attrappe: add → tid, get → nacheinander die Seiten, delete → ok."""
    seen: list[dict] = []
    gets = iter(pages)

    def handler(request):
        body = json.loads(request.content)
        seen.append(body)
        method = body["method"]
        if method == "add":
            return httpx.Response(200, json={"result": {"tid": 77, "status": {"code": 0}}})
        if method == "delete":
            return httpx.Response(200, json={"result": {"status": {"code": 0}}})
        return httpx.Response(200, json={"result": next(gets)})

    return FazSource(transport=httpx.MockTransport(handler)), seen


async def test_logsearch_polls_until_done_and_cleans_up(monkeypatch):
    monkeypatch.setattr("faz.client.POLL_S", 0)
    faz, seen = _faz([
        {"percentage": 40, "data": [], "status": {"code": 0}},
        {"percentage": 100, "data": [{"action": "deny"}], "total-count": 1,
         "status": {"code": 0}},
    ])
    res = await faz.logsearch(CFG, logtype="traffic", filter="srcip==10.1.1.10",
                              start="2026-10-19 10:00:00", end="2026-10-19 12:00:00")
    assert res == {"logs": [{"action": "deny"}], "complete": True, "total": 1}
    add = seen[0]["params"][0]
    assert add["url"] == "/logview/adom/root/logsearch" and add["apiver"] == 3
    assert add["device"] == [{"devid": "All_FortiGate"}] and add["time-order"] == "desc"
    assert add["time-range"] == {"start": "2026-10-19 10:00:00", "end": "2026-10-19 12:00:00"}
    assert [b["method"] for b in seen] == ["add", "get", "get", "delete"]
    assert seen[1]["params"][0]["url"] == "/logview/adom/root/logsearch/77"
    # gleiche Frage binnen einer Minute: aus dem Cache
    await faz.logsearch(CFG, logtype="traffic", filter="srcip==10.1.1.10",
                        start="2026-10-19 10:00:00", end="2026-10-19 12:00:00")
    assert len(seen) == 4


async def test_logsearch_reads_the_nested_layout_too(monkeypatch):
    monkeypatch.setattr("faz.client.POLL_S", 0)
    faz, _ = _faz([{"data": {"status": "done", "percentage": 100, "total_lines": 2,
                             "logs": [{"a": 1}, {"a": 2}]}, "status": {"code": 0}}])
    res = await faz.logsearch(CFG, logtype="traffic", filter="x", start="s", end="e")
    assert res["logs"] == [{"a": 1}, {"a": 2}] and res["total"] == 2


async def test_logsearch_gives_up_at_the_deadline_with_partial_rows(monkeypatch):
    monkeypatch.setattr("faz.client.POLL_S", 0)
    faz, seen = _faz([{"percentage": 10, "data": [{"a": 1}], "status": {"code": 0}}] * 50)
    res = await faz.logsearch(dict(CFG, search_timeout_s=0), logtype="traffic",
                              filter="x", start="s", end="e")
    assert res["complete"] is False and res["logs"] == [{"a": 1}]
    assert seen[-1]["method"] == "delete"
