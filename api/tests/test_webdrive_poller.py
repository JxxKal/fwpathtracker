"""Graylog-Client (gegen httpx.MockTransport) und Poller (gegen Attrappen)."""
from __future__ import annotations

import base64
from datetime import timedelta

import httpx
import pytest

from webdrive.graylog import PAGE, GraylogClient, GraylogError, GraylogNotConfigured
from webdrive.parse import parse_ts
from webdrive.poller import WebdrivePoller, build_query, queries
from webdrive_fixtures import CFG, IDENTITIES, at, reference_day

GL_CFG = {**CFG, "base_url": "http://10.0.0.5:9000/api/", "token": "tok", "stream_id": "s1",
          "fac_query": "source:fac01", "oc_query": "source:opencloud"}


# ── Client ────────────────────────────────────────────────────────────────────

def mock_client(pages: list[list[dict]], status: int = 200):
    seen = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        if status != 200:
            return httpx.Response(status, text="nope")
        offset = int(request.url.params["offset"])
        idx = offset // PAGE
        msgs = pages[idx] if idx < len(pages) else []
        return httpx.Response(200, json={"messages": [{"message": m} for m in msgs]})

    return GraylogClient(transport=httpx.MockTransport(handler)), seen


async def test_search_pages_until_short_page():
    full = [{"_id": str(i)} for i in range(PAGE)]
    client, seen = mock_client([full, [{"_id": "x"}]])
    out = await client.search(GL_CFG, "q", at("09:00:00"), at("10:00:00"))
    assert len(out) == PAGE + 1
    req = seen[0]
    assert req.url.path == "/api/search/universal/absolute"      # /api am Ende der URL nicht doppelt
    assert req.url.params["filter"] == "streams:s1"
    assert req.url.params["from"] == "2026-10-07T09:00:00.000Z"
    assert req.url.params["sort"] == "timestamp:asc"
    assert req.headers["authorization"] == "Basic " + base64.b64encode(b"tok:token").decode()


async def test_too_many_messages_in_one_window_is_loud():
    full = [{"_id": str(i)} for i in range(PAGE)]
    client, _ = mock_client([full] * 30)
    with pytest.raises(GraylogError, match="enger fassen"):
        await client.search(GL_CFG, "q", at("09:00:00"), at("10:00:00"))


async def test_rejected_token():
    client, _ = mock_client([], status=401)
    with pytest.raises(GraylogError, match="Token"):
        await client.search(GL_CFG, "q", at("09:00:00"), at("10:00:00"))


async def test_not_configured():
    client, _ = mock_client([])
    with pytest.raises(GraylogNotConfigured):
        await client.test({**GL_CFG, "base_url": ""})
    with pytest.raises(GraylogNotConfigured):
        await client.test({**GL_CFG, "token": ""})


# ── Poller ────────────────────────────────────────────────────────────────────

class FakeGraylog:
    """Gleiche Signatur wie GraylogClient.search; liefert die Referenz-Nachrichten
    der passenden Quelle im angefragten Fenster."""

    def __init__(self, messages, fail_on_call: int | None = None):
        self.messages = messages
        self.fail_on_call = fail_on_call
        self.calls = []

    async def search(self, cfg, query, frm, to):
        self.calls.append((query, frm, to))
        if self.fail_on_call is not None and len(self.calls) == self.fail_on_call:
            raise GraylogError("Graylog nicht erreichbar")
        if "source:fac01" in query:
            want = {"fac"}
        elif "source:opencloud" in query:
            want = {"oc"}
        else:
            want = {"fac", "oc"}                                 # ganzer Stream
        return [m for s, m in self.messages if s in want and frm <= parse_ts(m["timestamp"]) <= to]


class FakeStore:
    def __init__(self, poll=None):
        self.events = {}
        self.identities = {}
        self.poll = dict(poll or {})
        self.purged = None

    async def insert_events(self, events):
        for e in events:
            self.events.setdefault(e.gl_id, e)

    async def load_events(self, since):
        return sorted((e for e in self.events.values() if e.ts >= since), key=lambda e: e.ts)

    async def load_identities(self):
        return dict(self.identities)

    async def save_identities(self, new):
        for k, v in new.items():
            self.identities.setdefault(k, v)

    async def get_poll(self):
        return dict(self.poll)

    async def mark_ok(self, polled_until, at, stats):
        self.poll.update(polled_until=polled_until, last_ok=at, last_error=None, stats=stats)

    async def mark_error(self, msg, at):
        self.poll["last_error"] = msg

    async def purge(self, days):
        self.purged = days


NOW = at("11:00:00")


def test_query_excludes_userinfo_noise():
    assert build_query("source:fac01") == '(source:fac01) AND NOT "Failed to send user info"'


def test_queries_are_optional_with_a_stream():
    assert queries({"stream_id": "s1"}) == ['(*) AND NOT "Failed to send user info"']
    assert queries({"stream_id": "s1", "fac_query": "a", "oc_query": "a"}) == [build_query("a")]
    assert queries({}) == []


async def test_stream_only_recognizes_both_sources():
    gl, store = FakeGraylog(reference_day()), FakeStore(poll={"polled_until": NOW - timedelta(hours=6)})
    stats = await WebdrivePoller(gl, store).run_once({**GL_CFG, "fac_query": "", "oc_query": ""}, NOW)
    assert stats["fac_events"] > 0 and stats["oc_events"] > 0
    assert store.identities == IDENTITIES


async def test_nothing_to_query_is_an_error():
    with pytest.raises(GraylogNotConfigured):
        await WebdrivePoller(FakeGraylog([]), FakeStore()).run_once(
            {**GL_CFG, "fac_query": "", "oc_query": "", "stream_id": ""}, NOW)


async def test_first_run_catches_up_24h_in_slices():
    gl, store = FakeGraylog(reference_day()), FakeStore()
    stats = await WebdrivePoller(gl, store).run_once(GL_CFG, NOW)
    assert len(gl.calls) == 48                                   # 24 Scheiben × 2 Quellen
    assert gl.calls[0][1] == NOW - timedelta(hours=24)
    assert all(to - frm <= timedelta(hours=1) for _, frm, to in gl.calls)
    assert store.poll["polled_until"] == NOW
    assert stats["fac_dropped"] >= 2                             # Rauschen gezählt, nicht gespeichert
    assert store.identities == IDENTITIES
    assert store.purged == 7


async def test_next_run_overlaps_two_minutes_without_duplicates():
    gl, store = FakeGraylog(reference_day()), FakeStore()
    poller = WebdrivePoller(gl, store)
    await poller.run_once(GL_CFG, NOW)
    n = len(store.events)
    store.poll["polled_until"] = at("10:44:00")                  # Stand zurückdrehen → Überlappung
    gl.calls.clear()
    await poller.run_once(GL_CFG, NOW)
    assert gl.calls[0][1] == at("10:42:00")
    assert len(store.events) == n


async def test_outage_keeps_progress_and_raises():
    gl = FakeGraylog(reference_day(), fail_on_call=5)            # 3. Scheibe, FAC
    store = FakeStore(poll={"polled_until": NOW - timedelta(hours=5)})
    with pytest.raises(GraylogError):
        await WebdrivePoller(gl, store).run_once(GL_CFG, NOW)
    start = NOW - timedelta(hours=5, minutes=2)
    assert store.poll["polled_until"] == start + timedelta(hours=2)
    assert store.poll["last_error"] == "Graylog nicht erreichbar"


async def test_long_outage_is_capped_at_24h():
    gl, store = FakeGraylog([]), FakeStore(poll={"polled_until": NOW - timedelta(days=3)})
    await WebdrivePoller(gl, store).run_once(GL_CFG, NOW)
    assert gl.calls[0][1] == NOW - timedelta(hours=24)


async def test_source_without_query_is_skipped():
    gl, store = FakeGraylog(reference_day()), FakeStore(poll={"polled_until": NOW - timedelta(minutes=1)})
    await WebdrivePoller(gl, store).run_once({**GL_CFG, "oc_query": ""}, NOW)
    assert all("source:fac01" in q for q, _, _ in gl.calls)
    assert not any("source:opencloud" in q for q, _, _ in gl.calls)
