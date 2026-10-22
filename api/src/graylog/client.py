"""Graylog-REST-Client (nur lesend): klassische Suche über ein Zeitfenster,
Trefferzahlen und Aggregationen.

/api/search/universal/absolute gibt es in Graylog 4–6. Der API-Token wird als
Basic Auth übergeben (`<token>:token`). OpenSearch begrenzt offset+limit auf
10.000 (max_result_window) — der Poller fragt deshalb in Zeitscheiben ab, und
hier bricht eine Scheibe mit mehr Treffern laut ab, statt still Nachrichten
zu verlieren.

Zählen und Gruppieren rechnet Graylog selbst: Trefferzahlen über die klassische
Suche mit `limit=1` (`total_results`), Gruppierungen über die Views-API
(`/api/views/search/sync` mit einem Pivot). Die einfachere
`/api/search/aggregate` gibt es erst ab Graylog 5.2. Hier läuft 5.0.
"""
from __future__ import annotations

from datetime import datetime, timezone

import uuid

import httpx

from netguard import guard_egress_url

PAGE = 500
MAX_PAGES = 20
# „All messages“. Ohne Stream-Filter verlangt die klassische Suche eine globale
# Suchberechtigung, die ein Reader nicht hat — mit Filter genügt Lesen auf dem Stream.
DEFAULT_STREAM = "000000000000000000000001"


class GraylogError(Exception):
    pass


class GraylogNotConfigured(GraylogError):
    pass


def fmt_ts(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def base_url(cfg: dict) -> str:
    base = (cfg.get("base_url") or "").strip().rstrip("/")
    if not base:
        raise GraylogNotConfigured("Graylog ist nicht konfiguriert.")
    if base.endswith("/api"):
        base = base[:-4]
    return base


class GraylogClient:
    def __init__(self, transport: httpx.AsyncBaseTransport | None = None) -> None:
        self._transport = transport      # Tests: httpx.MockTransport

    def _client(self, cfg: dict) -> httpx.AsyncClient:
        return httpx.AsyncClient(
            verify=cfg.get("ssl_verify", True),
            timeout=float(cfg.get("timeout_s", 20)),
            auth=(str(cfg.get("token") or ""), "token"),
            headers={"Accept": "application/json", "X-Requested-By": "a38"},
            transport=self._transport,
        )

    async def _get(self, cfg: dict, path: str, params: dict | None = None) -> dict:
        return await self._request(cfg, "GET", path, params=params)

    async def _request(self, cfg: dict, method: str, path: str, params: dict | None = None,
                       body: dict | None = None) -> dict:
        base = base_url(cfg)
        if not cfg.get("token"):
            raise GraylogNotConfigured("Graylog-API-Token fehlt.")
        guard_egress_url(base, "Graylog-URL")
        async with self._client(cfg) as client:
            r = await client.request(method, f"{base}/api/{path}", params=params, json=body)
        if r.status_code == 401:
            raise GraylogError("Graylog lehnt den Token ab (401).")
        if r.status_code == 403:
            where = (f"den Stream {cfg['stream_id']}" if cfg.get("stream_id")
                     else "den Stream „All messages“")
            raise GraylogError(f"Keine Leseberechtigung (403) – in Graylog {where} für den "
                               "API-User freigeben (Share → Viewer).")
        if r.status_code >= 400:
            raise GraylogError(f"Graylog antwortet {r.status_code}: {r.text[:200]}")
        try:
            body = r.json()
        except ValueError as exc:
            raise GraylogError("Antwort von Graylog ist kein JSON.") from exc
        return body if isinstance(body, dict) else {}

    async def search(self, cfg: dict, query: str, frm: datetime, to: datetime) -> list[dict]:
        """Alle Nachrichten im Fenster [frm, to], aufsteigend nach Zeit."""
        out: list[dict] = []
        for page in range(MAX_PAGES):
            params = {"query": query, "from": fmt_ts(frm), "to": fmt_ts(to),
                      "limit": PAGE, "offset": page * PAGE, "sort": "timestamp:asc"}
            params["filter"] = f"streams:{(cfg.get('stream_id') or '').strip() or DEFAULT_STREAM}"
            body = await self._get(cfg, "search/universal/absolute", params)
            msgs = [m.get("message") or {} for m in body.get("messages") or []]
            out.extend(msgs)
            if len(msgs) < PAGE:
                return out
        raise GraylogError(f"Mehr als {PAGE * MAX_PAGES} Nachrichten in einem Zeitfenster – "
                           "die Graylog-Abfrage enger fassen.")

    @staticmethod
    def _stream(cfg: dict) -> str:
        return (cfg.get("stream_id") or "").strip() or DEFAULT_STREAM

    async def count(self, cfg: dict, query: str, frm: datetime, to: datetime) -> int:
        """Trefferzahl im Fenster — ohne eine Nachricht zu übertragen."""
        body = await self._get(cfg, "search/universal/absolute", {
            "query": query or "*", "from": fmt_ts(frm), "to": fmt_ts(to), "limit": 1,
            "filter": f"streams:{self._stream(cfg)}"})
        return int(body.get("total_results") or 0)

    async def sample(self, cfg: dict, query: str, frm: datetime, to: datetime,
                     limit: int = 50) -> list[dict]:
        """Die jüngsten Nachrichten — für Diagnose und Feld-Erkennung."""
        body = await self._get(cfg, "search/universal/absolute", {
            "query": query or "*", "from": fmt_ts(frm), "to": fmt_ts(to),
            "limit": min(limit, PAGE), "sort": "timestamp:desc",
            "filter": f"streams:{self._stream(cfg)}"})
        return [m.get("message") or {} for m in body.get("messages") or []]

    async def streams(self, cfg: dict) -> list[dict]:
        """Die Streams, die der Token lesen darf."""
        body = await self._get(cfg, "streams")
        return [{"id": s.get("id"), "title": s.get("title") or "?",
                 "disabled": bool(s.get("disabled")),
                 "removes_from_default": bool(s.get("remove_matches_from_default_stream"))}
                for s in body.get("streams") or [] if isinstance(s, dict)]

    async def aggregate(self, cfg: dict, query: str, frm: datetime, to: datetime,
                        field: str, limit: int = 20) -> list[tuple[str, int]]:
        """Top-Werte eines Felds mit Anzahl, gerechnet in Graylog (Views-API).

        Ein Pivot mit einer Zeilengruppe und `count()`. Graylog 5.0 nennt das
        Gruppenfeld `field`, ab 5.1 heißt es `fields` (Liste). Beide werden
        mitgeschickt, die jeweils unbekannte Angabe ignoriert Graylog."""
        qid, sid = str(uuid.uuid4()), str(uuid.uuid4())
        body = {
            "queries": [{
                "id": qid,
                "query": {"type": "elasticsearch", "query_string": query or "*"},
                "timerange": {"type": "absolute", "from": fmt_ts(frm), "to": fmt_ts(to)},
                "filter": {"type": "or", "filters": [{"type": "stream",
                                                      "id": self._stream(cfg)}]},
                "search_types": [{
                    "id": sid, "type": "pivot", "rollup": True,
                    "row_groups": [{"type": "values", "field": field, "fields": [field],
                                    "limit": limit}],
                    "column_groups": [],
                    "series": [{"type": "count", "id": "count()"}],
                }],
            }],
            "parameters": [],
        }
        res = await self._request(cfg, "POST", "views/search/sync", body=body,
                                  params={"timeout": 60000})
        q = (res.get("results") or {}).get(qid) or {}
        if q.get("errors"):
            raise GraylogError("Aggregation fehlgeschlagen: " + "; ".join(
                str(e.get("description") or e) for e in q["errors"]))
        rows = ((q.get("search_types") or {}).get(sid) or {}).get("rows") or []
        out = []
        for row in rows:
            if row.get("source") != "leaf" or not row.get("key"):
                continue
            n = next((v.get("value") for v in row.get("values") or []
                      if v.get("key") == ["count()"]), 0)
            out.append((str(row["key"][0]), int(n or 0)))
        return sorted(out, key=lambda kv: -kv[1])

    async def test(self, cfg: dict) -> dict:
        info = await self._get(cfg, "system")
        return {"ok": True, "version": str(info.get("version") or "unbekannt")}
