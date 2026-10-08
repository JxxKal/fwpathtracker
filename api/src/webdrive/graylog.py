"""Graylog-REST-Client (nur lesend): klassische Suche über ein Zeitfenster.

/api/search/universal/absolute gibt es in Graylog 4–6. Der API-Token wird als
Basic Auth übergeben (`<token>:token`). OpenSearch begrenzt offset+limit auf
10.000 (max_result_window) — der Poller fragt deshalb in Zeitscheiben ab, und
hier bricht eine Scheibe mit mehr Treffern laut ab, statt still Nachrichten
zu verlieren.
"""
from __future__ import annotations

from datetime import datetime, timezone

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
        base = base_url(cfg)
        if not cfg.get("token"):
            raise GraylogNotConfigured("Graylog-API-Token fehlt.")
        guard_egress_url(base, "Graylog-URL")
        async with self._client(cfg) as client:
            r = await client.get(f"{base}/api/{path}", params=params)
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

    async def test(self, cfg: dict) -> dict:
        info = await self._get(cfg, "system")
        return {"ok": True, "version": str(info.get("version") or "unbekannt")}
