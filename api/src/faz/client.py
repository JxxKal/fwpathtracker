"""FortiAnalyzer-Client (read-only): Assets aus dem Asset Identity Center.

Die ARP-Historie weiß, wer in einem Netz JE gesprochen hat — bis zu ihrer
Aufbewahrungsfrist, also auch längst abgebaute Geräte. Der FortiAnalyzer
führt im Asset Identity Center (UEBA) die Endpoints, die die Fabric aktuell
sieht: genau die Quelle für „was lebt in diesem Netz".

API: JSON-RPC wie beim FortiManager, Bearer-Token,
    get /ueba/adom/{adom}/endpoints   (apiver 3)
Die Feldnamen des Endpoint-Datensatzes sind nur zum Teil dokumentiert
(epid, epname, epip). MAC und „zuletzt gesehen" werden deshalb unter allen
gängigen Schreibweisen gesucht; der Verbindungstest zeigt die tatsächlich
gelieferten Felder, damit man nachschärfen kann.
"""
from __future__ import annotations

import asyncio
import ipaddress
import logging
import time
from datetime import datetime, timezone
from typing import Any

import httpx
from cachetools import TTLCache

from locate.mac import normalize_mac
from netguard import guard_egress_url

log = logging.getLogger("faz.client")

API_VERSION = 3
DEFAULT_MAX_AGE_DAYS = 7

IP_KEYS = ("epip", "ip", "ipv4", "ip-addr", "ipaddr", "ip_addr")
NAME_KEYS = ("epname", "hostname", "host-name", "host_name", "name")
MAC_KEYS = ("mac", "epmac", "macaddr", "mac-addr", "mac_addr", "mac-address")
SEEN_KEYS = ("lastseen", "last-seen", "last_seen", "lastactive", "last-active",
             "lastupdate", "last-update", "updatetime", "update-time")
OS_KEYS = ("os", "osname", "os-name", "ostype")


# Logsuche: je Abruf höchstens LOG_PAGE Zeilen (FAZ-Obergrenze), insgesamt
# LOG_LIMIT — mehr braucht keine Auswertung, und mehr hält der FAZ nicht gern aus.
LOG_PAGE = 1000
LOG_LIMIT = 5000
SEARCH_TIMEOUT_S = 45
POLL_S = 1.0


class FazNotConfigured(Exception):
    pass


class FazError(Exception):
    pass


def _first(rec: dict, keys: tuple[str, ...]) -> Any:
    for k in keys:
        v = rec.get(k)
        if v not in (None, "", [], "N/A", "n/a"):
            return v
    return None


def _ipv4s(value: Any) -> list[str]:
    """epip kommt als String, Liste oder kommagetrennt — nur gültige IPv4."""
    if value is None:
        return []
    items = value if isinstance(value, list) else str(value).replace(";", ",").split(",")
    out = []
    for item in items:
        if isinstance(item, dict):
            item = _first(item, IP_KEYS)
        try:
            ip = ipaddress.IPv4Address(str(item).strip())
        except (ipaddress.AddressValueError, ValueError):
            continue
        if not (ip.is_unspecified or ip.is_loopback):
            out.append(str(ip))
    return out


def _timestamp(value: Any) -> datetime | None:
    """Epoch-Sekunden oder 'YYYY-MM-DD HH:MM:SS' (FAZ-Zeit, als UTC gelesen)."""
    if value is None:
        return None
    try:
        n = float(value)
        if n > 1e12:            # Millisekunden
            n /= 1000
        return datetime.fromtimestamp(n, tz=timezone.utc) if n > 0 else None
    except (TypeError, ValueError):
        pass
    try:
        ts = datetime.fromisoformat(str(value).strip().replace(" ", "T"))
    except ValueError:
        return None
    return ts if ts.tzinfo else ts.replace(tzinfo=timezone.utc)


def _records(data: Any) -> list[dict]:
    if isinstance(data, list):
        return [r for r in data if isinstance(r, dict)]
    if isinstance(data, dict):
        for k in ("data", "endpoints", "items"):
            if k in data:
                return _records(data[k])
    return []


def _tid(res: Any) -> int | None:
    for src in (res, res.get("data") if isinstance(res, dict) else None):
        if isinstance(src, dict) and src.get("tid") not in (None, ""):
            try:
                return int(src["tid"])
            except (TypeError, ValueError):
                return None
    return None


def _percentage(res: Any) -> int:
    """Fortschritt der Suche — je nach FAZ-Version neben oder in 'data'."""
    for src in (res, res.get("data") if isinstance(res, dict) else None):
        if isinstance(src, dict):
            for k in ("percentage", "percentage-done", "progress"):
                if src.get(k) is not None:
                    try:
                        return int(float(src[k]))
                    except (TypeError, ValueError):
                        pass
    return 0


def _total(res: Any) -> int | None:
    for src in (res, res.get("data") if isinstance(res, dict) else None):
        if isinstance(src, dict):
            for k in ("total-count", "total_lines", "total-lines", "total"):
                if isinstance(src.get(k), int):
                    return src[k]
    return None


def _log_rows(res: Any) -> list[dict]:
    if not isinstance(res, dict):
        return []
    data = res.get("data")
    if isinstance(data, list):
        return [r for r in data if isinstance(r, dict)]
    if isinstance(data, dict):
        for k in ("logs", "data"):
            if isinstance(data.get(k), list):
                return [r for r in data[k] if isinstance(r, dict)]
    return []


def normalize(rec: dict, now: datetime | None = None) -> list[dict]:
    """Ein Endpoint-Datensatz → ein Host je IPv4-Adresse."""
    now = now or datetime.now(timezone.utc)
    seen = _timestamp(_first(rec, SEEN_KEYS))
    name = _first(rec, NAME_KEYS)
    mac = _first(rec, MAC_KEYS)
    base = {
        "name": str(name).strip() if name else None,
        "mac": normalize_mac(str(mac)) if mac else None,
        "last_seen": seen.isoformat() if seen else None,
        "age_s": max(0, int((now - seen).total_seconds())) if seen else None,
        "os": _first(rec, OS_KEYS),
        "epid": rec.get("epid"),
    }
    return [dict(base, ip=ip) for ip in _ipv4s(_first(rec, IP_KEYS))]


class FazSource:
    """Endpoints je Konfiguration, kurz gecacht — ein Netzplan fragt sie für
    jedes Netz ab, der FAZ soll aber nur einmal pro Zeichnung gefragt werden."""

    def __init__(self, ttl_s: int = 300,
                 transport: httpx.AsyncBaseTransport | None = None) -> None:
        self._cache: TTLCache = TTLCache(maxsize=4, ttl=ttl_s)
        self._log_cache: TTLCache = TTLCache(maxsize=64, ttl=60)
        self._transport = transport

    def invalidate(self) -> None:
        self._cache.clear()
        self._log_cache.clear()

    @staticmethod
    def configured(cfg: dict) -> bool:
        return bool((cfg.get("base_url") or "").strip() and cfg.get("token"))

    async def _rpc(self, cfg: dict, url: str, method: str = "get", whole: bool = False,
                   **params: Any) -> Any:
        base = (cfg.get("base_url") or "").strip().rstrip("/")
        if not base:
            raise FazNotConfigured("FortiAnalyzer ist nicht konfiguriert.")
        if not cfg.get("token"):
            raise FazNotConfigured("FortiAnalyzer-API-Token fehlt.")
        guard_egress_url(base, "FortiAnalyzer-URL")
        payload = {"id": 1, "jsonrpc": "2.0", "method": method,
                   "params": [{"url": url, **params}]}
        async with httpx.AsyncClient(
                verify=cfg.get("ssl_verify", True), timeout=float(cfg.get("timeout_s", 30)),
                headers={"Authorization": f"Bearer {cfg['token']}"},
                transport=self._transport) as client:
            r = await client.post(f"{base}/jsonrpc", json=payload)
        if r.status_code in (401, 403):
            raise FazError("FortiAnalyzer lehnt den Token ab (401/403).")
        r.raise_for_status()
        try:
            body = r.json()
        except ValueError as exc:
            raise FazError("Antwort des FortiAnalyzer ist kein JSON.") from exc
        result = body.get("result") if isinstance(body, dict) else None
        if isinstance(result, list):
            result = result[0] if result else {}
        if not isinstance(result, dict):
            raise FazError(f"Unerwartete Antwort: {str(body)[:200]}")
        status = result.get("status") or {}
        if isinstance(status, dict) and status.get("code") not in (None, 0):
            raise FazError(f"FortiAnalyzer: {status.get('message') or status.get('code')}"
                           f" ({url})")
        # Die Logsuche braucht die ganze Antwort: Fortschritt und Zeilenzahl
        # stehen neben den Daten, nicht in ihnen.
        return result if whole else result.get("data", result)

    async def _raw_endpoints(self, cfg: dict) -> list[dict]:
        adom = (cfg.get("adom") or "root").strip()
        data = await self._rpc(cfg, f"/ueba/adom/{adom}/endpoints",
                               apiver=API_VERSION, **{"detail-level": "standard"})
        return _records(data)

    async def endpoints(self, cfg: dict) -> list[dict]:
        """Alle Endpoints mit IPv4, die jünger als max_age_days sind.
        Ohne Zeitstempel im Datensatz bleibt ein Endpoint drin — der FAZ führt
        ihn ja als aktuell."""
        key = (cfg.get("base_url"), cfg.get("adom"), cfg.get("max_age_days"))
        if key in self._cache:
            return self._cache[key]
        max_age = int(cfg.get("max_age_days", DEFAULT_MAX_AGE_DAYS) or 0) * 86400
        now = datetime.now(timezone.utc)
        out = [h for rec in await self._raw_endpoints(cfg) for h in normalize(rec, now)
               if not (max_age and h["age_s"] is not None and h["age_s"] > max_age)]
        self._cache[key] = out
        return out

    async def by_ip(self, cfg: dict, ip: str) -> dict | None:
        """Jüngster Endpoint mit dieser IP und einer MAC."""
        hits = [h for h in await self.endpoints(cfg) if h["ip"] == ip and h.get("mac")]
        return min(hits, key=lambda h: h["age_s"] if h["age_s"] is not None else 1 << 62,
                   default=None)

    async def logsearch(self, cfg: dict, *, logtype: str, filter: str,
                        start: str, end: str, limit: int = LOG_LIMIT) -> dict:
        """Asynchrone Logsuche: Aufgabe anlegen, auf 100 % warten, seitenweise
        abholen, Aufgabe wieder löschen. Rückgabe {logs, complete, total}.

        complete=False heißt: Zeitüberschreitung — die Zeilen sind dann nur ein
        Teil. time-order desc sorgt dafür, dass es wenigstens die jüngsten sind.
        Ergebnisse werden eine Minute gehalten, weil dieselbe Frage beim
        Durchklicken gern zweimal kommt.
        """
        key = ("log", cfg.get("base_url"), cfg.get("adom"), logtype, filter, start, end, limit)
        if key in self._log_cache:
            return self._log_cache[key]
        adom = (cfg.get("adom") or "root").strip()
        base_url = f"/logview/adom/{adom}/logsearch"
        added = await self._rpc(
            cfg, base_url, method="add", whole=True, apiver=API_VERSION,
            logtype=logtype, filter=filter, device=[{"devid": "All_FortiGate"}],
            **{"time-range": {"start": start, "end": end}, "time-order": "desc",
               "case-sensitive": False})
        tid = _tid(added)
        if tid is None:
            raise FazError(f"Logsuche ohne Task-ID beantwortet: {str(added)[:200]}")
        url = f"{base_url}/{tid}"
        deadline = time.monotonic() + float(cfg.get("search_timeout_s", SEARCH_TIMEOUT_S))
        logs: list[dict] = []
        complete, total = False, None
        try:
            while True:
                res = await self._rpc(cfg, url, whole=True, apiver=API_VERSION,
                                      limit=LOG_PAGE, offset=0)
                pct = _percentage(res)
                if pct >= 100:
                    complete = True
                    break
                if time.monotonic() >= deadline:
                    break
                await asyncio.sleep(POLL_S)
            total = _total(res)
            logs = _log_rows(res)
            while len(logs) < limit and len(_log_rows(res)) == LOG_PAGE:
                res = await self._rpc(cfg, url, whole=True, apiver=API_VERSION,
                                      limit=LOG_PAGE, offset=len(logs))
                logs.extend(_log_rows(res))
        finally:
            try:
                await self._rpc(cfg, url, method="delete", whole=True, apiver=API_VERSION)
            except Exception as exc:     # aufräumen ist Kür, nicht Pflicht
                log.debug("Logsuche %s nicht gelöscht: %s", tid, exc)
        out = {"logs": logs[:limit], "complete": complete,
               "total": total if total is not None else len(logs)}
        if complete:
            self._log_cache[key] = out
        return out

    async def test(self, cfg: dict) -> dict:
        """Verbindungstest: Anzahl und die Feldnamen, die der FAZ wirklich liefert."""
        recs = await self._raw_endpoints(cfg)
        hosts = [h for r in recs for h in normalize(r)]
        fields = sorted({k for r in recs[:50] for k in r})
        return {"ok": True, "endpoints": len(recs), "hosts": len(hosts),
                "with_mac": sum(1 for h in hosts if h["mac"]),
                "with_last_seen": sum(1 for h in hosts if h["last_seen"]),
                "fields": fields}


def in_network(hosts: list[dict], cidr: str) -> list[dict]:
    net = ipaddress.IPv4Network(cidr, strict=False)
    return [h for h in hosts if ipaddress.IPv4Address(h["ip"]) in net]
