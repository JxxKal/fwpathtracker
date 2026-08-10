"""LibreNMS-API-Client (read-only) mit TTL-Caches.

LibreNMS liefert zwei Dinge, die der FortiManager nicht weiß: die
Forwarding-Database der Switches (MAC → Switchport) und — an den Standorten,
wo ein L3-Switch statt der FortiGate routet — die ARP-Tabelle.

Zugriff ausschließlich lesend über die v0-API mit `X-Auth-Token`. Kein
DB-Zugriff: der Tracker bekommt einen normalen LibreNMS-Token und nicht mehr.

Gecacht wird alles, was sich seltener ändert als eine Suche dauert:
`/resources/links` (LLDP/CDP-Nachbarn), Geräte-Stammdaten und Portlisten.
Ohne Cache wäre jede Suche ein Vielfaches an Requests gegen eine Appliance,
die nebenher pollt und discovert.
"""
from __future__ import annotations

import logging
from typing import Any

import httpx
from cachetools import TTLCache

from netguard import guard_egress_url

log = logging.getLogger("librenms.client")

API_PREFIX = "/api/v0"


class LibrenmsError(RuntimeError):
    """LibreNMS antwortet, aber nicht mit dem, was wir wollten."""


class LibrenmsNotConfigured(LibrenmsError):
    """Kein base_url/token hinterlegt — Aufrufer soll die Quelle überspringen."""


def _rows(body: Any, *keys: str) -> list[dict]:
    """Listen-Nutzlast aus einem LibreNMS-Envelope holen.

    Die API benennt das Nutzlast-Feld je Endpunkt anders (`arp`, `ports_fdb`,
    `links`, `devices`, `ports`, …) und die Namen haben sich über Versionen
    hinweg schon verschoben. Erst die bekannten Namen probieren, sonst die
    erste Liste im Objekt nehmen — das ist robuster als eine feste Annahme.
    """
    if not isinstance(body, dict):
        return []
    for k in keys:
        val = body.get(k)
        if isinstance(val, list):
            return [r for r in val if isinstance(r, dict)]
    for k, val in body.items():
        if k in ("status", "message", "count"):
            continue
        if isinstance(val, list):
            return [r for r in val if isinstance(r, dict)]
    return []


class LibrenmsClient:
    """Ein Exemplar pro App (hält die Caches); jede Methode bekommt die Config."""

    def __init__(self, ttl_s: int = 900, fdb_ttl_s: int = 300) -> None:
        self._links: TTLCache = TTLCache(maxsize=4, ttl=ttl_s)
        self._devices: TTLCache = TTLCache(maxsize=2048, ttl=ttl_s)
        self._ports: TTLCache = TTLCache(maxsize=2048, ttl=ttl_s)
        self._port_by_id: TTLCache = TTLCache(maxsize=2048, ttl=ttl_s)
        # Kürzer: Basis der MAC-Zählung je Port, ändert sich mit jeder Discovery.
        self._device_fdb: TTLCache = TTLCache(maxsize=512, ttl=fdb_ttl_s)

    # ── HTTP ────────────────────────────────────────────────────────────────

    @staticmethod
    def _base(cfg: dict) -> str:
        base = (cfg.get("base_url") or "").strip()
        if not base:
            raise LibrenmsNotConfigured("LibreNMS ist nicht konfiguriert.")
        if not cfg.get("token"):
            raise LibrenmsNotConfigured("LibreNMS-Token fehlt.")
        return base.rstrip("/")

    @staticmethod
    def _client(cfg: dict) -> httpx.AsyncClient:
        return httpx.AsyncClient(
            verify=cfg.get("ssl_verify", True),
            timeout=float(cfg.get("timeout_s", 20)),
            headers={"X-Auth-Token": str(cfg.get("token") or "")},
        )

    async def _get(self, cfg: dict, path: str, params: dict | None = None) -> dict:
        """GET auf die v0-API. 404 ist bei LibreNMS 'nichts gefunden', kein Fehler."""
        base = self._base(cfg)
        guard_egress_url(base, "LibreNMS-URL")
        url = f"{base}{API_PREFIX}/{path.lstrip('/')}"
        async with self._client(cfg) as client:
            r = await client.get(url, params=params)
        if r.status_code == 404:
            return {}
        if r.status_code in (401, 403):
            raise LibrenmsError("LibreNMS lehnt den Token ab (401/403).")
        r.raise_for_status()
        try:
            body = r.json()
        except ValueError as exc:
            raise LibrenmsError(f"Antwort ist kein JSON ({url}).") from exc
        if isinstance(body, dict) and body.get("status") == "error":
            raise LibrenmsError(str(body.get("message") or "Unbekannter LibreNMS-Fehler"))
        return body if isinstance(body, dict) else {}

    def invalidate(self) -> None:
        """Alle Caches leeren (Settings-Panel: 'Cache aktualisieren')."""
        for cache in (self._links, self._devices, self._ports,
                      self._port_by_id, self._device_fdb):
            cache.clear()

    # ── Endpunkte ───────────────────────────────────────────────────────────

    async def arp(self, cfg: dict, query: str) -> list[dict]:
        """/resources/ip/arp/:query — query ist IP, MAC oder CIDR."""
        body = await self._get(cfg, f"resources/ip/arp/{query}")
        return _rows(body, "arp")

    async def fdb(self, cfg: dict, mac: str) -> list[dict]:
        """/resources/fdb/:mac — port_id, device_id, vlan_id, updated_at.

        Bewusst nicht /detail: die Detail-Variante verknüpft intern mit der
        VLAN-Tabelle, und Geräte ohne VLAN-Zuordnung in der FDB (MOXA schreibt
        vlan_id 0, siehe docs/wiki/LibreNMS-MOXA-FDB.md) können dort
        herausfallen. Namen holen wir uns separat über die Portliste.
        """
        body = await self._get(cfg, f"resources/fdb/{mac}")
        return _rows(body, "ports_fdb", "fdb")

    async def device_fdb(self, cfg: dict, device_id: int | str) -> list[dict]:
        """/devices/:id/fdb — Basis für 'wie viele MACs hängen an dem Port'."""
        key = str(device_id)
        cached = self._device_fdb.get(key)
        if cached is not None:
            return cached
        body = await self._get(cfg, f"devices/{device_id}/fdb")
        rows = _rows(body, "ports_fdb", "fdb")
        self._device_fdb[key] = rows
        return rows

    async def device(self, cfg: dict, device_id: int | str) -> dict:
        key = str(device_id)
        cached = self._devices.get(key)
        if cached is not None:
            return cached
        body = await self._get(cfg, f"devices/{device_id}")
        rows = _rows(body, "devices")
        dev = rows[0] if rows else {}
        self._devices[key] = dev
        return dev

    async def device_ports(self, cfg: dict, device_id: int | str) -> list[dict]:
        key = str(device_id)
        cached = self._ports.get(key)
        if cached is not None:
            return cached
        body = await self._get(
            cfg, f"devices/{device_id}/ports",
            {"columns": "port_id,ifIndex,ifName,ifDescr,ifAlias,ifOperStatus,ifAdminStatus"},
        )
        rows = _rows(body, "ports")
        self._ports[key] = rows
        return rows

    async def port(self, cfg: dict, port_id: int | str) -> dict:
        """/ports/:id — nur für Provenance (an welchem Gerät hängt ein ARP-Eintrag)."""
        key = str(port_id)
        cached = self._port_by_id.get(key)
        if cached is not None:
            return cached
        body = await self._get(cfg, f"ports/{port_id}")
        rows = _rows(body, "port", "ports")
        p = rows[0] if rows else {}
        self._port_by_id[key] = p
        return p

    async def links(self, cfg: dict) -> list[dict]:
        """/resources/links — LLDP/CDP-Nachbarn, einmal für die ganze Installation."""
        cached = self._links.get("all")
        if cached is not None:
            return cached
        body = await self._get(cfg, "resources/links")
        rows = _rows(body, "links")
        self._links["all"] = rows
        return rows

    async def neighbours(self, cfg: dict) -> dict[int, str]:
        """port_id → lesbarer Nachbar. Ein Port mit Nachbar ist ein Uplink."""
        out: dict[int, str] = {}
        for link in await self.links(cfg):
            pid = link.get("local_port_id")
            if pid in (None, 0):
                continue
            remote = str(link.get("remote_hostname") or "").strip()
            rport = str(link.get("remote_port") or "").strip()
            label = " / ".join(p for p in (remote, rport) if p) or "unbekannt"
            try:
                out[int(pid)] = label
            except (TypeError, ValueError):
                continue
        return out

    async def test(self, cfg: dict) -> dict:
        """Verbindungstest fürs Settings-Panel: Version + Gerätezahl."""
        body = await self._get(cfg, "system")
        sysrows = _rows(body, "system")
        info = sysrows[0] if sysrows else {}
        devices = await self._get(cfg, "devices")
        return {
            "ok": True,
            "version": str(info.get("local_ver") or info.get("local_branch") or "unbekannt"),
            "db_schema": info.get("db_schema"),
            "devices": int(devices.get("count") or len(_rows(devices, "devices"))),
        }
