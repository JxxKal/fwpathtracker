"""Zabbix-API-Client (read-only, JSON-RPC) mit TTL-Caches.

Zabbix weiß, was keine andere Quelle des Trackers weiß: ob ein Host gerade
läuft. Topologie und Stammdaten kommen weiter aus FMG, LibreNMS und iTop —
von Zabbix brauchen wir nur Hosts (mit Interface-IPs zum Zuordnen) und die
aktiven Probleme.

Ab Zabbix 7 geht das API-Token als `Authorization: Bearer` mit; der User
dahinter braucht nur Leserechte auf die Host-Gruppen. `apiinfo.version` muss
OHNE Token aufgerufen werden — Zabbix lehnt es sonst ab.
"""
from __future__ import annotations

import logging
from typing import Any

import httpx
from cachetools import TTLCache

from netguard import guard_egress_url

log = logging.getLogger("zabbix.client")

API_PATH = "/api_jsonrpc.php"


class ZabbixError(RuntimeError):
    """Zabbix antwortet, aber mit einem Fehler."""


class ZabbixNotConfigured(ZabbixError):
    """Kein base_url/token hinterlegt — Aufrufer soll die Quelle überspringen."""


class ZabbixClient:
    """Ein Exemplar pro App (hält die Caches); jede Methode bekommt die Config."""

    def __init__(self, ttl_s: int = 600, problem_ttl_s: int = 60) -> None:
        self._hosts: TTLCache = TTLCache(maxsize=4, ttl=ttl_s)
        # Probleme kommen und gehen — kurz cachen, nur gegen Doppelabrufe
        # innerhalb einer Zeichnung und schnell hintereinander erzeugte Pläne.
        self._problems: TTLCache = TTLCache(maxsize=4, ttl=problem_ttl_s)

    @staticmethod
    def _url(cfg: dict) -> str:
        base = (cfg.get("base_url") or "").strip().rstrip("/")
        if not base:
            raise ZabbixNotConfigured("Zabbix ist nicht konfiguriert.")
        if not cfg.get("token"):
            raise ZabbixNotConfigured("Zabbix-API-Token fehlt.")
        if base.endswith(API_PATH):
            base = base[: -len(API_PATH)]
        return base + API_PATH

    async def _call(self, cfg: dict, method: str, params: Any, auth: bool = True) -> Any:
        url = self._url(cfg)
        guard_egress_url(url, "Zabbix-URL")
        headers = {"Content-Type": "application/json-rpc"}
        if auth:
            headers["Authorization"] = f"Bearer {cfg.get('token')}"
        async with httpx.AsyncClient(verify=cfg.get("ssl_verify", True),
                                     timeout=float(cfg.get("timeout_s", 20))) as client:
            r = await client.post(url, headers=headers, json={
                "jsonrpc": "2.0", "method": method, "params": params, "id": 1})
        if r.status_code in (401, 403):
            raise ZabbixError("Zabbix lehnt den Token ab (401/403).")
        r.raise_for_status()
        try:
            body = r.json()
        except ValueError as exc:
            raise ZabbixError(f"Antwort ist kein JSON ({url}).") from exc
        if not isinstance(body, dict):
            raise ZabbixError("Unerwartete Antwort von Zabbix.")
        if body.get("error"):
            err = body["error"]
            raise ZabbixError(" — ".join(str(p) for p in (err.get("message"), err.get("data"))
                                         if p))
        return body.get("result")

    def invalidate(self) -> None:
        self._hosts.clear()
        self._problems.clear()

    def _groups(self, cfg: dict) -> dict:
        """Optionaler Filter auf Host-Gruppen (IDs) — sonst alles, was der User sieht."""
        ids = [str(g).strip() for g in (cfg.get("groupids") or []) if str(g).strip()]
        return {"groupids": ids} if ids else {}

    async def hosts(self, cfg: dict) -> list[dict]:
        """Alle sichtbaren Hosts mit Interfaces, Status und Wartung."""
        cached = self._hosts.get("all")
        if cached is not None:
            return cached
        rows = await self._call(cfg, "host.get", {
            "output": ["hostid", "host", "name", "status", "maintenance_status"],
            "selectInterfaces": ["ip", "dns", "useip", "available", "type", "main", "error"],
            **self._groups(cfg),
        }) or []
        self._hosts["all"] = rows
        return rows

    async def problems(self, cfg: dict) -> list[dict]:
        """Aktive Probleme als Trigger im Zustand PROBLEM.

        `trigger.get` statt `problem.get`, weil nur Trigger ihre Hosts
        mitliefern. `skipDependent` blendet Folgeprobleme aus — hängt ein
        Switch, soll nicht jeder Host dahinter zusätzlich rot sein, nur weil
        sein Agent nicht antwortet."""
        cached = self._problems.get("all")
        if cached is not None:
            return cached
        rows = await self._call(cfg, "trigger.get", {
            "output": ["triggerid", "description", "priority", "lastchange"],
            "filter": {"value": 1},
            "monitored": True,
            "skipDependent": True,
            "expandDescription": True,
            "selectHosts": ["hostid"],
            "selectLastEvent": ["acknowledged", "suppressed"],
            **self._groups(cfg),
        }) or []
        self._problems["all"] = rows
        return rows

    async def test(self, cfg: dict) -> dict:
        """Verbindungstest fürs Settings-Panel: Version, Hosts, aktive Probleme."""
        self._url(cfg)
        version = await self._call(cfg, "apiinfo.version", [], auth=False)
        self.invalidate()
        hosts = await self.hosts(cfg)
        problems = await self.problems(cfg)
        # Welche Host-Gruppen sieht der User? Zabbix verschweigt Hosts ohne
        # Leserecht kommentarlos — die Liste zeigt, wo Rechte fehlen.
        groups = await self._call(cfg, "hostgroup.get", {
            "output": ["groupid", "name"], "selectHosts": "count", **self._groups(cfg)}) or []
        return {"ok": True, "version": str(version or "unbekannt"), "hosts": len(hosts),
                "problems": len(problems), "filtered": bool(self._groups(cfg)),
                "groups": sorted(({"id": str(g.get("groupid")), "name": g.get("name") or "?",
                                   "hosts": int(g.get("hosts") or 0)} for g in groups),
                                 key=lambda g: (-g["hosts"], g["name"]))}
