"""Resolver-Quelle 2: iTop-CMDB (core/get, portiert aus ids itop.py).

Server/NetworkDevice mit TeemIPs managementip_id_friendlyname. Der Host-
Index für Autocomplete wird lazy geladen und TTL-gecacht.
"""
from __future__ import annotations

import json
import logging
import time

import httpx

from netguard import guard_egress_url

log = logging.getLogger("resolver.itop")

_CI_CLASSES: dict[str, str] = {
    "Server": "name,managementip_id_friendlyname,description",
    "NetworkDevice": "name,managementip_id_friendlyname,description",
}


def _oql_str(s: str) -> str:
    """OQL-String-Literal escapen (verhindert OQL-Injection über org-Filter)."""
    return s.replace("\\", "\\\\").replace("'", "\\'")


async def _core_get(client: httpx.AsyncClient, base_url: str, user: str, pwd: str,
                    cls: str, fields: str, oql: str | None = None) -> list[dict]:
    query = oql or f"SELECT {cls}"
    payload = json.dumps({
        "operation": "core/get",
        "class": cls,
        "key": query,
        "output_fields": fields,
    })
    r = await client.post(
        f"{base_url.rstrip('/')}/webservices/rest.php",
        data={"version": "1.3", "auth_user": user, "auth_pwd": pwd, "json_data": payload},
    )
    r.raise_for_status()
    body = r.json()
    if body.get("code", 0) != 0:
        raise RuntimeError(f"iTop-Fehler ({cls}): {body.get('message', body)}")
    out: list[dict] = []
    for obj in (body.get("objects") or {}).values():
        if obj.get("code", 0) != 0:
            continue
        fields = dict(obj.get("fields") or {})
        fields.setdefault("_key", obj.get("key"))   # iTop-Objekt-ID (z.B. subnet_id-Bezug)
        out.append(fields)
    return out


class ItopSource:
    def __init__(self) -> None:
        self._hosts: list[dict] = []   # {name, ip, description}
        self._loaded_at: float = 0.0
        self._ttl_s = 900
        self._ipam: dict | None = None  # {subnets, ranges, loaded_at} — Bereichsbaum
        self._ipam_ttl_s = 300

    @staticmethod
    def _client(cfg: dict) -> httpx.AsyncClient:
        # TLS-Verifikation default AN (ids-Muster)
        return httpx.AsyncClient(verify=cfg.get("ssl_verify", True), timeout=30)

    async def _index(self, cfg: dict) -> list[dict]:
        if not cfg.get("base_url") or not cfg.get("enabled", True):
            return []
        if self._hosts and time.monotonic() - self._loaded_at < self._ttl_s:
            return self._hosts
        guard_egress_url(cfg["base_url"], "iTop-URL")
        org = (cfg.get("org_filter") or "").strip()
        hosts: list[dict] = []
        async with self._client(cfg) as client:
            for cls, fields in _CI_CLASSES.items():
                oql = f"SELECT {cls} WHERE org_name = '{_oql_str(org)}'" if org else None
                try:
                    cis = await _core_get(client, cfg["base_url"], cfg["user"],
                                          cfg["password"], cls, fields, oql)
                except Exception as exc:
                    log.warning("iTop %s: %s – übersprungen.", cls, exc)
                    continue
                for ci in cis:
                    ip_raw = (ci.get("managementip_id_friendlyname") or "").strip()
                    name = (ci.get("name") or "").strip()
                    if not name or not ip_raw or ip_raw in ("0.0.0.0", ""):
                        continue
                    hosts.append({"name": name, "ip": ip_raw.split("/")[0],
                                  "description": (ci.get("description") or "").strip()})
        self._hosts = hosts
        self._loaded_at = time.monotonic()
        return hosts

    async def refresh(self, cfg: dict) -> int:
        """Host-Index sofort neu laden (Cache invalidieren) — für den manuellen
        Refresh-Button und den täglichen Auto-Refresh. Gibt die Anzahl Hosts zurück.
        """
        self._loaded_at = 0.0
        self._ipam = None
        return len(await self._index(cfg))

    async def hosts(self, cfg: dict) -> list[dict]:
        """Host-Index (Server/NetworkDevice mit Management-IP) — TTL-gecacht."""
        return await self._index(cfg)

    async def subnets(self, cfg: dict) -> list[dict]:
        """IPv4-Subnetze aus iTop (IPAM/TeemIP) — für den Free-Subnet-Finder.
        Klasse/Felder konfigurierbar (Default TeemIP): subnet_class=IPv4Subnet,
        subnet_ip_field=ip, subnet_mask_field=mask. Rückgabe: [{cidr, name}].
        """
        import ipaddress
        if not cfg.get("base_url") or not cfg.get("enabled", True):
            return []
        guard_egress_url(cfg["base_url"], "iTop-URL")
        cls = cfg.get("subnet_class") or "IPv4Subnet"
        ipf = cfg.get("subnet_ip_field") or "ip"
        maskf = cfg.get("subnet_mask_field") or "mask"
        org = (cfg.get("org_filter") or "").strip()
        oql = (f"SELECT {cls} WHERE org_name = '{_oql_str(org)}'" if org else f"SELECT {cls}")
        async with self._client(cfg) as client:
            rows = await _core_get(client, cfg["base_url"], cfg["user"], cfg["password"],
                                   cls, f"{ipf},{maskf},name", oql)
        out: list[dict] = []
        for r in rows:
            ipv = str(r.get(ipf) or "").strip()
            mv = str(r.get(maskf) or "").strip()
            if not ipv or not mv:
                continue
            try:
                net = ipaddress.IPv4Network(f"{ipv}/{mv}", strict=False)
            except ValueError:
                continue
            out.append({"cidr": str(net), "name": str(r.get("name") or "").strip()})
        return out

    async def ipam(self, cfg: dict) -> dict:
        """Subnetze + Ranges für den Bereichsbaum (TTL-gecacht, 5 min).

        subnets: [{id, cidr, name, gateway}] — wie subnets(), plus Objekt-ID und
        Gateway. ranges: [{subnet_id, first, last, name, dhcp}] aus IPv4Range;
        die Klasse ist TeemIP-Standard — fehlt sie, gibt es eben keine Ranges,
        der Rest funktioniert weiter.
        """
        import ipaddress
        if self._ipam and time.monotonic() - self._ipam["loaded_at"] < self._ipam_ttl_s:
            return self._ipam
        if not cfg.get("base_url") or not cfg.get("enabled", True):
            return {"subnets": [], "ranges": [], "loaded_at": time.monotonic()}
        guard_egress_url(cfg["base_url"], "iTop-URL")
        cls = cfg.get("subnet_class") or "IPv4Subnet"
        ipf = cfg.get("subnet_ip_field") or "ip"
        maskf = cfg.get("subnet_mask_field") or "mask"
        org = (cfg.get("org_filter") or "").strip()
        where = f" WHERE org_name = '{_oql_str(org)}'" if org else ""
        subnets: list[dict] = []
        ranges: list[dict] = []
        async with self._client(cfg) as client:
            # gatewayip ist TeemIP-Standard; bei angepasster Subnetz-Klasse
            # ohne das Feld schlägt der erste Versuch fehl → ohne Gateway laden.
            try:
                rows = await _core_get(client, cfg["base_url"], cfg["user"], cfg["password"],
                                       cls, f"{ipf},{maskf},name,gatewayip", f"SELECT {cls}{where}")
            except Exception:
                rows = await _core_get(client, cfg["base_url"], cfg["user"], cfg["password"],
                                       cls, f"{ipf},{maskf},name", f"SELECT {cls}{where}")
            for r in rows:
                ipv, mv = str(r.get(ipf) or "").strip(), str(r.get(maskf) or "").strip()
                if not ipv or not mv:
                    continue
                try:
                    net = ipaddress.IPv4Network(f"{ipv}/{mv}", strict=False)
                except ValueError:
                    continue
                gw = str(r.get("gatewayip") or "").strip() or None
                subnets.append({"id": str(r.get("_key")), "cidr": str(net),
                                "name": str(r.get("name") or "").strip(), "gateway": gw})
            try:
                rrows = await _core_get(client, cfg["base_url"], cfg["user"], cfg["password"],
                                        "IPv4Range", "subnet_id,firstip,lastip,range,dhcp",
                                        f"SELECT IPv4Range{where}")
            except Exception as exc:
                log.info("iTop IPv4Range nicht ladbar (%s) — Baum ohne Ranges.", exc)
                rrows = []
            for r in rrows:
                try:
                    lo = ipaddress.IPv4Address(str(r.get("firstip") or "").strip())
                    hi = ipaddress.IPv4Address(str(r.get("lastip") or "").strip())
                except ValueError:
                    continue
                ranges.append({"subnet_id": str(r.get("subnet_id")), "first": str(lo),
                               "last": str(hi), "name": str(r.get("range") or "").strip(),
                               "dhcp": str(r.get("dhcp") or "").lower() in ("yes", "1", "true")})
        self._ipam = {"subnets": subnets, "ranges": ranges, "loaded_at": time.monotonic()}
        return self._ipam

    async def addresses(self, cfg: dict, subnet_ids: list[str]) -> dict[str, dict]:
        """IPv4Address-Objekte der Subnetze — immer frisch, denn genau hier
        trägt jemand kurz vorher eine Reservierung ein und sucht dann weiter.
        Rückgabe ip → {status, name}; name = short_name oder fqdn."""
        ids = [i for i in subnet_ids if i and i.isdigit()]
        if not ids or not cfg.get("base_url") or not cfg.get("enabled", True):
            return {}
        guard_egress_url(cfg["base_url"], "iTop-URL")
        oql = f"SELECT IPv4Address WHERE subnet_id IN ({','.join(ids)})"
        async with self._client(cfg) as client:
            rows = await _core_get(client, cfg["base_url"], cfg["user"], cfg["password"],
                                   "IPv4Address", "ip,status,short_name,fqdn", oql)
        out: dict[str, dict] = {}
        for r in rows:
            ip = str(r.get("ip") or "").strip()
            if not ip:
                continue
            name = str(r.get("fqdn") or r.get("short_name") or "").strip()
            out[ip] = {"status": str(r.get("status") or "").strip().lower(), "name": name}
        return out

    async def resolve_name(self, cfg: dict, name: str) -> dict | None:
        needle = name.strip().lower()
        for h in await self._index(cfg):
            if h["name"].lower() == needle:
                return {"ip": h["ip"], "name": h["name"], "provenance": "itop"}
        return None

    async def resolve_ip(self, cfg: dict, ip: str) -> dict | None:
        for h in await self._index(cfg):
            if h["ip"] == ip:
                return {"name": h["name"], "provenance": "itop"}
        return None

    async def search(self, cfg: dict, q: str, limit: int = 10) -> list[dict]:
        needle = q.strip().lower()
        out = []
        for h in await self._index(cfg):
            if needle in h["name"].lower() or needle in h["ip"]:
                out.append({"name": h["name"], "ip": h["ip"], "provenance": "itop"})
                if len(out) >= limit:
                    break
        return out

    async def test(self, cfg: dict) -> dict:
        guard_egress_url(cfg.get("base_url") or "", "iTop-URL")
        payload = json.dumps({"operation": "core/get", "class": "Organization",
                              "key": "SELECT Organization", "output_fields": "name"})
        async with self._client(cfg) as client:
            r = await client.post(
                f"{cfg['base_url'].rstrip('/')}/webservices/rest.php",
                data={"version": "1.3", "auth_user": cfg.get("user"),
                      "auth_pwd": cfg.get("password"), "json_data": payload},
            )
        r.raise_for_status()
        body = r.json()
        if body.get("code", 0) != 0:
            raise ValueError(body.get("message", "Unbekannter Fehler"))
        orgs = [o["fields"]["name"] for o in (body.get("objects") or {}).values()]
        return {"ok": True, "organisations": orgs}
