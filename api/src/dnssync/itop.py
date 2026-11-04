"""iTop-Zugriff für den DNS-Abgleich. Lesen wie überall; SCHREIBEN nur über
update_address() — eine Klasse (IPv4Address), zwei Felder (short_name,
domain_id), sonst nichts. Der Wächter steht vor jedem Request."""
from __future__ import annotations

import json
import logging

import httpx

from netguard import guard_egress_url
from resolver.itop_source import _core_get, _oql_str

log = logging.getLogger("dnssync.itop")

# Klassen mit Management-IP (TeemIP: managementip_id → IPv4Address). Fehlt
# eine Klasse in einer Installation, wird sie übersprungen.
CI_CLASSES = ("Server", "VirtualMachine", "NetworkDevice", "PC", "Printer", "Hypervisor")
ADDRESS_FIELDS = "ip,status,short_name,domain_id,domain_name,fqdn,org_name"

WRITE_CLASS = "IPv4Address"
WRITE_FIELDS = frozenset({"short_name", "domain_id"})


class ItopWriteBlocked(Exception):
    pass


def guard_write(cls: str, fields: dict) -> None:
    """Der einzige Schreibweg: IPv4Address.short_name/domain_id."""
    if cls != WRITE_CLASS:
        raise ItopWriteBlocked(f"Schreiben nur auf {WRITE_CLASS}, nicht auf {cls}.")
    extra = set(fields) - WRITE_FIELDS
    if extra or not fields:
        raise ItopWriteBlocked(f"Schreiben nur von {sorted(WRITE_FIELDS)}, nicht {sorted(extra)}.")


def _client(cfg: dict) -> httpx.AsyncClient:
    return httpx.AsyncClient(verify=cfg.get("ssl_verify", True), timeout=60)


async def read_all(cfg: dict) -> dict:
    """Adressobjekte, Domains und CIs mit Management-IP."""
    guard_egress_url(cfg["base_url"], "iTop-URL")
    org = (cfg.get("org_filter") or "").strip()
    where = f" WHERE org_name = '{_oql_str(org)}'" if org else ""
    args = (cfg["base_url"], cfg["user"], cfg["password"])
    out: dict = {"addresses": [], "domains": [], "cis": [], "errors": []}
    async with _client(cfg) as client:
        out["addresses"] = await _core_get(client, *args, "IPv4Address", ADDRESS_FIELDS,
                                           f"SELECT IPv4Address{where}")
        try:
            out["domains"] = await _core_get(client, *args, "Domain", "name", "SELECT Domain")
        except Exception as exc:
            out["errors"].append(f"Domain: {exc}")
        for cls in CI_CLASSES:
            try:
                rows = await _core_get(client, *args, cls,
                                       "name,managementip_id,managementip_id_friendlyname",
                                       f"SELECT {cls}{where}")
            except Exception as exc:
                log.info("iTop %s ohne managementip_id: %s", cls, exc)
                continue
            for r in rows:
                if str(r.get("managementip_id") or "0") not in ("", "0"):
                    out["cis"].append({"class": cls, "id": str(r.get("_key") or ""),
                                       "name": str(r.get("name") or "").strip(),
                                       "ip_id": str(r["managementip_id"])})
    return out


async def get_address(cfg: dict, ip_id: str) -> dict | None:
    guard_egress_url(cfg["base_url"], "iTop-URL")
    async with _client(cfg) as client:
        rows = await _core_get(client, cfg["base_url"], cfg["user"], cfg["password"],
                               "IPv4Address", ADDRESS_FIELDS,
                               f"SELECT IPv4Address WHERE id = {int(ip_id)}")
    return rows[0] if rows else None


async def update_address(cfg: dict, ip_id: str, fields: dict, comment: str) -> dict:
    guard_write(WRITE_CLASS, fields)
    guard_egress_url(cfg["base_url"], "iTop-URL")
    user = cfg.get("write_user") or cfg["user"]
    pwd = cfg.get("write_password") or cfg["password"]
    payload = json.dumps({"operation": "core/update", "comment": comment[:250],
                          "class": WRITE_CLASS, "key": int(ip_id),
                          "output_fields": "short_name,domain_name,fqdn", "fields": fields})
    async with _client(cfg) as client:
        r = await client.post(f"{cfg['base_url'].rstrip('/')}/webservices/rest.php",
                              data={"version": "1.3", "auth_user": user, "auth_pwd": pwd,
                                    "json_data": payload})
    r.raise_for_status()
    body = r.json()
    if body.get("code", 0) != 0:
        raise RuntimeError(body.get("message") or str(body))
    obj = next(iter((body.get("objects") or {}).values()), {})
    if obj.get("code", 0) != 0:
        raise RuntimeError(obj.get("message") or str(obj))
    return dict(obj.get("fields") or {})
