"""FortiAuthenticator-REST-API (nur lesend): die importierten LDAP-User.

Die Logs nennen bei einem Sync nur die Anzahl („Retrieved 26 user(s)“), nie
die Namen. Welche User es sind und ob ihnen E-Mail oder Name fehlen — also
genau das, woran OpenCloud bei der Erstanmeldung scheitert — weiß nur der FAC.

Authentifizierung: Admin-Benutzername + Web-Service-API-Key als Basic Auth.
Antwortformat (tastypie): {"meta": {"total_count", "next", …}, "objects": [...]}.
"""
from __future__ import annotations

import time

import httpx

from netguard import guard_egress_url

PAGE = 100
MAX_PAGES = 50
CACHE_S = 300      # die Liste ändert sich nur mit dem stündlichen Sync


class FacError(Exception):
    pass


class FacNotConfigured(FacError):
    pass


def fac_base(cfg: dict) -> str:
    base = (cfg.get("fac_url") or "").strip().rstrip("/")
    if not base:
        raise FacNotConfigured("FortiAuthenticator-URL fehlt.")
    if not cfg.get("fac_user") or not cfg.get("fac_api_key"):
        raise FacNotConfigured("FortiAuthenticator-Benutzer oder API-Key fehlt.")
    for suffix in ("/api/v1", "/api"):
        if base.endswith(suffix):
            base = base[: -len(suffix)]
    return base


class FacClient:
    def __init__(self, transport: httpx.AsyncBaseTransport | None = None) -> None:
        self._transport = transport
        self._cache: tuple[float, tuple, list[dict]] | None = None

    async def _get(self, cfg: dict, path: str, params: dict) -> dict:
        base = fac_base(cfg)
        guard_egress_url(base, "FortiAuthenticator-URL")
        async with httpx.AsyncClient(
            verify=cfg.get("fac_ssl_verify", True), timeout=float(cfg.get("timeout_s", 20)),
            auth=(str(cfg["fac_user"]), str(cfg["fac_api_key"])),
            headers={"Accept": "application/json"}, transport=self._transport,
        ) as client:
            r = await client.get(f"{base}/api/v1/{path}", params=params)
        if r.status_code in (401, 403):
            raise FacError("FortiAuthenticator lehnt Benutzer/API-Key ab (401/403).")
        if r.status_code >= 400:
            raise FacError(f"FortiAuthenticator antwortet {r.status_code}: {r.text[:200]}")
        try:
            body = r.json()
        except ValueError as exc:
            raise FacError("Antwort des FortiAuthenticator ist kein JSON.") from exc
        return body if isinstance(body, dict) else {}

    async def ldapusers(self, cfg: dict) -> list[dict]:
        key = (cfg.get("fac_url"), cfg.get("fac_user"))
        if self._cache and self._cache[1] == key and time.monotonic() - self._cache[0] < CACHE_S:
            return self._cache[2]
        out: list[dict] = []
        for page in range(MAX_PAGES):
            body = await self._get(cfg, "ldapusers/", {"limit": PAGE, "offset": page * PAGE, "format": "json"})
            objs = body.get("objects") or []
            out.extend(objs)
            total = (body.get("meta") or {}).get("total_count")
            if len(objs) < PAGE or (total is not None and len(out) >= total):
                break
        self._cache = (time.monotonic(), key, out)
        return out

    def invalidate(self) -> None:
        self._cache = None

    async def test(self, cfg: dict) -> dict:
        body = await self._get(cfg, "ldapusers/", {"limit": 1, "format": "json"})
        return {"ok": True, "ldapusers": int((body.get("meta") or {}).get("total_count") or 0)}
