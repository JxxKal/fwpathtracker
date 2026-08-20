"""FastAPI-Abhängigkeiten – aktuellen Benutzer aus JWT ermitteln (ids-Muster)."""
from __future__ import annotations

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError

from jwt_utils import decode_token

_bearer = HTTPBearer(auto_error=False)


def get_app_state(request: Request):
    """Zugriff auf app.state (Config, Inventory, FMG-Client, Resolver)."""
    return request.app.state


async def get_current_user(
    request: Request,
    credentials: HTTPAuthorizationCredentials | None = Depends(_bearer),
) -> dict:
    if not credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Nicht angemeldet",
            headers={"WWW-Authenticate": "Bearer"},
        )
    try:
        payload = decode_token(request.app.state.cfg.secret_key, credentials.credentials)
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token ungültig oder abgelaufen",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return payload


async def resolve_query(request: Request, value: str) -> tuple[str, list[str]]:
    """Eingabe (IP ODER Name) → (IP, alle bekannten Namen).

    Gemeinsamer Eingabepfad für alle Werkzeuge: Wer im Pfad-Tracker ein
    FortiManager-Adressobjekt eintippen darf, soll das auch in der
    Netz-Zugehörigkeit und der Switchport-Suche können — sonst muss man die IP
    erst woanders nachschlagen, um ein Werkzeug zu benutzen, das genau dabei
    helfen soll.

    Die Namen sind dabei nicht bloß Kosmetik: die Switchport-Suche gleicht sie
    gegen LLDP-Nachbarschaften und Port-Descriptions ab.
    """
    # Import im Funktionsrumpf: routers.config importiert seinerseits deps
    # (require_admin) — auf Modulebene wäre das ein Zirkel.
    from resolver.chain import is_ip, is_ipv6
    from routers.config import read_config

    value = value.strip()
    if is_ipv6(value):
        raise HTTPException(400, "IPv6 wird nicht unterstützt (wie im Pfad-Tracker).")
    itop_cfg, dns_cfg = await read_config("itop"), await read_config("dns")
    try:
        resolved = await request.app.state.resolver.resolve_endpoint(
            value, request.app.state.inventory, itop_cfg, dns_cfg
        )
        return resolved["ip"], [n["name"] for n in resolved.get("names", []) if n.get("name")]
    except ValueError as exc:
        if not is_ip(value):
            raise HTTPException(422, str(exc)) from exc
        # Eine IP ohne bekannten Namen ist völlig in Ordnung.
        return value, []


async def require_admin(user: dict = Depends(get_current_user)) -> dict:
    if user.get("role") != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="Admin-Rechte erforderlich"
        )
    return user
