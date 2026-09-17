"""Link-Status der Interfaces — live von der FortiGate über den FMG-Proxy.

Der FMG-Snapshot kennt nur die KONFIGURATION: `set status up|down`, also ob
ein Interface administrativ abgeschaltet ist. Ob das Kabel steckt, steht
nirgends in der Konfiguration — das ist Laufzeitzustand und genau das, was
der FortiManager in seiner Interface-Liste rot oder grün färbt.

Ein Netzplan, der ein totes Interface wie ein lebendiges zeichnet, behauptet
etwas Falsches. Deshalb wird der Zustand beim Erzeugen einmal live geholt:
ein Monitor-Aufruf je VDOM im Scope, parallel, und jeder Fehlschlag kostet
nur die Markierung — nie die Zeichnung. Unbekannt heißt unbekannt (None),
nicht "up".
"""
from __future__ import annotations

import asyncio
import logging

from config import Config
from fmg.client import FmgError, FmgTargetOffline
from fmg.factory import build_fmg_client
from fmg.proxy import fortios_results, monitor_get

log = logging.getLogger("diagram.linkstatus")

PATH = "system/interface"
CONCURRENCY = 8


def _rows(results) -> list[dict]:
    """FortiOS liefert die Interfaces je nach Version als Liste oder als
    Objekt mit dem Namen als Schlüssel."""
    if isinstance(results, dict):
        out = []
        for name, row in results.items():
            if isinstance(row, dict):
                out.append({**row, "name": row.get("name") or name})
        return out
    return [r for r in (results or []) if isinstance(r, dict)]


def _flag(value) -> bool | None:
    """'link'/'status' tolerant lesen: bool, 0/1 oder 'up'/'down'."""
    if isinstance(value, bool):
        return value
    if value is None:
        return None
    text = str(value).strip().lower()
    if text in ("up", "1", "true", "yes"):
        return True
    if text in ("down", "0", "false", "no"):
        return False
    return None


def parse(results) -> dict[str, dict]:
    """Monitor-Antwort → {Interface-Name: {link, admin_up, speed}}."""
    out: dict[str, dict] = {}
    for row in _rows(results):
        name = str(row.get("name") or "").strip()
        if not name:
            continue
        out[name] = {
            "link": _flag(row.get("link")),
            "admin_up": _flag(row.get("status")),
            "speed": row.get("speed"),
        }
    return out


async def _one(client, adom: str, device: str, vdom: str,
               warnings: list[str]) -> tuple[tuple[str, str], dict[str, dict]]:
    try:
        resp = await monitor_get(client, adom, device, vdom, PATH)
    except FmgTargetOffline as exc:
        warnings.append(f"Link-Status von {device} nicht abrufbar: {exc}")
        return (device, vdom), {}
    except FmgError as exc:
        log.info("Interface-Monitor auf %s/%s nicht nutzbar: %s", device, vdom, exc)
        return (device, vdom), {}
    except Exception as exc:                       # pragma: no cover — nie die Zeichnung kippen
        log.warning("Link-Status %s/%s: %s", device, vdom, exc)
        return (device, vdom), {}
    return (device, vdom), parse(fortios_results(resp))


async def collect(targets: list[tuple[str, str]], inv, fmg_cfg: dict, app_cfg: Config,
                  warnings: list[str]) -> dict[tuple[str, str], dict[str, dict]]:
    """Link-Status für (Gerät, VDOM) im Scope. Leeres Ergebnis heißt: nicht
    ermittelbar — der Plan zeichnet dann wie bisher nach Konfiguration."""
    if not targets or (not fmg_cfg.get("host") and not fmg_cfg.get("fixture_mode")):
        return {}
    try:
        client = build_fmg_client(fmg_cfg, app_cfg)
    except Exception as exc:
        warnings.append(f"Link-Status nicht abrufbar (FortiManager): {exc}")
        return {}
    sem = asyncio.Semaphore(CONCURRENCY)

    async def guarded(device: str, vdom: str):
        async with sem:
            return await _one(client, inv.adom_of(device) or "root", device, vdom, warnings)

    try:
        pairs = await asyncio.gather(*(guarded(d, v) for d, v in targets))
    finally:
        await client.close()
    return {key: value for key, value in pairs if value}
