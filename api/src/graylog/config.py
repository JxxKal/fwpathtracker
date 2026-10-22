"""Graylog-Verbindung: eigene Config `graylog`, Webdrive nutzt sie mit.

Bis Oktober 2026 stand die Verbindung nur in `webdrive`. Beim Start wird sie
einmalig nach `graylog` übernommen. Webdrive darf weiter einen eigenen Token
führen: Der Report-User bekommt mehr Rechte (AD, iFIX), die nicht
automatisch der Webdrive-Abfrage zufallen sollen.
"""
from __future__ import annotations

import logging

from routers.config import read_config, write_config

log = logging.getLogger("graylog.config")

CONNECTION = ("base_url", "token", "ssl_verify", "timeout_s")


def merge(webdrive: dict, graylog: dict) -> dict:
    """Webdrive-Config mit der Graylog-Verbindung als Rückfall.

    Eigene URL und eigener Token in `webdrive` gehen vor; was dort leer ist,
    kommt aus `graylog`."""
    out = dict(webdrive)
    if not (webdrive.get("base_url") or "").strip():
        for k in ("base_url", "ssl_verify", "timeout_s"):
            if k in graylog:
                out[k] = graylog[k]
    if not webdrive.get("token") and graylog.get("token"):
        out["token"] = graylog["token"]
    return out


async def webdrive_config() -> dict:
    return merge(await read_config("webdrive"), await read_config("graylog"))


async def migrate() -> bool:
    """Verbindung aus `webdrive` nach `graylog` kopieren, wenn dort noch nichts steht."""
    graylog = await read_config("graylog")
    if (graylog.get("base_url") or "").strip():
        return False
    webdrive = await read_config("webdrive")
    if not (webdrive.get("base_url") or "").strip():
        return False
    await write_config("graylog", {**graylog, **{k: webdrive[k] for k in CONNECTION
                                                  if k in webdrive}})
    log.info("Graylog-Verbindung aus den Webdrive-Einstellungen übernommen.")
    return True
