"""FortiManager-JSON-RPC-Simulator.

Ein einziger Endpoint /jsonrpc, der die vom Tracker genutzten FMG-Methoden
originalgetreu beantwortet: get (dvmdb/pm/config, /sys/status) und
exec (/sys/login/user, /sys/logout, /sys/proxy/json → FortiOS-Monitor).

Zweck: den kompletten Tracker-Stack ohne echtes Lab trocken durchspielen und
die noch offenen API-ASSUMPTIONS an EINER Stelle greifbar/änderbar halten.
"""
from __future__ import annotations

import itertools
import logging
import os
from urllib.parse import parse_qsl, urlsplit

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

import fmgdb
from fortios import MONITOR_HANDLERS
from model import Model

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s %(levelname)s %(name)s %(message)s")
log = logging.getLogger("fmg-sim")

app = FastAPI(title="fmg-sim", docs_url=None, redoc_url=None)
app.state.model = Model.load()
_sessions = itertools.count(1)

MONITOR_PREFIX = "/api/v2/monitor/"


def _ok_status() -> dict:
    return {"code": 0, "message": "OK"}


def _result(req_id, url: str, data=None, status: dict | None = None) -> dict:
    entry = {"status": status or _ok_status(), "url": url}
    if data is not None:
        entry["data"] = data
    return {"id": req_id, "result": [entry]}


def _error(req_id, url: str, code: int, message: str) -> dict:
    return {"id": req_id, "result": [{"status": {"code": code, "message": message},
                                      "url": url}]}


def _proxy(m: Model, req_id, url: str, data: dict) -> dict:
    """exec /sys/proxy/json → FortiOS-Monitor-Call an das Ziel-Device."""
    resource = data.get("resource", "")
    targets = data.get("target") or []
    parts = urlsplit(resource)
    if not parts.path.startswith(MONITOR_PREFIX):
        return _error(req_id, url, -6, f"Unsupported proxy resource: {resource}")
    monitor_path = parts.path[len(MONITOR_PREFIX):]
    params = dict(parse_qsl(parts.query))
    vdom = params.get("vdom", "root")

    handler = MONITOR_HANDLERS.get(monitor_path)
    if handler is None:
        return _error(req_id, url, -6, f"Unsupported monitor path: {monitor_path}")

    entries = []
    for target in targets:
        device = target.rsplit("/", 1)[-1]      # adom/<adom>/device/<dev>
        dev = m.devices.get(device)
        if dev is None:
            entries.append({"target": target,
                            "status": {"code": -3, "message": "device not found"}})
            continue
        if not dev.online:
            # Degraded-Mode-Test: FortiGate über den FGFM-Tunnel nicht erreichbar.
            entries.append({"target": target,
                            "status": {"code": -2,
                                       "message": "no response from target device (offline)"}})
            continue
        response = handler(m, device, vdom, params)
        entries.append({"target": target, "status": _ok_status(),
                        "response": response})
    return _result(req_id, url, data=entries)


@app.get("/healthz")
async def healthz() -> dict:
    return {"status": "ok", "devices": len(app.state.model.devices)}


@app.post("/_reload")
async def reload_lab() -> dict:
    """lab.yaml ohne Neustart neu einlesen (Topologie-Iteration)."""
    app.state.model = Model.load()
    return {"status": "reloaded", "devices": len(app.state.model.devices)}


@app.post("/jsonrpc")
async def jsonrpc(request: Request):
    m: Model = app.state.model
    body = await request.json()
    req_id = body.get("id")
    method = (body.get("method") or "").lower()
    params = (body.get("params") or [{}])[0]
    url = params.get("url", "")
    data = params.get("data")

    if method == "exec":
        if url == "/sys/login/user":
            return JSONResponse({**_result(req_id, url),
                                 "session": f"sim-session-{next(_sessions)}"})
        if url == "/sys/logout":
            return JSONResponse(_result(req_id, url))
        if url == "/sys/proxy/json":
            return JSONResponse(_proxy(m, req_id, url, data or {}))
        return JSONResponse(_error(req_id, url, -6, f"exec {url} not supported"))

    if method == "get":
        try:
            result_data = fmgdb.handle_get(m, url)
        except fmgdb.NotFound:
            return JSONResponse(_error(req_id, url, -3,
                                       "The requested object does not exist"))
        return JSONResponse(_result(req_id, url, data=result_data))

    return JSONResponse(_error(req_id, url, -6, f"method '{method}' not supported"))
