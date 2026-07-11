"""FortiOS-Monitor-Emulation (via exec /sys/proxy/json).

Baut die rohen FortiOS-REST-Envelopes für router/lookup und
firewall/policy-lookup nach. Diese Envelopes sind genau die Stellen, die im
Tracker-Plan als ASSUMPTIONS markiert sind — dieser Simulator ist damit die
ausführbare Referenz-Spezifikation. Fällt beim späteren Lab-Abgleich ein
Feld anders aus, wird es HIER korrigiert und der Tracker bleibt unberührt.
"""
from __future__ import annotations

from model import Device, Model


def _envelope(device: Device, vdom: str, path: str, name: str, results) -> dict:
    """Rohes FortiOS-REST-Antwort-Envelope (wie es die FortiGate liefert)."""
    return {
        "http_method": "GET",
        "results": results,
        "vdom": vdom,
        "path": path,
        "name": name,
        "action": "select",
        "status": "success",
        "serial": device.serial,
        "version": "v7.4.3",
        "build": 2573,
    }


def router_lookup(m: Model, device: str, vdom: str, params: dict) -> dict:
    """monitor/router/lookup?destination=... → Route mit Egress-Interface.

    ASSUMPTION (Lab): Feldnamen der results verifizieren. Wir liefern
    interface + gateway (der Tracker-Parser akzeptiert interface/oif/intf).
    """
    dev = m.devices[device]
    dst = params.get("destination", "")
    hit = m.route_lookup(device, vdom, dst)
    if hit is None:
        # Kein Treffer: FortiOS liefert leere/negative Antwort.
        return _envelope(dev, vdom, "router", "lookup", {})
    egress, gateway = hit
    results = {
        "interface": egress,
        "gateway": gateway or "0.0.0.0",
    }
    return _envelope(dev, vdom, "router", "lookup", results)


def policy_lookup(m: Model, device: str, vdom: str, params: dict) -> dict:
    """monitor/firewall/policy-lookup → matchende Policy oder implizites Deny.

    ASSUMPTION (Lab): Erfolgs-Payload verifizieren. Dokumentiert/berichtet:
    Match → {"success": true, "policy_id": <n>}; kein Match → {"success": false}.
    """
    dev = m.devices[device]
    srcintf = params.get("srcintf", "")
    sourceip = params.get("sourceip", "")
    dest = params.get("dest", "")
    protocol = params.get("protocol", "tcp")
    port_raw = params.get("destport")
    port = int(port_raw) if port_raw not in (None, "") else None

    pol = m.policy_lookup(device, vdom, srcintf, sourceip, dest, protocol, port)
    if pol is None:
        results: dict = {"success": False}
    else:
        results = {
            "success": True,
            "policy_id": pol["id"],
            "action": pol.get("action", "deny"),
            "policy_name": pol.get("name", ""),
        }
        vip = m.vip_extip_hit(dev.adom, dest)
        if vip is not None:
            results["vip"] = vip["name"]        # Debug-Hinweis (Tracker ignoriert Extras)
    return _envelope(dev, vdom, "firewall", "policy-lookup", results)


MONITOR_HANDLERS = {
    "router/lookup": router_lookup,
    "firewall/policy-lookup": policy_lookup,
}
