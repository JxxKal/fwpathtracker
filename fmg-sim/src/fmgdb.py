"""Übersetzt die pm/config- und dvmdb-GET-URLs in echte FMG-Datenshapes.

Was hier rauskommt, landet nach dem Sync 1:1 im fmg_snapshot des Trackers —
darum bilden wir die Feldnamen der echten FortiManager-API nach: Liste
[ip, netmask], Integer-action (1/0), Feld "scope member" (mit Leerzeichen),
dynamic_mapping für Zonen usw.
"""
from __future__ import annotations

from model import Model, cidr_to_pair, net_to_pair

_ACTION_INT = {"accept": 1, "deny": 0, "ipsec": 2}


class NotFound(Exception):
    """URL trifft kein Objekt → FMG-Statuscode -3."""


def _sys_status(m: Model) -> dict:
    return {"Version": m.version, "Hostname": m.hostname,
            "Serial": "FMG-VMSIM0000001", "Admin Domain Configuration": "enabled"}


def _adoms(m: Model) -> list[dict]:
    return [{"name": a, "oid": 100 + i} for i, a in enumerate(m.adoms)]


def _devices(m: Model, adom: str) -> list[dict]:
    out = []
    for dev in m.devices.values():
        if dev.adom != adom:
            continue
        out.append({
            "name": dev.name, "sn": dev.serial, "os_ver": dev.os_ver,
            "conn_status": 1 if dev.online else 0,
            "vdom": [{"name": v} for v in dev.vdoms],
        })
    return out


def _packages(m: Model, adom: str) -> list[dict]:
    out = []
    for pname, pkg in m.packages.items():
        scope = [s for s in (pkg.get("scope") or [])
                 if _device_in_adom(m, s.get("device"), adom)]
        if not scope:
            continue
        out.append({
            "name": pname, "type": "pkg",
            "scope member": [{"name": s["device"], "vdom": s["vdom"]} for s in scope],
        })
    return out


def _device_in_adom(m: Model, device: str | None, adom: str) -> bool:
    dev = m.devices.get(device or "")
    return dev is not None and dev.adom == adom


def _policies(m: Model, adom: str, pkg_path: str) -> list[dict]:
    pkg = m.packages.get(pkg_path)
    if pkg is None:
        raise NotFound(pkg_path)
    out = []
    for pol in pkg.get("policies") or []:
        out.append({
            "policyid": pol["id"], "name": pol.get("name", ""),
            "action": _ACTION_INT.get(pol.get("action", "deny"), 0),
            "status": 0 if pol.get("status") in ("disable", 0) else 1,
            "srcintf": list(pol.get("srcintf") or ["any"]),
            "dstintf": list(pol.get("dstintf") or ["any"]),
            "srcaddr": list(pol.get("srcaddr") or ["all"]),
            "dstaddr": list(pol.get("dstaddr") or ["all"]),
            "service": list(pol.get("service") or ["ALL"]),
            "schedule": ["always"], "logtraffic": 2,
        })
    return out


def _addresses(m: Model, adom: str) -> list[dict]:
    addrs = (m.objects.get(adom) or {}).get("addresses") or {}
    return [{"name": n, "type": "ipmask", "subnet": net_to_pair(o["subnet"])}
            for n, o in addrs.items()]


def _services(m: Model, adom: str) -> list[dict]:
    svcs = (m.objects.get(adom) or {}).get("services") or {}
    out = []
    for n, o in svcs.items():
        entry: dict = {"name": n, "protocol": o.get("protocol", "TCP/UDP/SCTP")}
        if o.get("tcp"):
            entry["tcp-portrange"] = [str(p) for p in o["tcp"]]
        if o.get("udp"):
            entry["udp-portrange"] = [str(p) for p in o["udp"]]
        out.append(entry)
    return out


def _vips(m: Model, adom: str) -> list[dict]:
    vips = (m.objects.get(adom) or {}).get("vips") or {}
    return [{"name": n, "extip": o["extip"], "mappedip": [o["mappedip"]],
             "type": "static-nat"} for n, o in vips.items()]


def _zones(m: Model, adom: str) -> list[dict]:
    """obj/dynamic/interface: pro Zonenname ein Objekt mit dynamic_mapping
    über alle Geräte/VDOMs des ADOM, die diese Zone führen."""
    agg: dict[str, list[dict]] = {}
    for dev in m.devices.values():
        if dev.adom != adom:
            continue
        for vname, vdom in dev.vdoms.items():
            for zname, members in vdom.zones.items():
                agg.setdefault(zname, []).append({
                    "_scope": [{"name": dev.name, "vdom": vname}],
                    "local-intf": list(members),
                })
    return [{"name": z, "dynamic_mapping": maps} for z, maps in agg.items()]


def _interfaces(m: Model, device: str) -> list[dict]:
    dev = m.devices.get(device)
    if dev is None:
        raise NotFound(device)
    out = []
    for vname, vdom in dev.vdoms.items():
        for intf in vdom.interfaces.values():
            entry: dict = {"name": intf.name, "vdom": [vname]}
            if intf.ip is not None:
                entry["ip"] = [str(intf.ip.ip), str(intf.ip.network.netmask)]
            if intf.type:
                entry["type"] = intf.type
            out.append(entry)
    return out


def _static_routes(m: Model, device: str, vdom_name: str) -> list[dict]:
    dev = m.devices.get(device)
    if dev is None or vdom_name not in dev.vdoms:
        raise NotFound(f"{device}/{vdom_name}")
    out = []
    for i, rt in enumerate(dev.vdoms[vdom_name].routes, start=1):
        entry = {
            "seq-num": i,
            "dst": [str(rt.network.network_address), str(rt.network.netmask)],
            "device": [rt.via],
        }
        if rt.gateway:
            entry["gateway"] = rt.gateway
        out.append(entry)
    return out


def handle_get(m: Model, url: str):
    """GET-URL → data-Wert (Objekt oder Liste). Wirft NotFound bei Unbekanntem."""
    parts = url.strip("/").split("/")

    if url == "/sys/status":
        return _sys_status(m)
    if url == "/dvmdb/adom":
        return _adoms(m)

    # /dvmdb/adom/{adom}/device
    if len(parts) == 4 and parts[:2] == ["dvmdb", "adom"] and parts[3] == "device":
        return _devices(m, parts[2])

    # /pm/pkg/adom/{adom}
    if len(parts) == 4 and parts[:3] == ["pm", "pkg", "adom"]:
        return _packages(m, parts[3])

    # /pm/config/adom/{adom}/...
    if len(parts) >= 5 and parts[:3] == ["pm", "config", "adom"]:
        adom = parts[3]
        rest = parts[4:]
        # .../pkg/{path}/firewall/policy   (path kann Slashes enthalten → Folder)
        if rest[0] == "pkg" and rest[-2:] == ["firewall", "policy"]:
            pkg_path = "/".join(rest[1:-2])
            return _policies(m, adom, pkg_path)
        tail = "/".join(rest)
        table = {
            "obj/firewall/address": _addresses,
            "obj/firewall/vip": _vips,
            "obj/dynamic/interface": _zones,
        }.get(tail)
        if table is not None:
            return table(m, adom)
        if tail == "obj/firewall/service/custom":
            return _services(m, adom)
        if tail in ("obj/firewall/addrgrp", "obj/firewall/service/group"):
            return []            # in diesem Lab nicht modelliert → leer (valide)

    # /pm/config/device/{name}/global/system/interface
    if (len(parts) == 7 and parts[:3] == ["pm", "config", "device"]
            and parts[4:] == ["global", "system", "interface"]):
        return _interfaces(m, parts[3])

    # /pm/config/device/{name}/vdom/{vdom}/router/static
    if (len(parts) == 8 and parts[:3] == ["pm", "config", "device"]
            and parts[4] == "vdom" and parts[6:] == ["router", "static"]):
        return _static_routes(m, parts[3], parts[5])

    raise NotFound(url)
