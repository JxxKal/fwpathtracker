"""Lab-Modell: lädt lab.yaml und bietet Match-Helfer für die FortiOS-Emulation.

Die Konvertierung in die echten FMG-Antwortshapes (Liste [ip, netmask],
Integer-action, Feld 'scope member' usw.) passiert in fmgdb.py; hier liegen
nur die geparsten Strukturen + Routing-/Policy-Match-Logik.
"""
from __future__ import annotations

import ipaddress
import os
from dataclasses import dataclass, field
from typing import Any

import yaml

LAB_PATH = os.environ.get("LAB_FILE", "/app/lab.yaml")


def cidr_to_pair(cidr: str) -> list[str]:
    """'10.1.1.1/24' → ['10.1.1.1', '255.255.255.0'] (FMG-Form)."""
    iface = ipaddress.ip_interface(cidr)
    return [str(iface.ip), str(iface.network.netmask)]


def net_to_pair(cidr: str) -> list[str]:
    """'10.2.0.0/20' → ['10.2.0.0', '255.255.240.0'] (FMG-Form)."""
    net = ipaddress.ip_network(cidr, strict=False)
    return [str(net.network_address), str(net.netmask)]


@dataclass
class Interface:
    name: str
    vdom: str
    ip: ipaddress.IPv4Interface | None
    type: str | None


@dataclass
class Route:
    network: ipaddress.IPv4Network
    via: str
    gateway: str | None


@dataclass
class Vdom:
    name: str
    interfaces: dict[str, Interface] = field(default_factory=dict)
    zones: dict[str, list[str]] = field(default_factory=dict)
    routes: list[Route] = field(default_factory=list)


@dataclass
class Device:
    name: str
    adom: str
    serial: str
    os_ver: str
    online: bool
    vdoms: dict[str, Vdom] = field(default_factory=dict)


class Model:
    def __init__(self, raw: dict) -> None:
        self.version: str = raw.get("version", "v7.4.3-build2573")
        self.hostname: str = raw.get("hostname", "fmg-sim")
        self.adoms: list[str] = list(raw.get("adoms") or ["root"])
        self.devices: dict[str, Device] = {}
        self.packages: dict[str, dict] = raw.get("packages") or {}
        self.objects: dict[str, dict] = raw.get("objects") or {}
        self._load_devices(raw.get("devices") or {})

    # ── Laden ────────────────────────────────────────────────────────────────

    def _load_devices(self, devs: dict) -> None:
        for dname, d in devs.items():
            dev = Device(
                name=dname, adom=d.get("adom", self.adoms[0]),
                serial=d.get("serial", f"FGVMSIM{dname}"),
                os_ver=str(d.get("os_ver", "7.4")),
                online=bool(d.get("online", True)),
            )
            for vname, v in (d.get("vdoms") or {}).items():
                vdom = Vdom(name=vname)
                for iname, i in (v.get("interfaces") or {}).items():
                    ip = ipaddress.ip_interface(i["ip"]) if i.get("ip") else None
                    vdom.interfaces[iname] = Interface(
                        name=iname, vdom=vname, ip=ip, type=i.get("type"))
                vdom.zones = {z: list(m) for z, m in (v.get("zones") or {}).items()}
                for r in (v.get("routes") or []):
                    vdom.routes.append(Route(
                        network=ipaddress.ip_network(r["dst"], strict=False),
                        via=r["via"], gateway=r.get("gateway")))
                dev.vdoms[vname] = vdom
            self.devices[dname] = dev

    @classmethod
    def load(cls, path: str = LAB_PATH) -> "Model":
        with open(path, "r", encoding="utf-8") as fh:
            return cls(yaml.safe_load(fh))

    # ── Routing / Policy-Match (FortiOS-Emulation) ───────────────────────────

    def route_lookup(self, device: str, vdom: str,
                     dst: str) -> tuple[str, str | None] | None:
        """Longest-Prefix-Match über connected Netze + statische Routen.
        Rückgabe (egress_intf, gateway) oder None."""
        dev = self.devices.get(device)
        if not dev or vdom not in dev.vdoms:
            return None
        addr = ipaddress.ip_address(dst)
        best: tuple[int, str, str | None] | None = None
        # connected (Priorität hoch)
        for intf in dev.vdoms[vdom].interfaces.values():
            if intf.ip is None:
                continue
            net = intf.ip.network
            if addr in net and (best is None or net.prefixlen > best[0]):
                best = (net.prefixlen, intf.name, "0.0.0.0")
        # statische Routen
        for rt in dev.vdoms[vdom].routes:
            if addr in rt.network and (best is None or rt.network.prefixlen > best[0]):
                best = (rt.network.prefixlen, rt.via, rt.gateway)
        if best is None:
            return None
        return best[1], best[2]

    def zone_of(self, device: str, vdom: str, intf: str) -> str:
        dev = self.devices.get(device)
        if dev and vdom in dev.vdoms:
            for zname, members in dev.vdoms[vdom].zones.items():
                if intf in members:
                    return zname
        return intf

    def _addr_matches(self, adom: str, names: list[str], ip: str) -> bool:
        if any(n == "all" for n in names):
            return True
        addr = ipaddress.ip_address(ip)
        addresses = (self.objects.get(adom) or {}).get("addresses") or {}
        for n in names:
            obj = addresses.get(n)
            if obj and addr in ipaddress.ip_network(obj["subnet"], strict=False):
                return True
        return False

    def _service_matches(self, adom: str, names: list[str],
                         protocol: str, port: int | None) -> bool:
        if any(n == "ALL" for n in names):
            return True
        proto = protocol.lower()
        field_name = {"tcp": "tcp", "udp": "udp"}.get(proto)
        services = (self.objects.get(adom) or {}).get("services") or {}
        for n in names:
            obj = services.get(n)
            if not obj:
                continue
            if proto == "icmp" and str(obj.get("protocol", "")).upper() == "ICMP":
                return True
            if field_name is None or port is None:
                continue
            for pr in (obj.get(field_name) or []):
                lo, _, hi = str(pr).partition("-")
                try:
                    if int(lo) <= port <= (int(hi) if hi else int(lo)):
                        return True
                except ValueError:
                    continue
        return False

    def policy_lookup(self, device: str, vdom: str, srcintf: str, sourceip: str,
                      dest: str, protocol: str, port: int | None) -> dict | None:
        """Erste passende Policy (in Reihenfolge) → dict der Policy, sonst None
        (= implizites Deny). Spiegelt die Zonen-/Objekt-Match-Semantik des
        Trackers, damit Live-Verdict und Cache-Kandidaten übereinstimmen."""
        dev = self.devices.get(device)
        if not dev or vdom not in dev.vdoms:
            return None
        adom = dev.adom
        route = self.route_lookup(device, vdom, dest)
        dstintf = route[0] if route else "any"
        src_zone = self.zone_of(device, vdom, srcintf)
        dst_zone = self.zone_of(device, vdom, dstintf)

        for pkg in self.packages.values():
            if not any(s.get("device") == device and s.get("vdom") == vdom
                       for s in (pkg.get("scope") or [])):
                continue
            for pol in pkg.get("policies") or []:
                if pol.get("status", "enable") in ("disable", 0):
                    continue
                si = pol.get("srcintf") or ["any"]
                di = pol.get("dstintf") or ["any"]
                if not any(z in ("any", srcintf, src_zone) for z in si):
                    continue
                if not any(z in ("any", dstintf, dst_zone) for z in di):
                    continue
                if not self._addr_matches(adom, pol.get("srcaddr") or ["all"], sourceip):
                    continue
                if not self._addr_matches(adom, pol.get("dstaddr") or ["all"], dest):
                    continue
                if not self._service_matches(adom, pol.get("service") or ["ALL"],
                                             protocol, port):
                    continue
                return pol
        return None

    def vip_extip_hit(self, adom: str, dest: str) -> dict | None:
        for name, vip in ((self.objects.get(adom) or {}).get("vips") or {}).items():
            if str(vip.get("extip")) == dest:
                return {"name": name, **vip}
        return None
