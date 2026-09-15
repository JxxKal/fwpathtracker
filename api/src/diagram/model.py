"""Netzplan-Modell: was in einem Scope (VDOM, Firewall) an Netzen, Nachbarn und
Hosts existiert — zusammengetragen aus FMG-Inventar, iTop, ARP-Historie und
LibreNMS. Der Renderer (drawio.py) macht daraus Kästen; hier entsteht nur der
Inhalt.

Drei Detailstufen, weil ein Standort mit 1500 Hosts als eine Zeichnung
wertlos ist:
    none    nur Netze, Firewalls und ihre Kopplungen (Netzverbindungsplan,
            auch übers WAN: Routen zu fremden VDOMs werden als Nachbarn gezeichnet)
    netdev  dazu Netzwerkgeräte — Switches (LibreNMS), NetworkDevice-CIs (iTop)
    all     alle Hosts, die iTop, FMG-Objekte oder die ARP-Historie kennen
`auto` wählt `all` und fällt oberhalb von MAX_HOSTS auf `netdev` zurück.
"""
from __future__ import annotations

import ipaddress
import logging
from collections.abc import Awaitable, Callable

from inventory.prefixes import PrefixTable
from inventory.store import Inventory
from resolver import fmg_source

log = logging.getLogger("diagram.model")

MAX_HOSTS = 1500
HOST_MODES = ("auto", "all", "netdev", "none")

ArpLookup = Callable[[str], Awaitable[list[dict]]]


def vdom_key(device: str, vdom: str) -> str:
    return f"{device}/{vdom}"


def scope_vdoms(inv: Inventory, scope: str, device: str, vdom: str | None) -> list[tuple[str, str]]:
    if device not in inv.devices:
        raise ValueError(f"Gerät '{device}' ist nicht im FMG-Inventar.")
    vdoms = inv.devices[device]["vdoms"] or ["root"]
    if scope == "firewall":
        return [(device, v) for v in vdoms]
    if scope == "vdom":
        if vdom is None:
            raise ValueError("Scope 'vdom' braucht einen VDOM-Namen.")
        if vdom not in vdoms:
            raise ValueError(f"VDOM '{vdom}' gibt es auf '{device}' nicht.")
        return [(device, vdom)]
    raise ValueError(f"Unbekannter Scope '{scope}' (vdom | firewall).")


def _networks(inv: Inventory, device: str, vdom: str, itop_subnets: list[dict]) -> list[dict]:
    """Connected Netze des VDOMs mit L3-Fakten und iTop-Name."""
    by_cidr = {s["cidr"]: s for s in itop_subnets}
    out: list[dict] = []
    for intf in (inv.interfaces.get(device) or {}).values():
        if intf["vdom"] != vdom or not intf.get("enabled", True):
            continue
        addrs = ([intf["ip"]] if intf["ip"] is not None else []) + list(intf.get("secondary_ips") or [])
        if not addrs:
            continue
        facts = inv.interface_facts(device, intf["name"])
        for a in addrs:
            net = a.network
            it = by_cidr.get(str(net))
            out.append({
                "id": f"net:{device}/{vdom}/{intf['name']}/{net}",
                "interface": intf["name"], "cidr": str(net), "fw_ip": str(a.ip),
                "vlan": facts["vlan"], "zone": facts["zone"],
                "alias": facts["alias"], "description": facts["description"],
                "type": intf.get("type"),
                "itop_name": (it or {}).get("name") or None,
                "itop_gateway": (it or {}).get("gateway"),
                "hosts": [], "host_count": 0, "hosts_truncated": False,
            })
    out.sort(key=lambda n: (n["vlan"] is None, n["vlan"] or 0, n["cidr"]))
    return out


def _neighbors(inv: Inventory, prefixes: PrefixTable, device: str, vdom: str,
               in_scope: set[str]) -> list[dict]:
    """Kopplungen dieses VDOMs nach außen: VDOM-Links, Routen zu fremden VDOMs
    (Overlay/Transit — der WAN-Teil des Plans), Default-Route."""
    edges: list[dict] = []
    me = vdom_key(device, vdom)
    table = inv.interfaces.get(device) or {}

    for intf in table.values():
        if intf["vdom"] != vdom or not inv.is_vdom_link(device, intf["name"]):
            continue
        peer = inv.vdom_link_peer(device, intf["name"])
        if peer is None:
            continue
        pintf, pvdom = peer
        edges.append({"from": me, "to": vdom_key(device, pvdom), "kind": "vdom-link",
                      "label": f"{intf['name']} ↔ {pintf}", "via": intf["name"]})

    routes = inv.static_routes.get((device, vdom)) or []
    per_target: dict[str, dict] = {}
    for rt in routes:
        net = rt["network"]
        if net.prefixlen == 0:
            gw = rt.get("gateway")
            gw_s = f" → {gw}" if gw and gw != "0.0.0.0" else ""
            # Default über einen VDOM-Link ist kein Internet, sondern der
            # Router-VDOM nebenan; alles andere landet in EINER Wolke.
            peer = inv.vdom_link_peer(device, rt["interface"] or "") \
                if inv.is_vdom_link(device, rt["interface"] or "") else None
            if peer is not None:
                edges.append({"from": me, "to": vdom_key(device, peer[1]), "kind": "vdom-link",
                              "label": f"Default via {rt['interface']}{gw_s}", "via": rt["interface"]})
            else:
                edges.append({"from": me, "to": "default", "kind": "default",
                              "label": f"Default via {rt['interface']}{gw_s}", "via": rt["interface"]})
            continue
        targets: list[str] = []
        gw = rt.get("gateway")
        if gw and gw != "0.0.0.0":
            hit = inv.interface_by_ip(gw)
            if hit and vdom_key(hit[0], hit[1]) != me:
                targets = [vdom_key(hit[0], hit[1])]
        if not targets:
            # Wer hält die Netze hinter dieser Route? Eine Standort-Route
            # (/20) zeigt auf alle VDOMs, die dort connected Segmente tragen —
            # genau die sollen als WAN-Nachbarn erscheinen. Die eigene statische
            # Route steht selbst in der PrefixTable und zählt nicht.
            owners = {vdom_key(e.device, e.vdom) for e in prefixes.entries
                      if e.source in ("connected", "override")
                      and vdom_key(e.device, e.vdom) != me
                      and (e.network.subnet_of(net) or net.subnet_of(e.network))}
            targets = sorted(owners)
        if not targets:
            continue
        intf_type = (table.get(rt["interface"] or "") or {}).get("type")
        kind = "overlay" if intf_type == "tunnel" else "transit"
        for target in targets:
            slot = per_target.setdefault(target, {"from": me, "to": target, "kind": kind,
                                                  "nets": [], "via": rt["interface"]})
            slot["nets"].append(str(net))
    for slot in per_target.values():
        nets = slot.pop("nets")
        shown = ", ".join(nets[:3]) + (f" … (+{len(nets) - 3})" if len(nets) > 3 else "")
        slot["label"] = f"{slot['via']}: {shown}"
        edges.append(slot)
    return edges


def _is_netdev(host: dict) -> bool:
    return host.get("kind") in ("NetworkDevice", "switch")


async def _collect_hosts(net: dict, inv: Inventory, itop_hosts: list[dict],
                         itop_addresses: dict[str, dict], arp: ArpLookup | None,
                         librenms_devices: dict[str, dict]) -> list[dict]:
    cidr = ipaddress.IPv4Network(net["cidr"])
    hosts: dict[str, dict] = {}

    def slot(ip: str) -> dict:
        return hosts.setdefault(ip, {"ip": ip, "name": None, "kind": None, "sources": [],
                                     "description": None, "mac": None, "last_seen": None,
                                     "age_s": None})

    for h in itop_hosts:
        try:
            if ipaddress.IPv4Address(h["ip"]) not in cidr:
                continue
        except ValueError:
            continue
        s = slot(h["ip"])
        s["name"] = s["name"] or h["name"]
        s["kind"] = h.get("kind") or s["kind"]
        s["description"] = h.get("description") or s["description"]
        s["sources"].append("itop-ci")
    for ip, rec in itop_addresses.items():
        try:
            if ipaddress.IPv4Address(ip) not in cidr:
                continue
        except ValueError:
            continue
        if (rec.get("status") or "") not in ("allocated", "reserved"):
            continue
        s = slot(ip)
        s["name"] = s["name"] or rec.get("name") or None
        s["itop_status"] = rec.get("status")
        s["sources"].append("itop-ip")
    for key, dev in librenms_devices.items():
        ip = str(dev.get("ip") or "").strip()
        try:
            if not ip or ipaddress.IPv4Address(ip) not in cidr:
                continue
        except ValueError:
            continue
        s = slot(ip)
        s["name"] = s["name"] or dev.get("sysName") or dev.get("hostname")
        s["kind"] = "switch"
        s["librenms"] = {"hostname": dev.get("hostname"), "device_id": dev.get("device_id"),
                         "os": dev.get("os"), "hardware": dev.get("hardware")}
        if "librenms" not in s["sources"]:
            s["sources"].append("librenms")
    if arp is not None:
        try:
            for b in await arp(net["cidr"]):
                s = slot(b["ip"])
                s["mac"], s["last_seen"], s["age_s"] = b["mac"], b["last_seen"], b["age_s"]
                s["sources"].append("arp")
        except Exception as exc:
            log.warning("ARP-Historie für %s nicht lesbar: %s", net["cidr"], exc)
    hosts.pop(net["fw_ip"], None)
    for ip, s in hosts.items():
        if s["name"] is None:
            hit = fmg_source.resolve_ip(inv, ip)
            if hit:
                s["name"], s["sources"] = hit["name"], s["sources"] + ["fmg"]
    return sorted(hosts.values(), key=lambda h: ipaddress.IPv4Address(h["ip"]))


async def _switches(inv: Inventory, device: str, librenms, librenms_cfg: dict | None) -> list[dict]:
    """Switches, die per LLDP an dieser Firewall hängen (LibreNMS-Links, bei
    denen der Nachbar so heißt wie das FMG-Gerät)."""
    if librenms is None or not librenms_cfg or not librenms_cfg.get("base_url"):
        return []
    try:
        links = await librenms.links(librenms_cfg)
        index = await librenms.device_index(librenms_cfg)
    except Exception as exc:
        log.info("LibreNMS-Links für den Netzplan nicht abrufbar: %s", exc)
        return []
    by_id = {str(d.get("device_id")): d for d in index.values()}
    out: dict[str, dict] = {}
    needle = device.lower()
    for link in links:
        remote = str(link.get("remote_hostname") or "").strip().lower()
        if not remote or (remote != needle and remote.split(".")[0] != needle):
            continue
        sw = by_id.get(str(link.get("local_device_id")))
        if sw is None:
            continue
        name = sw.get("sysName") or sw.get("hostname") or str(link.get("local_device_id"))
        slot = out.setdefault(name, {"id": f"switch:{name}", "name": name, "ip": sw.get("ip"),
                                     "hardware": sw.get("hardware"), "ports": []})
        slot["ports"].append({"fw_port": str(link.get("remote_port") or "?"),
                              "local_port_id": link.get("local_port_id")})
    return list(out.values())


async def build(inv: Inventory, prefixes: PrefixTable, *, scope: str, device: str,
                vdom: str | None, hosts: str = "auto",
                itop_subnets: list[dict] | None = None, itop_hosts: list[dict] | None = None,
                itop_addresses: dict[str, dict] | None = None, arp: ArpLookup | None = None,
                librenms=None, librenms_cfg: dict | None = None,
                librenms_devices: dict[str, dict] | None = None,
                max_hosts: int = MAX_HOSTS) -> dict:
    if hosts not in HOST_MODES:
        raise ValueError(f"hosts muss eines von {HOST_MODES} sein.")
    targets = scope_vdoms(inv, scope, device, vdom)
    in_scope = {vdom_key(d, v) for d, v in targets}
    vdoms: list[dict] = []
    edges: list[dict] = []
    for d, v in targets:
        nets = _networks(inv, d, v, itop_subnets or [])
        vdoms.append({"id": vdom_key(d, v), "device": d, "vdom": v, "networks": nets})
        edges.extend(_neighbors(inv, prefixes, d, v, in_scope))

    # Hosts einsammeln, dann je nach Modus (und Menge) ausdünnen.
    mode = hosts
    total = 0
    if mode != "none":
        for vd in vdoms:
            for net in vd["networks"]:
                net["hosts"] = await _collect_hosts(
                    net, inv, itop_hosts or [], itop_addresses or {}, arp,
                    librenms_devices or {})
                total += len(net["hosts"])
        if mode == "auto":
            mode = "netdev" if total > max_hosts else "all"
        if mode == "netdev":
            for vd in vdoms:
                for net in vd["networks"]:
                    net["hosts"] = [h for h in net["hosts"] if _is_netdev(h)]
    shown = 0
    for vd in vdoms:
        for net in vd["networks"]:
            net["host_count"] = len(net["hosts"])
            shown += len(net["hosts"])

    switches = await _switches(inv, device, librenms, librenms_cfg) if mode != "none" else []

    # Nachbarn: alles, worauf Kanten zeigen und was nicht im Scope liegt.
    neighbor_ids = sorted({e["to"] for e in edges if e["to"] not in in_scope} |
                          {e["from"] for e in edges if e["from"] not in in_scope})
    neighbors = []
    for nid in neighbor_ids:
        if nid == "default":
            neighbors.append({"id": nid, "kind": "default", "label": "Internet / Default-Route"})
        else:
            d, _, v = nid.partition("/")
            site = None
            for e in prefixes.entries:
                if e.device == d and e.vdom == v and e.site_name:
                    site = e.site_name
                    break
            neighbors.append({"id": nid, "kind": "vdom", "device": d, "vdom": v, "site": site,
                              "label": nid + (f" ({site})" if site else "")})

    return {
        "scope": {"scope": scope, "device": device, "vdom": vdom},
        "vdoms": vdoms, "edges": edges, "neighbors": neighbors, "switches": switches,
        "hosts_mode": mode,
        "stats": {"vdoms": len(vdoms), "networks": sum(len(v["networks"]) for v in vdoms),
                  "hosts_found": total, "hosts_shown": shown, "neighbors": len(neighbors),
                  "switches": len(switches), "hosts_reduced": hosts == "auto" and mode == "netdev"},
    }
