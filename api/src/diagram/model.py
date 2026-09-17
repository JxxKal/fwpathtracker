"""Netzplan-Modell: was in einem Scope (VDOM, Firewall, Standort, Global) an
Netzen, Nachbarn und
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

Vier Scopes, von innen nach außen:
    vdom      ein VDOM
    firewall  alle VDOMs eines Geräts
    site      alle VDOMs, die im Standort-Supernetz ein connected Netz halten
    global    alle Geräte, nach Standort gruppiert — hier zählen nur noch die
              Kopplungen (wer redet mit wem), deshalb ohne Netze und Hosts.
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
SCOPES = ("vdom", "firewall", "site", "global")
NO_SITE = "ohne Standort"

ArpLookup = Callable[[str], Awaitable[list[dict]]]


def vdom_key(device: str, vdom: str) -> str:
    return f"{device}/{vdom}"


def _supernets(sites: list[dict]) -> list[tuple[str, ipaddress.IPv4Network]]:
    out = []
    for s in sites or []:
        try:
            out.append((str(s.get("name") or s.get("cidr")),
                        ipaddress.IPv4Network(str(s["cidr"]), strict=False)))
        except (KeyError, ValueError):
            continue
    return out


def _override(prefixes: PrefixTable, device: str, vdoms: list[str]) -> str | None:
    for e in prefixes.entries:
        if e.device == device and e.vdom in vdoms and e.site_name:
            return e.site_name
    return None


def site_scores(inv: Inventory, device: str, vdoms: list[str],
                supernets: list[tuple[str, ipaddress.IPv4Network]]) -> dict[str, int]:
    """Standortname → Anzahl connected Netze des Geräts in dessen Supernetz.

    Gezählt statt geraten: ein Gerät hat viele Netze, und einzelne davon
    zeigen woandershin — eine Management-Adresse aus einem zentralen Bereich,
    ein Transfernetz zum Nachbarstandort. Wer den ERSTEN Treffer nimmt, hängt
    die Firewall an das falsche Haus (Feld-Fall: EUGE*-Firewalls landeten in
    Hamburg statt Gas Nord). Zu Hause ist sie dort, wo die Mehrheit der
    Segmente liegt, die sie lokal routet.
    """
    nets = [n for v in vdoms for n, _ in inv.connected_networks(device, v)]
    out: dict[str, int] = {}
    for net in nets:
        # Jedes Netz hat EINE Stimme, und zwar für den spezifischsten Standort,
        # der es enthält. Zählt man je Supernetz, stimmt ein Netz bei
        # verschachtelten Bereichen (Standort-/20 innerhalb eines Haus-/16)
        # doppelt ab und der größere Bereich gewinnt jede Abstimmung.
        hit = max((s for _n, s in supernets if net.subnet_of(s)),
                  key=lambda s: s.prefixlen, default=None)
        if hit is None:
            continue
        name = next(n for n, s in supernets if s == hit)
        out[name] = out.get(name, 0) + 1
    return out


def _best_site(scores: dict[str, int],
               supernets: list[tuple[str, ipaddress.IPv4Network]]) -> str | None:
    if not scores:
        return None
    # Gleichstand: das engere Supernetz gewinnt — es ist die genauere Aussage.
    depth = {name: max(s.prefixlen for n, s in supernets if n == name) for name in scores}
    return max(scores, key=lambda n: (scores[n], depth[n]))


def site_of(inv: Inventory, prefixes: PrefixTable, device: str, vdom: str,
            supernets: list[tuple[str, ipaddress.IPv4Network]]) -> str | None:
    """Standort EINES VDOMs: erst ein Site-Override aus den Einstellungen,
    sonst der Standort mit den meisten connected Netzen dieses VDOMs. Ohne
    beides hat das VDOM keinen Standort — eine Aussage, kein Fehler
    (Transit-/Lab-Geräte gibt es wirklich)."""
    return (_override(prefixes, device, [vdom])
            or _best_site(site_scores(inv, device, [vdom], supernets), supernets))


def site_of_device(inv: Inventory, prefixes: PrefixTable, device: str,
                   supernets: list[tuple[str, ipaddress.IPv4Network]]) -> str | None:
    """Standort des GANZEN Geräts — über alle VDOMs gezählt. Ein Router-VDOM
    mit einem Transfernetz darf die Zuordnung nicht allein bestimmen, während
    das Schutz-VDOM daneben die Standortsegmente hält."""
    vdoms = (inv.devices.get(device) or {}).get("vdoms") or ["root"]
    return (_override(prefixes, device, list(vdoms))
            or _best_site(site_scores(inv, device, list(vdoms), supernets), supernets))


def all_vdoms(inv: Inventory) -> list[tuple[str, str]]:
    return [(d, v) for d, info in sorted(inv.devices.items())
            for v in (info["vdoms"] or ["root"])]


def scope_vdoms(inv: Inventory, scope: str, device: str | None, vdom: str | None,
                site: str | None = None, prefixes: PrefixTable | None = None,
                sites: list[dict] | None = None) -> list[tuple[str, str]]:
    if scope not in SCOPES:
        raise ValueError(f"Unbekannter Scope '{scope}' ({' | '.join(SCOPES)}).")
    if scope == "global":
        return all_vdoms(inv)
    if scope == "site":
        if not site:
            raise ValueError("Scope 'site' braucht einen Standortnamen.")
        if prefixes is None:
            raise ValueError("Scope 'site' braucht die PrefixTable.")
        sup = _supernets(sites or [])
        hits = [(d, v) for d, v in all_vdoms(inv)
                if site_of(inv, prefixes, d, v, sup) == site]
        if not hits:
            raise ValueError(
                f"Zum Standort '{site}' gehört kein VDOM mit connected Netz — "
                "Standort-Supernetz in den Einstellungen prüfen.")
        return hits
    if not device:
        raise ValueError(f"Scope '{scope}' braucht ein Gerät.")
    if device not in inv.devices:
        raise ValueError(f"Gerät '{device}' ist nicht im FMG-Inventar.")
    vdoms = inv.devices[device]["vdoms"] or ["root"]
    if scope == "firewall":
        return [(device, v) for v in vdoms]
    if vdom is None:
        raise ValueError("Scope 'vdom' braucht einen VDOM-Namen.")
    if vdom not in vdoms:
        raise ValueError(f"VDOM '{vdom}' gibt es auf '{device}' nicht.")
    return [(device, vdom)]


def _networks(inv: Inventory, device: str, vdom: str, itop_subnets: list[dict],
              link_status: dict | None = None) -> list[dict]:
    """Netze des VDOMs mit L3-Fakten und iTop-Name — abgeschaltete Interfaces
    ausdrücklich mit, als solche markiert.

    Für die Pfad-Engine zählt ein Interface im Shutdown NICHT als connected;
    es trägt keinen Verkehr, und es als Ingress zu wählen wäre falsch. Ein
    Netzplan ist aber ein Dokument über den KONFIGURIERTEN Bestand: ein
    stillgelegtes Segment einfach wegzulassen hieße, dass der Plan der
    Firewall-Konfiguration widerspricht und niemand erfährt, warum VLAN X
    fehlt. Die VLAN-Übersicht hält es aus demselben Grund genauso.
    """
    by_cidr = {s["cidr"]: s for s in itop_subnets}
    links = (link_status or {}).get((device, vdom)) or {}
    out: list[dict] = []
    for intf in (inv.interfaces.get(device) or {}).values():
        if intf["vdom"] != vdom:
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
                "enabled": bool(intf.get("enabled", True)),
                # None = nicht ermittelbar (FMG nicht erreichbar, Gerät offline).
                # Das ist ausdrücklich NICHT dasselbe wie "up".
                "link": (links.get(intf["name"]) or {}).get("link"),
                "itop_name": (it or {}).get("name") or None,
                "itop_gateway": (it or {}).get("gateway"),
                "hosts": [], "host_count": 0, "hosts_truncated": False,
            })
    # Reihenfolge: aktiv, dann Link down, dann abgeschaltet — der Plan liest
    # sich von lebendig nach stillgelegt.
    out.sort(key=lambda n: (not n["enabled"], n["link"] is False,
                            n["vlan"] is None, n["vlan"] or 0, n["cidr"]))
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


async def _switches(devices: list[str], librenms, librenms_cfg: dict | None) -> list[dict]:
    """Switches, die per LLDP an diesen Firewalls hängen (LibreNMS-Links, bei
    denen der Nachbar so heißt wie ein FMG-Gerät im Scope)."""
    if librenms is None or not librenms_cfg or not librenms_cfg.get("base_url") or not devices:
        return []
    try:
        links = await librenms.links(librenms_cfg)
        index = await librenms.device_index(librenms_cfg)
    except Exception as exc:
        log.info("LibreNMS-Links für den Netzplan nicht abrufbar: %s", exc)
        return []
    by_id = {str(d.get("device_id")): d for d in index.values()}
    by_needle = {d.lower(): d for d in devices}
    out: dict[tuple[str, str], dict] = {}
    for link in links:
        remote = str(link.get("remote_hostname") or "").strip().lower()
        if not remote:
            continue
        fw = by_needle.get(remote) or by_needle.get(remote.split(".")[0])
        if fw is None:
            continue
        sw = by_id.get(str(link.get("local_device_id")))
        if sw is None:
            continue
        name = sw.get("sysName") or sw.get("hostname") or str(link.get("local_device_id"))
        slot = out.setdefault((fw, name), {"id": f"switch:{fw}:{name}", "name": name,
                                           "device": fw, "ip": sw.get("ip"),
                                           "hardware": sw.get("hardware"), "ports": []})
        slot["ports"].append({"fw_port": str(link.get("remote_port") or "?"),
                              "local_port_id": link.get("local_port_id")})
    return list(out.values())


async def build(inv: Inventory, prefixes: PrefixTable, *, scope: str,
                device: str | None = None, vdom: str | None = None, site: str | None = None,
                hosts: str = "auto", sites: list[dict] | None = None,
                link_status: dict | None = None,
                itop_subnets: list[dict] | None = None, itop_hosts: list[dict] | None = None,
                itop_addresses: dict[str, dict] | None = None, arp: ArpLookup | None = None,
                librenms=None, librenms_cfg: dict | None = None,
                librenms_devices: dict[str, dict] | None = None,
                max_hosts: int = MAX_HOSTS) -> dict:
    if hosts not in HOST_MODES:
        raise ValueError(f"hosts muss eines von {HOST_MODES} sein.")
    targets = scope_vdoms(inv, scope, device, vdom, site, prefixes, sites)
    in_scope = {vdom_key(d, v) for d, v in targets}
    supernets = _supernets(sites or [])

    # Global zeichnet die Kopplungen, nicht den Inhalt: bei 40 Geräten wären
    # Netze und Hosts weder lesbar noch in vertretbarer Zeit einzusammeln.
    with_networks = scope != "global"
    mode = "none" if scope == "global" else hosts

    vdoms: list[dict] = []
    edges: list[dict] = []
    for d, v in targets:
        all_nets = _networks(inv, d, v, itop_subnets or [], link_status)
        nets = all_nets if with_networks else []
        vdoms.append({"id": vdom_key(d, v), "device": d, "vdom": v, "networks": nets,
                      "network_count": len(all_nets),
                      "networks_off": sum(1 for n in all_nets if not n["enabled"]),
                      "networks_link_down": sum(1 for n in all_nets
                                                if n["enabled"] and n["link"] is False)})
        edges.extend(_neighbors(inv, prefixes, d, v, in_scope))

    # Hosts einsammeln, dann je nach Modus (und Menge) ausdünnen.
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

    scope_devices = sorted({d for d, _ in targets})
    switches = await _switches(scope_devices, librenms, librenms_cfg) if mode != "none" else []
    sw_by_device: dict[str, list[dict]] = {}
    for sw in switches:
        sw_by_device.setdefault(sw["device"], []).append(sw)

    # Geräte → Standorte gruppieren. Die Gruppen sind das Gerüst der Zeichnung:
    # Standort-Container > Firewall-Container > VDOM > Netz.
    devices: list[dict] = []
    for dev in scope_devices:
        dev_vdoms = [vd for vd in vdoms if vd["device"] == dev]
        devices.append({"device": dev, "site": site_of_device(inv, prefixes, dev, supernets),
                        "adom": inv.adom_of(dev), "vdoms": dev_vdoms,
                        "ha": (inv.devices.get(dev) or {}).get("ha"),
                        "switches": sw_by_device.get(dev, [])})
    grouped: dict[str, list[dict]] = {}
    for d in devices:
        grouped.setdefault(d["site"] or NO_SITE, []).append(d)
    described = {str(s.get("name")): str(s.get("description") or "").strip()
                 for s in (sites or [])}
    site_groups = [{"name": name, "description": described.get(name) or None, "devices": devs}
                   for name, devs in sorted(grouped.items())]
    # Ein einzelner namenloser Standort ist keine Gruppe, sondern Rauschen.
    if len(site_groups) == 1 and site_groups[0]["name"] == NO_SITE:
        site_groups[0]["name"] = None

    # Nachbarn: alles, worauf Kanten zeigen und was nicht im Scope liegt.
    neighbor_ids = sorted({e["to"] for e in edges if e["to"] not in in_scope} |
                          {e["from"] for e in edges if e["from"] not in in_scope})
    neighbors = []
    for nid in neighbor_ids:
        if nid == "default":
            neighbors.append({"id": nid, "kind": "default", "label": "Internet / Default-Route"})
        else:
            d, _, v = nid.partition("/")
            nb_site = site_of_device(inv, prefixes, d, supernets) if d in inv.devices else None
            ha = (inv.devices.get(d) or {}).get("ha")
            label = nid + (f" ({nb_site})" if nb_site else "")
            neighbors.append({"id": nid, "kind": "vdom", "device": d, "vdom": v,
                              "site": nb_site, "ha": ha,
                              "label": label + (f" · HA {ha['mode']}" if ha else "")})

    return {
        "scope": {"scope": scope, "device": device, "vdom": vdom, "site": site,
                  "title": _title(scope, device, vdom, site)},
        "vdoms": vdoms, "devices": devices, "sites": site_groups,
        "edges": edges, "neighbors": neighbors, "switches": switches,
        "hosts_mode": mode, "with_networks": with_networks,
        "stats": {"devices": len(devices), "vdoms": len(vdoms),
                  "networks": sum(vd["network_count"] for vd in vdoms),
                  "networks_off": sum(vd["networks_off"] for vd in vdoms),
                  "networks_link_down": sum(vd["networks_link_down"] for vd in vdoms),
                  "hosts_found": total, "hosts_shown": shown, "neighbors": len(neighbors),
                  "switches": len(switches), "sites": len([g for g in site_groups if g["name"]]),
                  "ha_clusters": sum(1 for d in devices if d.get("ha")),
                  "hosts_reduced": hosts == "auto" and mode == "netdev"},
    }


def _title(scope: str, device: str | None, vdom: str | None, site: str | None) -> str:
    if scope == "global":
        return "Netzplan gesamt"
    if scope == "site":
        return f"Netzplan Standort {site}"
    if scope == "firewall":
        return f"Netzplan {device}"
    return f"Netzplan {device}/{vdom}"
