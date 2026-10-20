"""Segmentplan eines Service: ausgewählte VLANs als Netzsegmente, quer über alle Standorte.

Die Service-Übersicht (services.py) beantwortet „in welchen VLANs liegt der
Service?". Der Segmentplan zeichnet für eine Auswahl dieser VLANs, wie sie
im Netz hängen — im Stil der klassischen Standortpläne:

    Hosts ── Netzsegment (Busleiste) ── Switches
                  │ Interface
            Firewall · Segment-VDOM ── Inter-VDOM ── Router-VDOM
                                                        │ Uplink
                                                    SD-WAN-Wolke

Ein Service wie „Backup" hat an jedem Standort sein eigenes VLAN. Jeder
Standort wird ein Kasten, die Firewalls stehen auf der Seite zur Wolke, die
Wolke in der Mitte. Gezeichnet wird nur, was die Quellen belegen:

  * Segment und Firewall-Interface aus dem FortiManager (das VLAN, an dem
    die CIs des Service per IP liegen — dieselbe Zuordnung wie die Übersicht);
  * Hosts aus iTop, ARP-Historie, FortiAnalyzer und LibreNMS, markiert wie in
    der Übersicht (rot = nicht am Service, rot umrandet = nicht im iTop);
  * Switches aus LibreNMS: per LLDP von der Firewall aus erreichbar UND mit
    diesem VLAN konfiguriert. Dieselbe VLAN-Nummer gibt es an jedem Standort,
    erst die LLDP-Nachbarschaft macht daraus „die Switches DIESES Segments";
  * Router-VDOM wie in der Pfad-Engine: Name, sonst Default-Route, sonst Overlay.
"""
from __future__ import annotations

import ipaddress
import math
import re
from collections import deque

from diagram import drawio, model as diagram_model, services as service_view, titleblock
from diagram.mx import Doc, esc
from engine.path import _edge_vdom, _overlay_vdom, _router_vdom
from inventory.prefixes import PrefixTable
from inventory.store import Inventory

DEFAULT_ROUTER_RE = "(?i)(router|wan.?edge)"
DEFAULT_OVERLAY_RE = "(?i)(vpn|ovl|sdwan|tun|ipsec)"
# LLDP-Suche: wie weit vom Firewall-Port aus. Ein Standort hat selten mehr als
# Core → Verteiler → Access; die Grenze hält eine LLDP-Kette über einen
# unüberwachten Medienwandler hinweg davon ab, das halbe Land einzusammeln.
MAX_LLDP_HOPS = 4
FIREWALL_OS = ("fortigate", "fortios", "forti")
NO_SITE = diagram_model.NO_SITE


# ── Modell ────────────────────────────────────────────────────────────────────

def _router_of(inv: Inventory, device: str, router_re: re.Pattern,
               overlay_re: re.Pattern) -> str | None:
    vdoms = (inv.devices.get(device) or {}).get("vdoms") or []
    if len(vdoms) <= 1:
        return None
    return (_router_vdom(inv, device, router_re) or _edge_vdom(inv, device)
            or _overlay_vdom(inv, device, overlay_re))


def _vdom_link(inv: Inventory, device: str, vdom: str, peer_vdom: str) -> str:
    """Beschriftung der Kopplung Segment-VDOM → Router-VDOM."""
    for name, intf in sorted((inv.interfaces.get(device) or {}).items()):
        if intf["vdom"] != vdom or not inv.is_vdom_link(device, name):
            continue
        peer = inv.vdom_link_peer(device, name)
        if peer and peer[1] == peer_vdom:
            return f"{name} ↔ {peer[0]}"
    return "Inter-VDOM"


def _uplink(inv: Inventory, device: str, vdom: str, overlay_re: re.Pattern) -> str:
    """Wodurch dieser VDOM den Standort verlässt — für die Linie zur Wolke.
    Das Routing übers SD-WAN ist meist dynamisch (BGP) und steht dann in
    keiner statischen Route; das sagt die Beschriftung auch so."""
    default = sorted({rt["interface"] for rt in inv.static_routes.get((device, vdom)) or []
                      if rt["network"].prefixlen == 0 and rt.get("interface")
                      and not inv.is_vdom_link(device, rt["interface"])})
    if default:
        return "Default via " + ", ".join(default)
    tunnels = sorted(n for n, i in (inv.interfaces.get(device) or {}).items()
                     if i["vdom"] == vdom and (i.get("type") in ("tunnel", "ipsec")
                                               or overlay_re.search(n)))
    if tunnels:
        more = f" (+{len(tunnels) - 3})" if len(tunnels) > 3 else ""
        return "Overlay " + ", ".join(tunnels[:3]) + more
    return "SD-WAN (dynamisch geroutet)"


def _vlan_num(row: dict) -> int | None:
    try:
        n = int(str(row.get("vlan_vlan")).strip())
    except (TypeError, ValueError):
        return None
    return n if 1 <= n <= 4094 else None


def _is_firewall(dev: dict, fw_names: set[str]) -> bool:
    os_ = str(dev.get("os") or "").lower()
    names = {str(dev.get(k) or "").strip().lower().split(".")[0]
             for k in ("sysName", "hostname")}
    return any(o in os_ for o in FIREWALL_OS) or bool(names & fw_names)


def vlan_switches(device: str, vlan: int | None, lldp: dict | None,
                  fw_names: set[str]) -> list[dict]:
    """Switches des Segments: von der Firewall per LLDP erreichbar und mit
    dem VLAN konfiguriert. Ohne VLAN-Nummer (geroutetes Interface ohne Tag)
    zählen nur die direkt an der Firewall hängenden Switches."""
    if not lldp:
        return []
    links, index, vlan_rows = lldp["links"], lldp["index"], lldp["vlans"]
    by_id = {str(d.get("device_id")): d for d in index.values() if d.get("device_id")}
    me = device.lower()

    def is_me(name) -> bool:
        n = str(name or "").strip().lower()
        return bool(n) and (n == me or n.split(".")[0] == me)

    start: set[str] = set()
    adj: dict[str, set[str]] = {}
    for ln in links:
        a, b = str(ln.get("local_device_id") or ""), str(ln.get("remote_device_id") or "")
        a_dev = by_id.get(a)
        if is_me(ln.get("remote_hostname")) and a_dev and not _is_firewall(a_dev, fw_names):
            start.add(a)
        if a_dev and is_me(a_dev.get("sysName") or a_dev.get("hostname")) and b in by_id \
                and not _is_firewall(by_id[b], fw_names):
            start.add(b)
        if a in by_id and b in by_id and b != "0":
            adj.setdefault(a, set()).add(b)
            adj.setdefault(b, set()).add(a)
    if vlan is None:
        reached = start
    else:
        reached, queue = set(start), deque((s, 0) for s in start)
        while queue:
            cur, depth = queue.popleft()
            if depth >= MAX_LLDP_HOPS:
                continue
            for nxt in adj.get(cur, ()):
                if nxt in reached or _is_firewall(by_id[nxt], fw_names):
                    continue
                reached.add(nxt)
                queue.append((nxt, depth + 1))
        carrying = {str(r.get("device_id")) for r in vlan_rows if _vlan_num(r) == vlan}
        reached = {d for d in reached if d in carrying}
    out = []
    for did in sorted(reached, key=lambda d: str(by_id[d].get("sysName") or by_id[d].get("hostname"))):
        d = by_id[did]
        out.append({"id": did, "name": d.get("sysName") or d.get("hostname") or did,
                    "ip": d.get("ip"), "hardware": d.get("hardware"),
                    "uplink": did in start})
    return out


def find_service(families: list[dict], services: list[dict], service: str) -> list[dict]:
    """Die Familie mit genau diesem Service als einzigem — Eingabe für place()."""
    needle = service.strip().lower()
    for fam in service_view._wanted(families, services, None):
        for svc in fam["services"]:
            if svc["id"] == service or svc["name"].lower() == needle:
                return [dict(fam, services=[svc])]
    raise ValueError(f"Service '{service}' gibt es im iTop nicht.")


def network_choices(inv: Inventory, prefixes: PrefixTable, nets: dict[str, dict],
                    svc: dict, sites: list[dict]) -> list[dict]:
    """Die VLANs eines Service zur Auswahl — mit Standort, damit „Backup an
    allen Standorten" auf einen Blick als Liste dasteht."""
    supernets = diagram_model._supernets(sites)
    ips = [ipaddress.IPv4Address(i) for i in svc["ips"]]
    out = []
    for nid in svc["networks"]:
        n = nets[nid]
        cidr = ipaddress.IPv4Network(n["cidr"])
        out.append({"id": nid, "cidr": n["cidr"], "vlan": n["vlan"],
                    "name": n.get("alias") or n.get("itop_name") or n.get("description") or None,
                    "interface": n["interface"], "fw_id": n["fw_id"],
                    "site": diagram_model.site_of_device(inv, prefixes, n["device"], supernets),
                    "enabled": n["enabled"], "cis": sum(1 for a in ips if a in cidr)})
    out.sort(key=lambda r: (r["site"] is None, r["site"] or "", r["vlan"] is None,
                            r["vlan"] or 0, r["cidr"]))
    return out


async def build(inv: Inventory, prefixes: PrefixTable, *, family: dict, nets: dict[str, dict],
                selected: list[str], itop_hosts: list[dict], addresses=None, arp=None,
                dns=None, librenms_devices: dict[str, dict] | None = None,
                faz_hosts: list[dict] | None = None, arp_max_age_s: int = 0,
                sites: list[dict] | None = None, lldp: dict | None = None,
                router_vdom_pattern: str = DEFAULT_ROUTER_RE,
                overlay_pattern: str = DEFAULT_OVERLAY_RE) -> dict:
    svc = family["services"][0]
    unknown = [s for s in selected if s not in svc["networks"]]
    if unknown:
        raise ValueError(f"{len(unknown)} gewählte Netze gehören nicht (mehr) zum Service "
                         f"'{svc['name']}' — Auswahl neu laden.")
    chosen = [nets[nid] for nid in (selected or svc["networks"])]
    if not chosen:
        raise ValueError(f"Service '{svc['name']}' liegt in keinem Firewall-Netz.")
    warnings: list[str] = []
    router_re, overlay_re = re.compile(router_vdom_pattern), re.compile(overlay_pattern)
    supernets = diagram_model._supernets(sites or [])
    fw_names = {d.lower() for d in inv.devices}

    itop_addresses = await addresses([n["cidr"] for n in chosen]) if addresses else {}
    for net in chosen:
        net["hosts"] = await diagram_model._collect_hosts(
            net, inv, itop_hosts, itop_addresses, arp, librenms_devices or {},
            faz_hosts, arp_max_age_s)
    resolved = await diagram_model._resolve_names(chosen, dns, [diagram_model.DNS_MAX])
    ips = set(svc["ips"])
    for net in chosen:
        for h in net["hosts"]:
            h["in_itop"] = bool(service_view.ITOP_SOURCES & set(h.get("sources") or []))
        net["switches"] = vlan_switches(net["device"], net["vlan"], lldp, fw_names)
        net["vlan_sort"] = (net["vlan"] is None, net["vlan"] or 0, net["cidr"])

    # Standort → Firewalls → VDOM-Kette.
    by_site: dict[str, dict] = {}
    routers: dict[str, str | None] = {}
    for net in sorted(chosen, key=lambda n: n["vlan_sort"]):
        dev = net["device"]
        site = diagram_model.site_of_device(inv, prefixes, dev, supernets) or NO_SITE
        slot = by_site.setdefault(site, {"name": site, "segments": [], "firewalls": {}})
        slot["segments"].append(net)
        fw = slot["firewalls"].setdefault(dev, {
            "device": dev, "ha": (inv.devices.get(dev) or {}).get("ha"),
            "vdoms": [], "router": None, "links": {}, "uplink": None})
        if dev not in routers:
            routers[dev] = _router_of(inv, dev, router_re, overlay_re)
            if routers[dev] is None and len((inv.devices.get(dev) or {}).get("vdoms") or []) > 1:
                warnings.append(f"{dev}: Router-VDOM nicht erkennbar (Name, Default-Route, "
                                "Overlay) — die Segment-VDOMs koppeln direkt zur Wolke.")
        if net["vdom"] not in fw["vdoms"]:
            fw["vdoms"].append(net["vdom"])
    for site in by_site.values():
        for dev, fw in site["firewalls"].items():
            r = routers[dev]
            fw["router"] = r
            for v in fw["vdoms"]:
                if r and v != r:
                    fw["links"][v] = _vdom_link(inv, dev, v, r)
            fw["uplink"] = _uplink(inv, dev, r or fw["vdoms"][0], overlay_re)
            # Segment-VDOMs ohne Router: jeder geht selbst zur Wolke.
            fw["uplinks"] = ({r: fw["uplink"]} if r else
                             {v: _uplink(inv, dev, v, overlay_re) for v in fw["vdoms"]})
        site["firewalls"] = list(site["firewalls"].values())
    site_list = sorted(by_site.values(), key=lambda s: (s["name"] == NO_SITE, s["name"].lower()))

    hosts = [h for n in chosen for h in n["hosts"]]
    no_switch = [n for n in chosen if not n["switches"]]
    if lldp is None:
        warnings.append("LibreNMS nicht verfügbar — Switches der Segmente nicht ermittelbar.")
    elif no_switch:
        warnings.append(f"{len(no_switch)} von {len(chosen)} Segmenten ohne Switch: kein per "
                        "LLDP an der Firewall hängender Switch führt das VLAN in LibreNMS ("
                        + ", ".join(f"VLAN {n['vlan']}" if n["vlan"] else n["cidr"]
                                    for n in no_switch[:5]) + ").")
    return {
        "title": f"Segmentplan {svc['name']}", "service": svc, "family": family["name"],
        "sites": site_list, "warnings": warnings,
        "stats": {"sites": len(site_list), "segments": len(chosen),
                  "firewalls": sum(len(s["firewalls"]) for s in site_list),
                  "switches": len({sw["id"] for n in chosen for sw in n["switches"]}),
                  "hosts": len(hosts),
                  "hosts_not_in_itop": sum(1 for h in hosts if not h["in_itop"]),
                  "hosts_not_in_service": sum(1 for h in hosts
                                              if service_view._foreign(h, ips)),
                  "names_from_dns": resolved},
    }


# ── Zeichnung ─────────────────────────────────────────────────────────────────

GREEN, GREEN_DARK = "#1ba34a", "#127a35"
ORANGE, ORANGE_DARK = "#fbe5d6", "#d4762c"
RED = service_view.RED
HOSTS_PER_ROW = 6
SLOT_W, HOST_ICON, ROW_H = 120, 30, 84
STUB = 16                         # Leitung Busleiste → Host
BAR_H = 26
BAR_W = HOSTS_PER_ROW * SLOT_W
SW_W, SW_H, SW_SLOT = 40, 28, 170
SW_AREA = 58
SW_MAX = 4
HOST_MAX = 48
SEG_GAP = 22
SITE_HEAD, PAD = 32, 20
PILL_W, PILL_H, PILL_GAP = 130, 30, 14
FW_ICON = 46
FW_COL = 104                     # linke Spalte: Symbol, darunter der Name
FW_HEAD = 14
ROW_GAP = 34                      # zwischen Segment- und Router-VDOM-Reihe
CLOUD_W, CLOUD_H = 280, 120
CLOUD_GAP = 90
SITE_GAP = 70
LEGEND_W, LEGEND_H = 340, 112

STYLE = {
    "site": "swimlane;html=1;startSize=32;fontStyle=1;fontSize=16;fontColor=#555555;"
            "fillColor=none;strokeColor=#999999;dashed=1;rounded=1;arcSize=2;"
            "align=left;spacingLeft=10;swimlaneLine=0;",
    "bar": f"rounded=1;arcSize=50;html=1;fillColor={GREEN};strokeColor={GREEN_DARK};"
           "fontColor=#ffffff;fontSize=11;align=left;spacingLeft=12;whiteSpace=nowrap;",
    "bar-off": "rounded=1;arcSize=50;html=1;fillColor=#bbbbbb;strokeColor=#888888;"
               "fontColor=#ffffff;fontSize=11;align=left;spacingLeft=12;dashed=1;",
    "stub": f"endArrow=none;html=1;strokeColor={GREEN};strokeWidth=2;",
    "host": "shape={stencil};html=1;aspect=fixed;{paint}verticalLabelPosition=bottom;"
            f"verticalAlign=top;fontSize=9;whiteSpace=wrap;labelWidth={SLOT_W - 8};",
    "switch": "shape={stencil};html=1;aspect=fixed;{paint}labelPosition=right;"
              "verticalLabelPosition=middle;align=left;verticalAlign=middle;spacingLeft=4;"
              "fontSize=9;whiteSpace=nowrap;",
    "outline": f"rounded=1;arcSize=10;html=1;fillColor=none;strokeColor={RED};strokeWidth=2;"
               "dashed=1;",
    "more": "text;html=1;fontSize=10;fontStyle=2;align=left;verticalAlign=middle;",
    "fw": f"rounded=1;arcSize=6;html=1;fillColor={ORANGE};strokeColor={ORANGE_DARK};"
          "strokeWidth=2;",
    "fw-name": "text;html=1;align=center;verticalAlign=top;fontSize=10;whiteSpace=wrap;",
    "fw-icon": drawio.icon_style("firewall"),
    "pill": f"rounded=1;arcSize=40;html=1;fillColor=#ffffff;strokeColor={ORANGE_DARK};"
            "fontSize=10;whiteSpace=wrap;",
    "pill-router": f"rounded=1;arcSize=40;html=1;fillColor={ORANGE_DARK};strokeColor={ORANGE_DARK};"
                   "fontColor=#ffffff;fontStyle=1;fontSize=10;whiteSpace=wrap;",
    "link": "edgeStyle=orthogonalEdgeStyle;rounded=1;html=1;endArrow=none;fontSize=9;"
            "labelBackgroundColor=#ffffff;strokeWidth=2;",
    "cloud": f"ellipse;shape=cloud;html=1;whiteSpace=wrap;fillColor={GREEN};"
             f"strokeColor={GREEN_DARK};fontColor=#ffffff;fontStyle=1;fontSize=16;",
    "legend": service_view.STYLE["legend"],
}


def _host_cell(h: dict, ips: set[str]) -> tuple[str, str]:
    stencil, paint = drawio.SHAPES[drawio.host_shape(h)]
    style = STYLE["host"].format(stencil=stencil, paint=paint)
    if not h.get("in_itop"):
        style += f"fontColor={RED};"
    elif service_view._foreign(h, ips):
        style = re.sub(r"fillColor=#[0-9A-Fa-f]{6};", f"fillColor={RED};", style)
        style += f"fontColor={RED};fontStyle=1;"
    name = h.get("name") or ""
    label = (f"<b>{esc(name)}</b><br>{esc(h['ip'])}" if name else esc(h["ip"]))
    return label, style


def _visible_hosts(net: dict, ips: set[str], hide_not_in_itop: bool,
                   hide_not_in_service: bool) -> list[dict]:
    return [h for h in net["hosts"]
            if not (hide_not_in_itop and not h.get("in_itop"))
            and not (hide_not_in_service and service_view._foreign(h, ips))]


def _seg_height(n_hosts: int, has_switches: bool) -> float:
    shown = min(n_hosts, HOST_MAX) + (1 if n_hosts > HOST_MAX else 0)
    rows = math.ceil(shown / HOSTS_PER_ROW)
    return (SW_AREA if has_switches else 10) + BAR_H + (STUB + rows * ROW_H if rows else 12)


def _fw_size(fw: dict) -> tuple[float, float]:
    seg_vdoms = [v for v in fw["vdoms"] if v != fw["router"]]
    n = max(1, len(seg_vdoms))
    w = FW_COL + n * (PILL_W + PILL_GAP)
    rows = (1 if seg_vdoms else 0) + (1 if fw["router"] else 0)
    h = FW_HEAD + rows * PILL_H + (rows - 1) * ROW_GAP + 14
    return max(w, FW_COL + PILL_W + PILL_GAP), max(h, FW_ICON + 56)


def _bar_label(net: dict, n_hosts: int) -> str:
    head = " · ".join(p for p in (
        f"VLAN {net['vlan']}" if net.get("vlan") is not None else None,
        net.get("alias") or net.get("itop_name") or net.get("description") or net["interface"],
    ) if p)
    state = "" if net.get("enabled", True) else " · abgeschaltet"
    return (f"<b>{esc(head.upper())}</b>{esc(state)}&nbsp;&nbsp;&nbsp;"
            f"{esc(net['cidr'])} · GW {esc(net['fw_ip'])} · {n_hosts} Hosts")


class _Site:
    """Ein Standort-Kasten: Maße zuerst, gezeichnet wird danach."""

    def __init__(self, site: dict, ips: set[str], hide_itop: bool, hide_svc: bool,
                 facing_down: bool) -> None:
        self.site = site
        self.down = facing_down          # Firewalls unten (obere Reihe) oder oben
        self.hosts = [_visible_hosts(n, ips, hide_itop, hide_svc) for n in site["segments"]]
        self.seg_h = [_seg_height(len(h), bool(n["switches"]))
                      for h, n in zip(self.hosts, site["segments"])]
        n = len(site["segments"])
        self.lane_w = 24 + 10 * n
        self.fw_sizes = [_fw_size(fw) for fw in site["firewalls"]]
        fws_w = sum(w for w, _ in self.fw_sizes) + PILL_GAP * (len(self.fw_sizes) - 1)
        self.fw_h = max(h for _, h in self.fw_sizes)
        self.turn_gap = 24 + 6 * n
        self.w = self.lane_w + max(BAR_W, fws_w) + PAD
        self.h = (SITE_HEAD + PAD + sum(self.seg_h) + SEG_GAP * (n - 1)
                  + self.turn_gap + self.fw_h + PAD)


def _draw_site(doc: Doc, s: _Site, x: float, y: float, ips: set[str]) -> list[tuple[str, str]]:
    """Zeichnet den Standort; gibt (Zell-ID, Uplink-Text) der zur Wolke gehenden
    VDOMs zurück."""
    site = s.site
    box = doc.vertex(esc(site["name"]), STYLE["site"], x, y, s.w, s.h,
                     tooltip=f"Standort {site['name']} · {len(site['segments'])} Segmente")
    segs_total = sum(s.seg_h) + SEG_GAP * (len(s.seg_h) - 1)
    if s.down:
        seg_y0 = SITE_HEAD + PAD
        fw_y = seg_y0 + segs_total + s.turn_gap
    else:
        fw_y = SITE_HEAD + PAD
        seg_y0 = fw_y + s.fw_h + s.turn_gap

    # Firewalls: Segment-VDOMs in der Reihe weg von der Wolke, Router-VDOM zur Wolke hin.
    pills: dict[tuple[str, str], tuple[str, float, float]] = {}   # (dev, vdom) → id, cx, edge-y
    out: list[tuple[str, str]] = []
    fx = s.lane_w
    for fw, (fw_w, fw_h) in zip(site["firewalls"], s.fw_sizes):
        fy = fw_y + (s.fw_h - fw_h if not s.down else 0)
        label = f"<b>{esc(fw['device'])}</b>"
        if fw.get("ha"):
            label += f" <span style='color:#3d6ea8'>HA {esc(fw['ha'].get('mode') or '')}</span>"
        fid = doc.vertex("", STYLE["fw"], fx, fy, fw_w, fw_h, parent=box,
                         tooltip=f"FortiGate {fw['device']}")
        doc.vertex("", STYLE["fw-icon"], (FW_COL - FW_ICON) / 2, 8, FW_ICON, FW_ICON, parent=fid)
        doc.vertex(label, STYLE["fw-name"], 4, FW_ICON + 10, FW_COL - 8, fw_h - FW_ICON - 14,
                   parent=fid)
        seg_vdoms = [v for v in fw["vdoms"] if v != fw["router"]]
        rows = ([("seg", seg_vdoms)] if seg_vdoms else []) + \
               ([("router", [fw["router"]])] if fw["router"] else [])
        if not s.down:
            rows.reverse()
        py = FW_HEAD
        for kind, vdoms in rows:
            for i, v in enumerate(vdoms):
                px = FW_COL + i * (PILL_W + PILL_GAP)
                router = kind == "router"
                pid = doc.vertex(esc(f"VDOM {v}") + ("<br><span style='font-size:8px'>Router"
                                                     "</span>" if router else ""),
                                 STYLE["pill-router" if router else "pill"], px, py, PILL_W,
                                 PILL_H, parent=fid, tooltip=f"{fw['device']} · VDOM {v}")
                pills[(fw["device"], v)] = (pid, fx + px + PILL_W / 2,
                                            fy if s.down else fy + fw_h)
            py += PILL_H + ROW_GAP
        # Inter-VDOM: Segment-VDOM → Router-VDOM.
        for v, text in fw["links"].items():
            src, dst = pills[(fw["device"], v)][0], pills[(fw["device"], fw["router"])][0]
            doc.edge(src, dst, esc(text), STYLE["link"] + "strokeColor=#888888;dashed=1;"
                     + ("exitX=0.5;exitY=1;entryX=0.5;entryY=0;" if s.down
                        else "exitX=0.5;exitY=0;entryX=0.5;entryY=1;"), parent=box)
        for v, text in fw["uplinks"].items():
            out.append((pills[(fw["device"], v)][0], text))
        fx += fw_w + PILL_GAP

    # Segmente: Switches über der Leiste, Hosts darunter, Leitung links zur Firewall.
    sy = seg_y0
    for i, (net, hosts, h) in enumerate(zip(site["segments"], s.hosts, s.seg_h)):
        bar_y = sy + (SW_AREA if net["switches"] else 10)
        bar = doc.vertex(_bar_label(net, len(hosts)),
                         STYLE["bar" if net.get("enabled", True) else "bar-off"],
                         s.lane_w, bar_y, BAR_W, BAR_H, parent=box,
                         tooltip=drawio._net_tooltip(dict(net, host_count=len(hosts)))
                         + f"\nFirewall: {net['fw_id']}")
        for j, sw in enumerate(net["switches"][:SW_MAX]):
            label = esc(sw["name"]) + (f"<br><span style='color:#777'>{esc(sw['ip'])}</span>"
                                       if sw.get("ip") else "")
            if j == SW_MAX - 1 and len(net["switches"]) > SW_MAX:
                label += f"<br><i>+{len(net['switches']) - SW_MAX} weitere</i>"
            stencil, paint = drawio.SHAPES["switch"]
            sid = doc.vertex(label, STYLE["switch"].format(stencil=stencil, paint=paint),
                             s.lane_w + 16 + j * SW_SLOT, bar_y - SW_AREA + 10, SW_W, SW_H,
                             parent=box, tooltip="\n".join(p for p in (
                                 f"Switch {sw['name']}", sw.get("hardware"),
                                 "hängt per LLDP direkt an der Firewall" if sw.get("uplink")
                                 else "per LLDP hinter der Firewall", f"führt VLAN {net['vlan']}"
                                 if net.get("vlan") else None) if p))
            cx = (16 + j * SW_SLOT + SW_W / 2) / BAR_W
            doc.edge(sid, bar, "", STYLE["stub"] + f"exitX=0.5;exitY=1;entryX={cx:.3f};entryY=0;",
                     parent=box)
        for k, host in enumerate(hosts[:HOST_MAX]):
            r, c = divmod(k, HOSTS_PER_ROW)
            hx = s.lane_w + c * SLOT_W + (SLOT_W - HOST_ICON) / 2
            hy = bar_y + BAR_H + STUB + r * ROW_H
            tip = service_view._host_tooltip(host, ips)
            if not host.get("in_itop"):
                doc.vertex("", STYLE["outline"], s.lane_w + c * SLOT_W + 4, hy - 4, SLOT_W - 8,
                           ROW_H - 8, parent=box, tooltip=tip)
            label, style = _host_cell(host, ips)
            hid = doc.vertex(label, style, hx, hy, HOST_ICON, HOST_ICON, parent=box, tooltip=tip)
            if r == 0:
                doc.edge(bar, hid, "", STYLE["stub"]
                         + f"exitX={(c * SLOT_W + SLOT_W / 2) / BAR_W:.3f};exitY=1;"
                         "entryX=0.5;entryY=0;", parent=box)
        if len(hosts) > HOST_MAX:
            k = HOST_MAX
            r, c = divmod(k, HOSTS_PER_ROW)
            doc.vertex(esc(f"… +{len(hosts) - HOST_MAX} weitere"), STYLE["more"],
                       s.lane_w + c * SLOT_W + 8, bar_y + BAR_H + STUB + r * ROW_H, SLOT_W * 2, 30,
                       parent=box)
        # Leitung links an der Leiste vorbei zur Firewall. Jede Leitung hat
        # ihre eigene Spur, damit sie sich nicht decken.
        pid, pcx, pedge = pills[(net["device"], net["vdom"])]
        lane_x = 12 + i * 10
        turn = (pedge - 10 - i * 6) if s.down else (pedge + 10 + i * 6)
        vlan = f" · VLAN {net['vlan']}" if net.get("vlan") is not None else " · routed"
        doc.edge(bar, pid, esc(net["interface"] + vlan),
                 STYLE["link"] + f"strokeColor={GREEN};exitX=0;exitY=0.5;entryX=0.5;"
                 + ("entryY=0;" if s.down else "entryY=1;"),
                 parent=box, points=[(lane_x, bar_y + BAR_H / 2), (lane_x, turn), (pcx, turn)])
        sy += h + SEG_GAP
    return out


def render(mdl: dict, title_block: dict | None = None, hide_not_in_itop: bool = False,
           hide_not_in_service: bool = False) -> str:
    """Obere Reihe Standorte mit den Firewalls unten, Wolke in der Mitte,
    untere Reihe gespiegelt. Ein Standort allein steht über der Wolke."""
    doc = Doc(mdl["title"])
    ips = set(mdl["service"]["ips"])
    sites = mdl["sites"]
    half = math.ceil(len(sites) / 2) if len(sites) > 1 else len(sites)
    top = [_Site(s, ips, hide_not_in_itop, hide_not_in_service, True) for s in sites[:half]]
    bottom = [_Site(s, ips, hide_not_in_itop, hide_not_in_service, False) for s in sites[half:]]

    def row_w(row: list[_Site]) -> float:
        return sum(s.w for s in row) + SITE_GAP * max(0, len(row) - 1)

    x0, y0 = 40, 40
    width = max(row_w(top), row_w(bottom), CLOUD_W)
    top_h = max((s.h for s in top), default=0)
    uplinks: list[tuple[str, str, bool]] = []      # (VDOM-Zelle, Text, Wolke liegt darunter)
    x = x0 + (width - row_w(top)) / 2
    for s in top:
        uplinks += [(pid, t, True) for pid, t in _draw_site(doc, s, x, y0 + top_h - s.h, ips)]
        x += s.w + SITE_GAP
    cloud_y = y0 + top_h + CLOUD_GAP
    cloud = doc.vertex("SD-WAN", STYLE["cloud"], x0 + (width - CLOUD_W) / 2, cloud_y,
                       CLOUD_W, CLOUD_H, tooltip="Standortkopplung über das SD-WAN")
    x = x0 + (width - row_w(bottom)) / 2
    for s in bottom:
        uplinks += [(pid, t, False) for pid, t in _draw_site(
            doc, s, x, cloud_y + CLOUD_H + CLOUD_GAP, ips)]
        x += s.w + SITE_GAP
    for pid, text, down in uplinks:
        doc.edge(pid, cloud, esc(text), STYLE["link"] + "strokeColor=#d4762c;"
                 + ("exitX=0.5;exitY=1;" if down else "exitX=0.5;exitY=0;"))

    lx = x0 + width + 2 * SITE_GAP
    svc = mdl["service"]
    lines = [f"<b>{esc(mdl['title'])}</b>",
             f"Servicefamilie {esc(mdl['family'])} · {len(mdl['sites'])} Standorte",
             f"<span style='color:{GREEN};font-weight:bold'>▬ grün</span> = Netzsegment (VLAN) "
             "mit Switches darüber und Hosts darunter",
             "Leitung Segment → Firewall: Interface · VLAN; orange = Kopplung zum SD-WAN",
             (f"<span style='color:{RED};font-weight:bold'>■ rot</span> = im iTop, aber nicht "
              f"am Service {esc(svc['name'])}") if not hide_not_in_service
             else "ausgeblendet: Hosts, die nicht am Service hängen",
             (f"<span style='color:{RED}'>□ rot umrandet</span> = nicht im iTop geführt")
             if not hide_not_in_itop else "ausgeblendet: Hosts, die nicht im iTop stehen"]
    doc.vertex("<br>".join(lines), STYLE["legend"], lx, y0, LEGEND_W, LEGEND_H)
    if title_block:
        titleblock.draw(doc, lx, y0 + LEGEND_H + SITE_GAP / 2, title_block)
    return doc.to_xml()
