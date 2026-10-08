"""Service-Ansicht: Servicefamilie → Service → VLAN → Hosts, je Familie eine Seite.

Die Kette kommt vollständig aus Daten, die ohnehin gepflegt sind:

    ServiceFamily → Service → CI (lnkFunctionalCIToService) → Management-IP
        → Netz an der Firewall (FMG-Inventar, längster Präfix) → alle Hosts darin

An einem Service trägt niemand ein Netz ein. Das Netz ergibt sich aus der IP
des CIs, und gezeichnet wird dann das GANZE Netz — mit allem, was iTop, der
FortiManager, die ARP-Historie und das Reverse-DNS darin kennen. Genau dort
liegt die Auskunft der Zeichnung: Hosts, die nur aus FortiManager, ARP oder
DNS bekannt sind, stehen nicht im iTop und werden rot markiert.

Über jedem VLAN-Kasten führt eine Linie zur Firewall, die das Netz terminiert.
"""
from __future__ import annotations

import ipaddress
import re
from collections.abc import Awaitable, Callable

from diagram import drawio, model as diagram_model, titleblock
from diagram.mx import Doc, esc
from inventory.store import Inventory

NO_FAMILY = "ohne Servicefamilie"
ITOP_SOURCES = {"itop-ci", "itop-ip"}

AddrLookup = Callable[[list[str]], Awaitable[dict[str, dict]]]


# ── Modell ────────────────────────────────────────────────────────────────────

def _network_index(inv: Inventory, itop_subnets: list[dict]) -> list[tuple]:
    """(Netz, Netz-Dict) aller Firewall-Interfaces — Grundlage der Zuordnung
    CI-IP → VLAN. /31 und /32 sind Transfer- und Loopback-Adressen, kein VLAN."""
    out = []
    for d, v in diagram_model.all_vdoms(inv):
        for net in diagram_model._networks(inv, d, v, itop_subnets):
            cidr = ipaddress.IPv4Network(net["cidr"])
            if cidr.prefixlen >= 31:
                continue
            net.update(device=d, vdom=v, fw_id=diagram_model.vdom_key(d, v))
            out.append((cidr, net))
    return out


def _place(ip: str, index: list[tuple]) -> tuple[dict | None, int]:
    """Längster Präfix; bei Gleichstand gewinnt das eingeschaltete Interface.
    Zweiter Wert: wie viele gleich gute Treffer es gab (>1 = mehrdeutig)."""
    try:
        addr = ipaddress.IPv4Address(ip)
    except ValueError:
        return None, 0
    hits = [(c, n) for c, n in index if addr in c]
    if not hits:
        return None, 0
    best = max(c.prefixlen for c, _ in hits)
    top = [n for c, n in hits if c.prefixlen == best]
    top.sort(key=lambda n: (not n["enabled"], n["fw_id"], n["interface"]))
    return top[0], len({n["fw_id"] for n in top})


def _wanted(families: list[dict], services: list[dict], family: str | None) -> list[dict]:
    """Familien in Anzeigereihenfolge, auf eine eingeschränkt, wenn gewünscht.
    Services ohne Familie landen in einer eigenen Gruppe statt zu verschwinden."""
    by_id = {f["id"]: dict(f, services=[]) for f in families}
    for s in services:
        fam = by_id.get(s["family_id"])
        if fam is None:
            fam = by_id.setdefault("0", {"id": "0", "name": NO_FAMILY, "services": []})
        fam["services"].append(s)
    out = sorted(by_id.values(), key=lambda f: (f["id"] == "0", f["name"].lower()))
    if family:
        needle = family.strip().lower()
        out = [f for f in out if f["id"] == family or f["name"].lower() == needle]
    return out


async def build(inv: Inventory, *, families: list[dict], services: list[dict],
                links: list[dict], itop_hosts: list[dict], itop_subnets: list[dict],
                addresses: AddrLookup | None = None,
                arp: diagram_model.ArpLookup | None = None,
                dns: diagram_model.DnsLookup | None = None,
                librenms_devices: dict[str, dict] | None = None,
                family: str | None = None) -> dict:
    wanted = _wanted(families, services, family)
    if family and not wanted:
        raise ValueError(f"Servicefamilie '{family}' gibt es im iTop nicht.")
    index = _network_index(inv, itop_subnets)
    ci_ip = {h["id"]: h for h in itop_hosts if h.get("id")}
    ci_by_name = {h["name"].lower(): h for h in itop_hosts}
    links_of: dict[str, list[dict]] = {}
    for ln in links:
        links_of.setdefault(ln["service_id"], []).append(ln)

    warnings: list[str] = []
    nets: dict[str, dict] = {}
    for fam in wanted:
        fam["firewalls"] = []
        for svc in fam["services"]:
            svc["networks"], svc["ips"], svc["unplaced"] = [], [], []
            cis = links_of.get(svc["id"], [])
            svc["ci_count"] = len(cis)
            for ln in cis:
                host = ci_ip.get(ln["ci_id"]) or ci_by_name.get(ln["ci_name"].lower())
                if host is None:
                    svc["unplaced"].append({"name": ln["ci_name"], "reason": "ohne Management-IP"})
                    continue
                net, n_hits = _place(host["ip"], index)
                if net is None:
                    svc["unplaced"].append({"name": ln["ci_name"], "ip": host["ip"],
                                            "reason": "IP in keinem Firewall-Netz"})
                    continue
                if n_hits > 1:
                    warnings.append(f"{host['ip']} ({ln['ci_name']}) liegt in einem Netz, das "
                                    f"{n_hits} Firewalls führen — gezeichnet an {net['fw_id']}.")
                svc["ips"].append(host["ip"])
                nets.setdefault(net["id"], net)
                if net["id"] not in svc["networks"]:
                    svc["networks"].append(net["id"])
                if net["fw_id"] not in fam["firewalls"]:
                    fam["firewalls"].append(net["fw_id"])

    # Hosts je Netz einmal einsammeln, auch wenn mehrere Services es teilen.
    itop_addresses = await addresses([n["cidr"] for n in nets.values()]) if addresses and nets else {}
    for net in nets.values():
        net["hosts"] = await diagram_model._collect_hosts(
            net, inv, itop_hosts, itop_addresses, arp, librenms_devices or {})
    resolved = await diagram_model._resolve_names(list(nets.values()), dns, [diagram_model.DNS_MAX])
    for net in nets.values():
        net["host_count"] = len(net["hosts"])
        for h in net["hosts"]:
            h["in_itop"] = bool(ITOP_SOURCES & set(h.get("sources") or []))
        net["vlan_sort"] = (net["vlan"] is None, net["vlan"] or 0, net["cidr"])
    for fam in wanted:
        for svc in fam["services"]:
            svc["networks"].sort(key=lambda nid: nets[nid]["vlan_sort"])

    firewalls = {}
    for fw_id in {f for fam in wanted for f in fam["firewalls"]}:
        d, _, v = fw_id.partition("/")
        firewalls[fw_id] = {"id": fw_id, "device": d, "vdom": v,
                            "vdoms": len((inv.devices.get(d) or {}).get("vdoms") or ["root"]),
                            "ha": (inv.devices.get(d) or {}).get("ha")}

    hosts = [h for n in nets.values() for h in n["hosts"]]
    title = (f"Services {wanted[0]['name']}" if family and wanted else "Services nach Servicefamilie")
    return {
        "title": title, "families": wanted, "networks": nets, "firewalls": firewalls,
        "warnings": warnings,
        "stats": {"families": len(wanted),
                  "services": sum(len(f["services"]) for f in wanted),
                  "networks": len(nets), "firewalls": len(firewalls),
                  "hosts": len(hosts),
                  "hosts_not_in_itop": sum(1 for h in hosts if not h["in_itop"]),
                  "cis_unplaced": sum(len(s["unplaced"]) for f in wanted for s in f["services"]),
                  "names_from_dns": resolved},
    }


# ── Zeichnung ─────────────────────────────────────────────────────────────────

NET_COLS = 4
PAD, GAP = 24, 24
FAM_HEAD, SVC_HEAD = 40, 32
FW_W, FW_H, FW_SLOT, FW_TOP = 56, 48, 230, 12
# Linienführung: vom Netz-Kasten nach rechts in die Lücke zur nächsten Spalte,
# dort senkrecht nach oben bis in den Firewall-Streifen, waagerecht zur
# Firewall und von unten hinein. Die Lücken liegen in allen Services an
# derselben Stelle, also läuft keine Linie durch einen Kasten. Linien zur
# selben Firewall decken sich und lesen sich wie eine Sammelschiene.
LANE_IN, LANE_STEP = 6, 5        # Abstand der Senkrechten vom Kasten, je Firewall versetzt
BUS_GAP, BUS_STEP = 14, 8        # Waagerechte unter den Firewalls, je Firewall versetzt
EMPTY_H = 44
LEGEND_W, LEGEND_H = 300, 92
RED = "#e51400"

STYLE = {
    "family": "swimlane;html=1;startSize=40;fontStyle=1;fontSize=16;fillColor=#f5f5f5;"
              "strokeColor=#333333;align=left;spacingLeft=10;",
    "service": "swimlane;html=1;startSize=32;fontStyle=1;fontSize=13;fillColor=#ffffff;"
               "strokeColor=#333333;align=left;spacingLeft=8;swimlaneFillColor=#ffffff;",
    "empty": "text;html=1;fontSize=10;fontStyle=2;fontColor=#7a5c00;align=left;"
             "verticalAlign=top;spacingLeft=4;whiteSpace=wrap;",
    "edge": "edgeStyle=orthogonalEdgeStyle;rounded=0;html=1;endArrow=block;endFill=1;"
            "strokeColor=#666666;exitX=1;exitY={exit_y:.4f};exitDx=0;exitDy=0;"
            "entryX=0.5;entryY=1;entryDx=0;entryDy=0;",
    "firewall": drawio.icon_style("firewall").replace(
        "verticalLabelPosition=bottom;verticalAlign=top;",
        "labelPosition=right;verticalLabelPosition=middle;align=left;verticalAlign=middle;"
        "spacingLeft=4;"),
    "legend": "rounded=0;html=1;whiteSpace=wrap;align=left;verticalAlign=top;fontSize=10;"
              "spacingLeft=8;spacingTop=4;fillColor=#ffffff;strokeColor=#999999;",
}


def _host_style(h: dict) -> str:
    style = drawio.host_style(h)
    if h.get("in_itop"):
        return style
    # Rot heißt: im Netz gesehen, im iTop nicht geführt. Symbol UND Schrift,
    # damit es auch im Schwarz-Weiß-Ausdruck am fetten Namen auffällt.
    style = re.sub(r"fillColor=#[0-9A-Fa-f]{6};", f"fillColor={RED};", style)
    return style + f"fontColor={RED};fontStyle=1;"


def _host_tooltip(h: dict, service_ips: set[str]) -> str:
    tip = drawio._host_tooltip(h)
    if not h.get("in_itop"):
        return "NICHT IM iTOP – nur bekannt aus " + ", ".join(h.get("sources") or ["?"]) + "\n" + tip
    if h["ip"] in service_ips:
        return "CI dieses Service\n" + tip
    return tip


def _net_size(net: dict) -> tuple[float, float]:
    return drawio.NET_W, drawio._net_height(net)[0]


def _fw_label(fw: dict) -> str:
    name = f"<b>{esc(fw['device'])}</b>"
    if fw["vdoms"] > 1 or fw["vdom"] != "root":
        name += f"<br>VDOM {esc(fw['vdom'])}"
    if fw.get("ha"):
        name += f"<br><span style='color:#3d6ea8'>HA {esc(fw['ha'].get('mode') or '')}</span>"
    return name


def _unplaced_height(svc: dict) -> float:
    """Die Liste steht in EINER Spaltenbreite — die Linien zur Firewall laufen
    rechts daneben durch die Lücke, nicht durch den Text. Lange Zeilen brechen um."""
    if not svc["unplaced"]:
        return 0
    lines = 1 + sum(1 + len(f"{u['name']} {u.get('ip') or ''} {u['reason']}") // 40
                    for u in svc["unplaced"])
    return lines * 14 + 12


def _measure_service(svc: dict, nets: dict) -> tuple[float, float, list]:
    sizes = [_net_size(nets[nid]) for nid in svc["networks"]]
    pos, w, h = drawio._pack(sizes, NET_COLS, GAP)
    unplaced_h = _unplaced_height(svc)
    if not sizes:
        h = EMPTY_H + unplaced_h
        w = max(w, 2 * drawio.NET_W)
    else:
        h += (unplaced_h + GAP if unplaced_h else 0)
    return w + 2 * PAD, SVC_HEAD + PAD + h + PAD, pos


def _unplaced_text(svc: dict) -> str:
    lines = [f"{len(svc['unplaced'])} CI(s) ohne Netz:"]
    for u in svc["unplaced"]:
        ip = f" {u['ip']}" if u.get("ip") else ""
        lines.append(f"• {esc(u['name'])}{esc(ip)} – {esc(u['reason'])}")
    return "<br>".join(lines)


def _fw_band(n: int) -> float:
    return FW_TOP + FW_H + BUS_GAP + n * BUS_STEP + BUS_GAP if n else 0


def _net_label(net: dict, show_firewalls: bool) -> str:
    label = drawio._net_label(net)
    # Ohne Firewall-Symbole steht die terminierende Firewall im Kasten selbst —
    # in der dritten Zeile, der Kopf hat nur Platz für drei.
    return label if show_firewalls else label + f" · an {esc(net['fw_id'])}"


def _draw_family(doc: Doc, fam: dict, mdl: dict, title_block: dict | None,
                 show_firewalls: bool = True) -> None:
    nets, fws = mdl["networks"], mdl["firewalls"]
    fw_ids = sorted(fam["firewalls"]) if show_firewalls else []
    band = _fw_band(len(fw_ids))
    measured = [_measure_service(s, nets) for s in fam["services"]]
    inner_w = max([m[0] for m in measured] + [len(fw_ids) * FW_SLOT, 2 * drawio.NET_W])
    fam_h = FAM_HEAD + band + sum(m[1] + GAP for m in measured) + PAD
    x0, y0 = 40, 40
    fam_w = inner_w + 2 * PAD
    tip = f"Servicefamilie {fam['name']} · {len(fam['services'])} Services"
    fam_id = doc.vertex(esc(fam["name"]), STYLE["family"], x0, y0, fam_w, fam_h, tooltip=tip)

    # Firewalls oben in der Familie, über den Services; Beschriftung rechts
    # neben dem Symbol, damit die Linie von unten frei hineinläuft.
    fw_cell: dict[str, tuple[str, float, int]] = {}      # id → (Zelle, Mitte x, Index)
    start = PAD + (inner_w - len(fw_ids) * FW_SLOT) / 2
    for i, fw_id in enumerate(fw_ids):
        fw = fws[fw_id]
        fx = start + i * FW_SLOT
        cell = doc.vertex(_fw_label(fw), STYLE["firewall"], fx, FAM_HEAD + FW_TOP, FW_W, FW_H,
                          parent=fam_id, tooltip=f"FortiGate {fw['device']} · VDOM {fw['vdom']}")
        fw_cell[fw_id] = (cell, fx + FW_W / 2, i)
    bus_top = FAM_HEAD + FW_TOP + FW_H + BUS_GAP

    y = FAM_HEAD + band
    for svc, (w, h, pos) in zip(fam["services"], measured):
        stip = "\n".join(p for p in (
            f"Service {svc['name']}", svc.get("description") or None,
            f"{svc['ci_count']} CIs am Service, {len(svc['networks'])} Netze",
            f"Status: {svc['status']}" if svc.get("status") else None) if p)
        svc_id = doc.vertex(esc(svc["name"]), STYLE["service"], PAD, y, inner_w, h,
                            parent=fam_id, tooltip=stip)
        ips = set(svc["ips"])
        bottom = SVC_HEAD + PAD
        for nid, (px, py) in zip(svc["networks"], pos):
            net = nets[nid]
            nw, nh = _net_size(net)
            net_id = doc.vertex(_net_label(net, show_firewalls), drawio.STYLE["net"], PAD + px,
                                SVC_HEAD + PAD + py, nw, nh, parent=svc_id,
                                tooltip=drawio._net_tooltip(net) + f"\nFirewall: {net['fw_id']}")
            bottom = max(bottom, SVC_HEAD + PAD + py + nh)
            hy = drawio.NET_HEAD + 4
            for host in net["hosts"][:drawio.HOST_MAX_ROWS]:
                doc.vertex(drawio._host_label(host), _host_style(host), 12,
                           hy + (drawio.HOST_H - drawio.ICON) // 2, drawio.ICON, drawio.ICON,
                           parent=net_id, tooltip=_host_tooltip(host, ips))
                hy += drawio.HOST_H + 4
            if len(net["hosts"]) > drawio.HOST_MAX_ROWS:
                doc.vertex(esc(f"… +{len(net['hosts']) - drawio.HOST_MAX_ROWS} weitere"),
                           drawio.STYLE["more"], 12, hy, drawio.HOST_W, drawio.HOST_H,
                           parent=net_id)
            if net["fw_id"] in fw_cell:
                cell, fw_x, i = fw_cell[net["fw_id"]]
                head_y = drawio.NET_HEAD / 2
                lane_x = PAD + PAD + px + nw + min(LANE_IN + i * LANE_STEP, GAP - 2)
                bus_y = bus_top + i * BUS_STEP
                doc.edge(net_id, cell, "", STYLE["edge"].format(exit_y=head_y / nh),
                         parent=fam_id,
                         points=[(lane_x, y + SVC_HEAD + PAD + py + head_y),
                                 (lane_x, bus_y), (fw_x, bus_y)])
        if not svc["networks"]:
            text = ("Keine CIs am Service." if not svc["ci_count"] else "")
            if svc["unplaced"]:
                text = _unplaced_text(svc)
            doc.vertex(text, STYLE["empty"], PAD, SVC_HEAD + 8, w - 2 * PAD, h - SVC_HEAD - 16,
                       parent=svc_id)
        elif svc["unplaced"]:
            doc.vertex(_unplaced_text(svc), STYLE["empty"], PAD, bottom + GAP / 2,
                       drawio.NET_W, _unplaced_height(svc), parent=svc_id)
        y += h + GAP

    # Legende und Schriftfeld rechts neben der Familie.
    lx = x0 + fam_w + 2 * GAP
    legend = (f"<b>Legende</b><br>"
              f"<span style='color:{RED};font-weight:bold'>■ rot</span> = im Netz gesehen, "
              "aber nicht im iTop geführt (nur FortiManager, ARP oder DNS)<br>"
              + ("Pfeil = Netz terminiert an dieser Firewall" if show_firewalls
                 else "„an …“ = Firewall/VDOM, an der das Netz terminiert"))
    doc.vertex(legend, STYLE["legend"], lx, y0, LEGEND_W, LEGEND_H)
    if title_block:
        titleblock.draw(doc, lx, max(y0 + LEGEND_H + GAP, y0 + fam_h - titleblock.HEIGHT),
                        title_block)


def render(mdl: dict, title_block: dict | None = None, show_firewalls: bool = True) -> str:
    """Eine Seite je Servicefamilie. show_firewalls=False lässt Firewall-Symbole
    und Linien weg; die Firewall steht dann als Zeile im Netz-Kasten."""
    fams = mdl["families"] or [{"id": "0", "name": "Keine Servicefamilien", "services": [],
                                "firewalls": []}]
    doc = Doc(fams[0]["name"])
    for i, fam in enumerate(fams):
        if i:
            doc.page(fam["name"])
        _draw_family(doc, fam, mdl, title_block, show_firewalls)
    return doc.to_xml()
