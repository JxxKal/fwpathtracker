"""draw.io-Renderer: Netzplan-Modell → mxGraph-XML (unkomprimierte .drawio-Datei).

Layout ist ein Schichtenmodell, das draw.io nicht selbst mitbringt — von
außen nach innen:
    Standort-Container (nur wenn der Scope mehrere Standorte zeigt)
      └ Firewall-Container
          └ VDOM-Container
              └ Netz-Kästen im Raster, darin die Hosts als Liste (einklappbar,
                ab HOST_COLLAPSE zugeklappt — der Plan bleibt lesbar, die Hosts
                sind trotzdem drin)
    rechts:  Nachbar-VDOMs, Internet/Default (die WAN-Seite)
    unter jeder Firewall: ihre Switches per LLDP
Gerechnet wird von innen nach außen: erst die Netz-Kästen, daraus die Größe
des VDOMs, daraus die der Firewall, daraus die des Standorts.

Jeder Knoten trägt einen Tooltip mit allem, was die Quellen wissen — die
Zeichnung ist damit gleichzeitig der Abgleich von FMG, iTop und LibreNMS.
"""
from __future__ import annotations

import html
import xml.etree.ElementTree as ET
from datetime import datetime, timezone

NET_W, NET_HEAD = 240, 48
HOST_H, HOST_W = 30, 216
ICON = 24                   # Host-Symbol (Label steht rechts daneben)
# Netze mit Hosts starten ZUGEKLAPPT. Beim Öffnen zählt zuerst die Struktur —
# welche Netze gibt es, wer hängt woran; die Hostliste holt man sich dann gezielt
# per Klick. Ein Netz ohne Hosts hat nichts zum Aufklappen und bleibt, wie es ist.
HOST_MAX_ROWS = 60          # mehr Zeilen zeichnet niemand mehr — Rest als "+N"
FWS_PER_ROW = 3
SITES_PER_ROW = 2
GAP = 24
VDOM_HEAD, FW_HEAD, SITE_HEAD = 30, 34, 36
VDOM_MIN_W = 200
NET_M, NET_SPACING = 12, 12      # Rand/Abstand der Netz-Kästen im VDOM
VDOM_M, VDOM_SPACING = 24, 24    # Rand/Abstand der VDOMs in der Firewall
DEV_ICON_H = 34                  # Firewall-Symbol über dem Container
SWITCH_W, SWITCH_H, SWITCH_ROW = 72, 40, 76
NEIGHBOR_W, NEIGHBOR_H = 200, 60

STYLE: dict[str, str] = {
    # childLayout=stackLayout: draw.io ordnet die Kinder selbst an und zieht den
    # Container mit. Deshalb schiebt ein aufgeklapptes Netz seine Nachbarn nach
    # unten, statt sie zu überdecken — und beim Zuklappen schrumpft alles wieder
    # (resizeParentMax=0). Genau dafür ist das Layout da; ohne es sind die
    # Positionen fest und jedes Aufklappen überschreibt, was darunter liegt.
    "fw": "swimlane;html=1;startSize=34;fontStyle=1;fontSize=14;fillColor=#dae8fc;"
          "strokeColor=#6c8ebf;childLayout=stackLayout;horizontalStack=1;resizeParent=1;"
          f"resizeParentMax=0;marginLeft={VDOM_M};marginRight={VDOM_M};marginTop={VDOM_M};"
          f"marginBottom={VDOM_M};stackSpacing={VDOM_SPACING};",
    "vdom": "swimlane;html=1;startSize=30;fontStyle=1;fontSize=12;fillColor=#f5f5f5;"
            "strokeColor=#666666;childLayout=stackLayout;horizontalStack=0;resizeParent=1;"
            f"resizeParentMax=0;marginLeft={NET_M};marginRight={NET_M};marginTop={NET_M};"
            f"marginBottom={NET_M};stackSpacing={NET_SPACING};",
    "site": "swimlane;html=1;startSize=36;fontStyle=1;fontSize=16;fillColor=#f0f0f0;"
            "strokeColor=#333333;dashed=1;",
    "net": "swimlane;html=1;startSize=48;fontSize=10;align=left;spacingLeft=6;"
           "fillColor=#d5e8d4;strokeColor=#82b366;collapsible=1;",
    # Symbole aus der draw.io-Bibliothek „Network" (mxgraph.networks.*) — sie
    # sind Teil der Web-App, funktionieren also auch in der Offline-Instanz.
    # Host-Zeile: kleines Symbol, Label rechts daneben.
    "host-base": "shape={stencil};html=1;aspect=fixed;{paint}"
                 "labelPosition=right;verticalLabelPosition=middle;align=left;"
                 "verticalAlign=middle;spacingLeft=4;fontSize=9;whiteSpace=nowrap;",
    "more": "text;html=1;fontSize=9;fontStyle=2;align=left;spacingLeft=4;",
    # Freistehende Symbole mit Label darunter (Nachbarn, Switches, Internet).
    "icon-base": "shape={stencil};html=1;aspect=fixed;{paint}"
                 "verticalLabelPosition=bottom;verticalAlign=top;fontSize=11;whiteSpace=wrap;",
    "edge": "edgeStyle=orthogonalEdgeStyle;rounded=0;html=1;endArrow=none;fontSize=9;"
            "labelBackgroundColor=#ffffff;",
    "edge-vdom-link": "strokeColor=#666666;dashed=1;",
    "edge-overlay": "strokeColor=#b85450;dashed=1;dashPattern=8 4;",
    "edge-transit": "strokeColor=#6c8ebf;",
    "edge-default": "strokeColor=#b85450;",
    "edge-switch": "strokeColor=#9673a6;",
}


def _esc(s) -> str:
    return html.escape(str(s if s is not None else ""), quote=False)


# Symbol → (Stencil, Malstil). Die Network-Bibliothek ist flächig (nur Füllung);
# der Cisco-Switch ist ein Linien-Piktogramm und braucht Füllung + weiße Linien.
SHAPES = {
    "firewall": ("mxgraph.networks.firewall", "fillColor=#b85450;strokeColor=none;"),
    "switch": ("mxgraph.cisco.switches.workgroup_switch",
               "fillColor=#9673a6;strokeColor=#ffffff;strokeWidth=1;"),
    "server": ("mxgraph.networks.server", "fillColor=#29AAE1;strokeColor=none;"),
    "pc": ("mxgraph.networks.pc", "fillColor=#6c8ebf;strokeColor=none;"),
    "cloud": ("mxgraph.networks.cloud", "fillColor=#b85450;strokeColor=none;"),
}


def host_shape(h: dict) -> str:
    """Symbol je Host: iTop-Klasse zuerst, dann die Beschreibung, sonst PC."""
    kind = (h.get("kind") or "").lower()
    if kind in ("networkdevice", "switch"):
        return "switch"
    if kind == "server":
        return "server"
    desc = (h.get("description") or "").lower()
    if any(k in desc for k in ("server", "srv", "vm", "host")):
        return "server"
    if any(k in desc for k in ("switch", "router", "firewall", "gateway", "ap ", "access point")):
        return "switch"
    return "pc"


def host_style(h: dict) -> str:
    stencil, paint = SHAPES[host_shape(h)]
    return STYLE["host-base"].format(stencil=stencil, paint=paint)


def icon_style(shape: str) -> str:
    stencil, paint = SHAPES[shape]
    return STYLE["icon-base"].format(stencil=stencil, paint=paint)


class _Doc:
    def __init__(self, name: str) -> None:
        self.mxfile = ET.Element("mxfile", host="A38", modified=datetime.now(timezone.utc).isoformat())
        diagram = ET.SubElement(self.mxfile, "diagram", name=name, id="a38-netplan")
        model = ET.SubElement(diagram, "mxGraphModel", grid="1", gridSize="10", guides="1",
                              tooltips="1", connect="1", arrows="1", fold="1", page="1",
                              pageScale="1", pageWidth="1654", pageHeight="1169")
        self.root = ET.SubElement(model, "root")
        ET.SubElement(self.root, "mxCell", id="0")
        ET.SubElement(self.root, "mxCell", id="1", parent="0")
        self._n = 1

    def _id(self) -> str:
        self._n += 1
        return f"c{self._n}"

    def vertex(self, label: str, style: str, x: float, y: float, w: float, h: float,
               parent: str = "1", tooltip: str | None = None, collapsed: bool = False,
               alt: tuple[float, float] | None = None) -> str:
        cid = self._id()
        obj = ET.SubElement(self.root, "object", id=cid, label=label)
        if tooltip:
            obj.set("tooltip", tooltip)
        cell = ET.SubElement(obj, "mxCell", style=style, vertex="1", parent=parent)
        if collapsed:
            cell.set("collapsed", "1")
        geo = ET.SubElement(cell, "mxGeometry", x=str(int(x)), y=str(int(y)),
                            width=str(int(w)), height=str(int(h)))
        geo.set("as", "geometry")
        if alt:
            r = ET.SubElement(geo, "mxRectangle", x=str(int(x)), y=str(int(y)),
                              width=str(int(alt[0])), height=str(int(alt[1])))
            r.set("as", "alternateBounds")
        return cid

    def edge(self, src: str, dst: str, label: str, kind: str, parent: str = "1") -> str:
        cid = self._id()
        style = STYLE["edge"] + STYLE.get(f"edge-{kind}", "")
        cell = ET.SubElement(self.root, "mxCell", id=cid, style=style, edge="1", parent=parent,
                             source=src, target=dst, value=label)
        geo = ET.SubElement(cell, "mxGeometry", relative="1")
        geo.set("as", "geometry")
        return cid

    def to_xml(self) -> str:
        return '<?xml version="1.0" encoding="UTF-8"?>\n' + ET.tostring(self.mxfile, encoding="unicode")


def _net_label(net: dict) -> str:
    head = " · ".join(p for p in (
        f"VLAN {net['vlan']}" if net.get("vlan") is not None else None,
        net.get("alias") or net.get("itop_name") or net.get("description"),
    ) if p)
    zone = net.get("zone")
    # Dritte Zeile trägt die Anzahl mit: am zugeklappten Kasten ist sie die
    # Information, ob sich das Aufklappen überhaupt lohnt.
    tail = net["interface"]
    if zone and zone != net["interface"]:
        tail += f" · Zone {zone}"
    if net.get("host_count"):
        tail += f" · {net['host_count']} Hosts"
    return (f"<b>{_esc(head or net['interface'])}</b><br>"
            f"{_esc(net['cidr'])} · GW {_esc(net['fw_ip'])}<br>{_esc(tail)}")


def _net_tooltip(net: dict) -> str:
    rows = [("Interface", net["interface"]), ("Netz", net["cidr"]), ("Firewall-IP", net["fw_ip"]),
            ("VLAN", net.get("vlan")), ("Zone", net.get("zone")), ("Alias", net.get("alias")),
            ("Beschreibung", net.get("description")), ("iTop-Subnetz", net.get("itop_name")),
            ("iTop-Gateway", net.get("itop_gateway")), ("Hosts", net.get("host_count"))]
    return "\n".join(f"{k}: {v}" for k, v in rows if v not in (None, "", 0))


def _host_label(h: dict) -> str:
    name = h.get("name") or ""
    return f"<b>{_esc(name)}</b> {_esc(h['ip'])}" if name else _esc(h["ip"])


def _host_tooltip(h: dict) -> str:
    rows = [("IP", h["ip"]), ("Name", h.get("name")), ("Typ", h.get("kind")),
            ("Beschreibung", h.get("description")), ("iTop-Status", h.get("itop_status")),
            ("MAC", h.get("mac")), ("Zuletzt gesehen", h.get("last_seen")),
            ("Quellen", ", ".join(h.get("sources") or []))]
    lnms = h.get("librenms") or {}
    if lnms:
        rows.append(("LibreNMS", " ".join(str(v) for v in (lnms.get("hostname"), lnms.get("hardware")) if v)))
    return "\n".join(f"{k}: {v}" for k, v in rows if v not in (None, ""))


def _net_height(net: dict) -> tuple[float, float]:
    """(volle Höhe, zugeklappte Höhe) eines Netz-Kastens."""
    n = min(len(net["hosts"]), HOST_MAX_ROWS) + (1 if len(net["hosts"]) > HOST_MAX_ROWS else 0)
    return NET_HEAD + (n * (HOST_H + 4) + 8 if n else 6), NET_HEAD


def _pack(sizes: list[tuple[float, float]], cols: int,
          gap: int = GAP) -> tuple[list[tuple[float, float]], float, float]:
    """Kästen zeilenweise setzen: Positionen + Gesamtmaß. Ein Raster mit fester
    Spaltenzahl statt eines echten Auto-Layouts — vorhersagbar, und in draw.io
    lässt sich danach jederzeit „Anordnen → Layout" darüberlegen."""
    if not sizes:
        return [], 0.0, 0.0
    pos: list[tuple[float, float]] = []
    y, total_w = 0.0, 0.0
    for i in range(0, len(sizes), cols):
        row = sizes[i:i + cols]
        x = 0.0
        for w, _h in row:
            pos.append((x, y))
            x += w + gap
        total_w = max(total_w, x - gap)
        y += max(h for _w, h in row) + gap
    return pos, total_w, y - gap


# ── Maße ──────────────────────────────────────────────────────────────────────
# Gerechnet wird exakt so, wie draw.ios Stack-Layout es danach selbst tut: eine
# Spalte Netze je VDOM, eine Reihe VDOMs je Firewall. Damit sitzt die Zeichnung
# schon beim Öffnen dort, wo das Layout sie hinlegen würde — und das erste
# Auf- oder Zuklappen verrückt nicht plötzlich alles.

def _measure_vdom(vd: dict, with_networks: bool) -> tuple[tuple[float, float], list]:
    """Größe eines VDOM-Containers + Platzierung seiner Netz-Kästen (eine Spalte)."""
    nets = vd["networks"] if with_networks else []
    if not nets:
        return (VDOM_MIN_W, VDOM_HEAD + 2 * NET_M), []
    placed = []
    y = VDOM_HEAD + NET_M
    for net in nets:
        full, short = _net_height(net)
        collapsed = bool(net["hosts"])
        h = short if collapsed else full
        placed.append((net, NET_M, y, h, collapsed, full, short))
        y += h + NET_SPACING
    return (NET_W + 2 * NET_M, y - NET_SPACING + NET_M), placed


def _measure_device(dev: dict, with_networks: bool) -> tuple[tuple[float, float],
                                                             tuple[float, float], list]:
    """(Platzbedarf inkl. Symbol und Switch-Spalte, Container-Maß, VDOM-Kinder)."""
    measured = [_measure_vdom(vd, with_networks) for vd in dev["vdoms"]]
    inner_h = max((m[0][1] for m in measured), default=VDOM_HEAD + 2 * NET_M)
    x = VDOM_M
    kids = []
    for vd, ((w, _h), nets) in zip(dev["vdoms"], measured):
        kids.append((vd, x, FW_HEAD + VDOM_M, (w, inner_h), nets))
        x += w + VDOM_SPACING
    box = (max(x - VDOM_SPACING + VDOM_M, VDOM_MIN_W + 2 * VDOM_M),
           FW_HEAD + VDOM_M + inner_h + VDOM_M)
    # Switches stehen RECHTS neben der Firewall, nicht darunter: der Container
    # wächst beim Aufklappen nach unten und würde sie sonst überdecken.
    switch_col = SWITCH_W + GAP if dev["switches"] else 0
    return (box[0] + switch_col, DEV_ICON_H + box[1]), box, kids


def _measure_site(group: dict, with_networks: bool) -> tuple[tuple[float, float], list]:
    measured = [_measure_device(d, with_networks) for d in group["devices"]]
    pos, w, h = _pack([m[0] for m in measured], FWS_PER_ROW)
    head = SITE_HEAD + GAP if group["name"] else 0
    off = GAP if group["name"] else 0
    kids = [(dev, off + px, head + py, box, vdoms)
            for dev, (px, py), (_fp, box, vdoms) in zip(group["devices"], pos, measured)]
    if not group["name"]:
        return (w, h), kids
    return (w + 2 * GAP, head + h + GAP), kids


# ── Zeichnen ──────────────────────────────────────────────────────────────────

def _draw_vdom(doc: _Doc, vd: dict, parent: str, x: float, y: float,
               size: tuple[float, float], nets: list, cell_of: dict,
               with_networks: bool) -> None:
    label = _esc(vd["vdom"]) if with_networks else \
        f"{_esc(vd['vdom'])} <span style='color:#888'>· {vd['network_count']} Netze</span>"
    vd_id = doc.vertex(label, STYLE["vdom"], x, y, size[0], size[1], parent=parent,
                       tooltip=f"VDOM {vd['id']} · {vd['network_count']} Netze")
    cell_of[vd["id"]] = vd_id
    for net, nx, ny, nh, collapsed, full, short in nets:
        net_id = doc.vertex(_net_label(net), STYLE["net"], nx, ny, NET_W, nh, parent=vd_id,
                            tooltip=_net_tooltip(net), collapsed=collapsed,
                            alt=(NET_W, full if collapsed else short))
        cell_of[net["id"]] = net_id
        hy = NET_HEAD + 4
        for h in net["hosts"][:HOST_MAX_ROWS]:
            doc.vertex(_host_label(h), host_style(h), 12, hy + (HOST_H - ICON) // 2, ICON, ICON,
                       parent=net_id, tooltip=_host_tooltip(h))
            hy += HOST_H + 4
        if len(net["hosts"]) > HOST_MAX_ROWS:
            doc.vertex(_esc(f"… +{len(net['hosts']) - HOST_MAX_ROWS} weitere"), STYLE["more"],
                       12, hy, HOST_W, HOST_H, parent=net_id)


def _draw_device(doc: _Doc, dev: dict, parent: str, x: float, y: float,
                 box: tuple[float, float], vdoms: list, cell_of: dict,
                 with_networks: bool) -> None:
    """Symbol über dem Container, VDOMs darin, Switches rechts daneben. Der
    Container enthält NUR VDOMs — alles andere würde das Stack-Layout mit
    einreihen."""
    tip = " · ".join(p for p in (f"FortiGate {dev['device']}",
                                 f"ADOM {dev['adom']}" if dev.get("adom") else None,
                                 dev.get("site")) if p)
    doc.vertex("", icon_style("firewall").replace(
        "verticalLabelPosition=bottom;verticalAlign=top;", ""), x, y, 44, 28,
        parent=parent, tooltip=tip)
    fw_id = doc.vertex(_esc(dev["device"]), STYLE["fw"], x, y + DEV_ICON_H, box[0], box[1],
                       parent=parent, tooltip=tip)
    cell_of[f"device:{dev['device']}"] = fw_id
    for vd, vx, vy, vsize, nets in vdoms:
        _draw_vdom(doc, vd, fw_id, vx, vy, vsize, nets, cell_of, with_networks)
    for i, sw in enumerate(dev["switches"]):
        ports = ", ".join(sorted({p["fw_port"] for p in sw["ports"]}))
        stip = "\n".join(f"{k}: {v}" for k, v in (
            ("Switch", sw["name"]), ("IP", sw.get("ip")), ("Hardware", sw.get("hardware")),
            ("An Firewall-Port", ports)) if v)
        cell_of[sw["id"]] = doc.vertex(
            f"<b>{_esc(sw['name'])}</b><br>{_esc(sw.get('ip') or '')}", icon_style("switch"),
            x + box[0] + GAP, y + DEV_ICON_H + i * SWITCH_ROW, SWITCH_W, SWITCH_H,
            parent=parent, tooltip=stip)
        doc.edge(cell_of[sw["id"]], fw_id, _esc(ports), "switch")


def render(model: dict) -> str:
    doc = _Doc(model["scope"].get("title") or "Netzplan")
    cell_of: dict[str, str] = {}
    with_networks = model.get("with_networks", True)

    measured = [_measure_site(g, with_networks) for g in model["sites"]]
    pos, total_w, _total_h = _pack([m[0] for m in measured], SITES_PER_ROW)
    x0, y0 = 40, 40
    for group, (px, py), (size, devs) in zip(model["sites"], pos, measured):
        gx, gy = x0 + px, y0 + py
        if group["name"]:
            parent = doc.vertex(_esc(group["name"]), STYLE["site"], gx, gy, size[0], size[1],
                                tooltip=f"Standort {group['name']} · "
                                        f"{len(group['devices'])} Firewalls")
            cell_of[f"site:{group['name']}"] = parent
            ox, oy = 0.0, 0.0
        else:
            parent, ox, oy = "1", gx, gy
        for dev, dx, dy, box, vdoms in devs:
            _draw_device(doc, dev, parent, ox + dx, oy + dy, box, vdoms, cell_of, with_networks)

    # ── Nachbarn (WAN-Seite) rechts ────────────────────────────────────────
    nx, ny = x0 + total_w + 2 * GAP, y0
    for nb in model["neighbors"]:
        is_default = nb["kind"] == "default"
        style = icon_style("cloud" if is_default else "firewall")
        tip = nb["label"] if is_default else f"{nb['id']}" + (
            f"\nStandort: {nb['site']}" if nb.get("site") else "")
        w, h = (96, 60) if is_default else (64, 44)
        cell_of[nb["id"]] = doc.vertex(_esc(nb["label"]), style, nx + (NEIGHBOR_W - w) // 2, ny,
                                       w, h, tooltip=tip)
        ny += NEIGHBOR_H + GAP + 16

    # ── Kanten ─────────────────────────────────────────────────────────────
    seen: set[tuple[str, str, str]] = set()
    for e in model["edges"]:
        key = (e["from"], e["to"], e["kind"])
        if key in seen or (e["to"], e["from"], e["kind"]) in seen:
            continue
        seen.add(key)
        src, dst = cell_of.get(e["from"]), cell_of.get(e["to"])
        if src and dst:
            doc.edge(src, dst, _esc(e["label"]), e["kind"])
    return doc.to_xml()
