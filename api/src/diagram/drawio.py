"""draw.io-Renderer: Netzplan-Modell → mxGraph-XML (unkomprimierte .drawio-Datei).

Layout ist ein einfaches Schichtenmodell, das draw.io nicht selbst mitbringt:
    Firewall-Container
      └ VDOM-Container nebeneinander
          └ Netz-Kästen im Raster, darin die Hosts als Liste (einklappbar,
            ab HOST_COLLAPSE zugeklappt — der Plan bleibt lesbar, die Hosts
            sind trotzdem drin)
    rechts:  Nachbar-VDOMs, Internet/Default (die WAN-Seite)
    unten:   Switches per LLDP
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
HOST_COLLAPSE = 12          # ab so vielen Hosts zugeklappt starten
HOST_MAX_ROWS = 60          # mehr Zeilen zeichnet niemand mehr — Rest als "+N"
NETS_PER_ROW = 4
GAP = 24
VDOM_HEAD, FW_HEAD = 30, 34
NEIGHBOR_W, NEIGHBOR_H = 200, 60

STYLE = {
    "fw": "swimlane;html=1;startSize=34;fontStyle=1;fontSize=14;fillColor=#dae8fc;strokeColor=#6c8ebf;",
    "vdom": "swimlane;html=1;startSize=30;fontStyle=1;fontSize=12;fillColor=#f5f5f5;strokeColor=#666666;",
    "net": "swimlane;html=1;startSize=48;fontSize=10;align=left;spacingLeft=6;"
           "fillColor=#d5e8d4;strokeColor=#82b366;collapsible=1;",
    # Symbole aus der draw.io-Bibliothek „Network" (mxgraph.networks.*) — sie
    # sind Teil der Web-App, funktionieren also auch in der Offline-Instanz.
    # Host-Zeile: kleines Symbol, Label rechts daneben.
    "host-base": "shape=mxgraph.networks.{shape};html=1;strokeColor=none;aspect=fixed;"
                 "labelPosition=right;verticalLabelPosition=middle;align=left;"
                 "verticalAlign=middle;spacingLeft=4;fontSize=9;whiteSpace=nowrap;"
                 "fillColor={color};",
    "more": "text;html=1;fontSize=9;fontStyle=2;align=left;spacingLeft=4;",
    # Freistehende Symbole mit Label darunter (Nachbarn, Switches, Internet).
    "icon-base": "shape=mxgraph.networks.{shape};html=1;strokeColor=none;aspect=fixed;"
                 "verticalLabelPosition=bottom;verticalAlign=top;fontSize=11;"
                 "whiteSpace=wrap;fillColor={color};",
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


COLOR = {"firewall": "#b85450", "switch": "#9673a6", "server": "#29AAE1",
         "pc": "#6c8ebf", "cloud": "#b85450"}


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
    shape = host_shape(h)
    return STYLE["host-base"].format(shape=shape, color=COLOR[shape])


def icon_style(shape: str) -> str:
    return STYLE["icon-base"].format(shape=shape, color=COLOR[shape])


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
    zone_s = f" · Zone {zone}" if zone and zone != net["interface"] else ""
    return f"<b>{_esc(head or net['interface'])}</b><br>{_esc(net['cidr'])} · GW {_esc(net['fw_ip'])}<br>{_esc(net['interface'])}{_esc(zone_s)}"


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


def render(model: dict) -> str:
    sc = model["scope"]
    title = f"Netzplan {sc['device']}" + (f"/{sc['vdom']}" if sc.get("vdom") else "")
    doc = _Doc(title)
    cell_of: dict[str, str] = {}

    # ── Firewall-Container mit VDOMs ───────────────────────────────────────
    fw_x, fw_y = 40, 40
    x_cursor = GAP
    fw_h = FW_HEAD
    fw_id = doc.vertex(_esc(sc["device"]), STYLE["fw"], fw_x, fw_y, 10, 10,
                       tooltip=f"FortiGate {sc['device']}")
    for vd in model["vdoms"]:
        nets = vd["networks"]
        cols = max(1, min(NETS_PER_ROW, len(nets)))
        vd_w = cols * (NET_W + GAP) + GAP
        # Netze zeilenweise setzen; Zeilenhöhe = höchster (zugeklappter oder offener) Kasten
        y = VDOM_HEAD + GAP
        row_h = 0
        placed: list[tuple[dict, float, float, float, bool]] = []
        for i, net in enumerate(nets):
            col = i % cols
            if col == 0 and i > 0:
                y += row_h + GAP
                row_h = 0
            full, short = _net_height(net)
            collapsed = len(net["hosts"]) > HOST_COLLAPSE
            h = short if collapsed else full
            placed.append((net, GAP + col * (NET_W + GAP), y, h, collapsed))
            row_h = max(row_h, h)
        vd_h = y + row_h + GAP if nets else VDOM_HEAD + GAP
        vd_id = doc.vertex(_esc(vd["vdom"]), STYLE["vdom"], x_cursor, FW_HEAD + GAP, vd_w, vd_h,
                           parent=fw_id, tooltip=f"VDOM {vd['id']} · {len(nets)} Netze")
        cell_of[vd["id"]] = vd_id
        for net, nx, ny, nh, collapsed in placed:
            full, short = _net_height(net)
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
        x_cursor += vd_w + GAP
        fw_h = max(fw_h, FW_HEAD + GAP + vd_h + GAP)
    fw_w = max(x_cursor, 300)
    # Container-Geometrie nachziehen
    for obj in doc.root.iter("object"):
        if obj.get("id") == fw_id:
            geo = obj.find("mxCell/mxGeometry")
            geo.set("width", str(int(fw_w)))
            geo.set("height", str(int(fw_h)))
    # Firewall-Symbol rechts im Kopf des Containers
    doc.vertex("", icon_style("firewall").replace("verticalLabelPosition=bottom;verticalAlign=top;", ""),
               fw_w - 52, 3, 44, 28, parent=fw_id, tooltip=f"FortiGate {sc['device']}")

    # ── Nachbarn (WAN-Seite) rechts ────────────────────────────────────────
    nx = fw_x + fw_w + 2 * GAP
    ny = fw_y
    for nb in model["neighbors"]:
        is_default = nb["kind"] == "default"
        style = icon_style("cloud" if is_default else "firewall")
        tip = nb["label"] if is_default else f"{nb['id']}" + (f"\nStandort: {nb['site']}" if nb.get("site") else "")
        w, h = (96, 60) if is_default else (64, 44)
        cell_of[nb["id"]] = doc.vertex(_esc(nb["label"]), style, nx + (NEIGHBOR_W - w) // 2, ny, w, h,
                                       tooltip=tip)
        ny += NEIGHBOR_H + GAP + 16

    # ── Switches unten ─────────────────────────────────────────────────────
    sx, sy = fw_x, fw_y + fw_h + 2 * GAP
    for sw in model["switches"]:
        ports = ", ".join(sorted({p["fw_port"] for p in sw["ports"]}))
        label = f"<b>{_esc(sw['name'])}</b><br>{_esc(sw.get('ip') or '')}"
        tip = "\n".join(f"{k}: {v}" for k, v in (("Switch", sw["name"]), ("IP", sw.get("ip")),
                                                    ("Hardware", sw.get("hardware")),
                                                    ("An Firewall-Port", ports)) if v)
        cell_of[sw["id"]] = doc.vertex(label, icon_style("switch"), sx, sy, 72, 36, tooltip=tip)
        doc.edge(cell_of[sw["id"]], fw_id, _esc(ports), "switch")
        sx += NEIGHBOR_W + GAP

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
