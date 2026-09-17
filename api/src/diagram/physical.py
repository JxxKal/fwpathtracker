"""Physische Netzdokumentation nach der Hausvorgabe — zwei Ebenen.

  Ebene 1  Wie hängen die Netzwerkkomponenten untereinander? Knoten sind die
           überwachten Geräte, Kanten die LLDP-Nachbarschaften mit den Ports
           an beiden Enden. Die Anforderung nennt LLDP ausdrücklich als
           bevorzugte Quelle — genau die liest LibreNMS.

  Ebene 2  Was hängt an EINEM Switch? Der Switch als Port-Panel, daran die
           Geräte, die auf dem jeweiligen Port in der FDB stehen. Die
           Zuordnung läuft über die MAC-Adresse, wie gefordert; die IP kommt
           aus der IP↔MAC-Historie, die A38 ohnehin mitschreibt.

Beides ist reine LibreNMS-Sicht: hier zählt das Kabel, nicht das Routing.
"""
from __future__ import annotations

import logging

import re

from diagram import titleblock
from diagram.labels import common_prefix, strip_prefix
from diagram.mx import A3_LANDSCAPE, Doc, esc
from locate.mac import normalize_mac, readable_mac

log = logging.getLogger("diagram.physical")

# ── Ebene 1 ──────────────────────────────────────────────────────────────────
NODE_W, NODE_H, ICON_H = 170, 40, 40
ROW_GAP, COL_GAP = 190, 200
NODE = ("shape={stencil};html=1;aspect=fixed;fillColor={color};strokeColor=#ffffff;"
        "strokeWidth=1;verticalLabelPosition=bottom;verticalAlign=top;fontSize=10;"
        "whiteSpace=wrap;")
LINK = ("edgeStyle=orthogonalEdgeStyle;rounded=0;html=1;endArrow=none;fontSize=9;"
        "labelBackgroundColor=#ffffff;strokeColor=#6c8ebf;")

# ── Ebene 2 ──────────────────────────────────────────────────────────────────
# Ports groß genug für ihre Beschriftung: mit 38 px und Schriftgröße 8 ist
# „Ten-GigabitEthernet1/0/24" nicht zu lesen. Gekürzt wird zusätzlich am
# gemeinsamen Präfix, das einmal am Panel steht.
PORT_W, PORT_H, PORTS_PER_ROW = 62, 34, 24
PANEL_PAD, PANEL_HEAD = 16, 40
HOST_SLOT, HOST_ROW, HOST_ICON = 152, 92, 26
PANEL = ("rounded=0;html=1;fillColor=#d9d9d9;strokeColor=#666666;verticalAlign=top;"
         "align=left;spacingLeft=8;spacingTop=6;fontSize=12;fontStyle=1;")
PORT = "rounded=0;html=1;fillColor={fill};strokeColor=#666666;fontSize=9;whiteSpace=wrap;"

# Logische Interfaces gehören nicht auf ein Port-Panel: sie haben keine Buchse.
LOGICAL_PORT = re.compile(
    r"(?i)^(bridge-?agg|.*-?aggregation\d*|vlan-?interface|vlan\d|null\d|"
    r"in-?loop-?back|loopback|register-tunnel|tunnel\d|port-?channel|po\d|"
    r"mgmt-?vlan|nve\d)")

# Symbol nach Gerätetyp. Ein modellgenaues Faceplate gibt draw.io nicht her —
# das hier ist eine Klassenaussage (Layer-3-Switch, Access-Switch, Firewall),
# und das genaue Modell steht daneben im Panelkopf und im Tooltip.
VENDOR_SHAPES = (
    (("fortigate", "fortios", "firewall", "palo alto", "checkpoint"),
     "mxgraph.networks.firewall", "#b85450"),
    (("router", "juniper", "mikrotik", "draytek"),
     "mxgraph.networks.router", "#b85450"),
    (("wireless", "wlan", "access point", "unifi", "aruba ap"),
     "mxgraph.networks.wireless_hub", "#6a4c93"),
    (("nexus", "catalyst", "layer 3", "layer3", "l3", "core", "routing"),
     "mxgraph.cisco.switches.layer_3_switch", "#9673a6"),
)
DEFAULT_SHAPE = ("mxgraph.cisco.switches.workgroup_switch", "#9673a6")
PORT_FREE, PORT_USED, PORT_UPLINK = "#ffffff", "#d5e8d4", "#e1d5e7"
ATTACHED = ("shape={stencil};html=1;aspect=fixed;fillColor={color};strokeColor=none;"
            "verticalLabelPosition=bottom;verticalAlign=top;fontSize=9;whiteSpace=wrap;")
WIRE = "html=1;endArrow=none;strokeColor=#888888;"


def _name(dev: dict) -> str:
    return str(dev.get("sysName") or dev.get("hostname") or dev.get("device_id") or "?")


def device_shape(dev: dict) -> tuple[str, str]:
    """(Stencil, Farbe) nach Hersteller/Hardware — eine Klassenaussage, kein
    modellgenaues Abbild. Das genaue Modell steht daneben."""
    text = " ".join(str(dev.get(k) or "")
                    for k in ("os", "type", "hardware", "sysDescr")).lower()
    for words, stencil, color in VENDOR_SHAPES:
        if any(w in text for w in words):
            return stencil, color
    return DEFAULT_SHAPE


# ── Ebene 1: Infrastruktur ───────────────────────────────────────────────────

async def infra_model(client, cfg: dict, warnings: list[str]) -> dict:
    """Geräte und ihre LLDP-Nachbarschaften. Nur Kanten zwischen ÜBERWACHTEN
    Geräten: ein Nachbar ohne eigene Device-Id ist ein Endgerät, und Endgeräte
    gehören auf Ebene 2, nicht in die Infrastrukturansicht."""
    try:
        links = await client.links(cfg)
        index = await client.device_index(cfg)
    except Exception as exc:
        warnings.append(f"LibreNMS nicht abrufbar: {exc}")
        return {"nodes": {}, "edges": []}
    by_id: dict[str, dict] = {}
    for dev in index.values():
        did = str(dev.get("device_id") or "")
        if did:
            by_id[did] = dev

    edges: dict[tuple[str, str], dict] = {}
    for link in links:
        a, b = str(link.get("local_device_id") or ""), str(link.get("remote_device_id") or "")
        if not a or not b or a == b or a not in by_id or b not in by_id:
            continue
        key = (a, b) if a < b else (b, a)
        slot = edges.setdefault(key, {"a": key[0], "b": key[1], "ports": set()})
        lp = str(link.get("local_port") or link.get("local_port_id") or "")
        rp = str(link.get("remote_port") or "")
        if a == key[0]:
            slot["ports"].add((lp, rp))
        else:
            slot["ports"].add((rp, lp))

    used = {n for e in edges.values() for n in (e["a"], e["b"])}
    nodes = {did: by_id[did] for did in used}
    if not nodes:
        warnings.append("Keine LLDP-Nachbarschaften zwischen überwachten Geräten "
                        "gefunden — Discovery in LibreNMS prüfen.")
    return {"nodes": nodes,
            "edges": [{**e, "ports": sorted(e["ports"])} for e in edges.values()]}


def _layers(model: dict) -> list[list[str]]:
    """Ebenen per Breitensuche vom bestvernetzten Gerät aus — das ist in aller
    Regel der Core-Switch, und genau so liest sich die Zeichnung: Core oben,
    Verteiler darunter, Zugang unten. Nicht verbundene Inseln kommen ans Ende."""
    nodes, edges = model["nodes"], model["edges"]
    adj: dict[str, set[str]] = {n: set() for n in nodes}
    for e in edges:
        adj[e["a"]].add(e["b"])
        adj[e["b"]].add(e["a"])
    seen: set[str] = set()
    layers: list[list[str]] = []
    while len(seen) < len(nodes):
        rest = [n for n in nodes if n not in seen]
        root = max(rest, key=lambda n: (len(adj[n]), n))
        level, depth = [root], 0
        seen.add(root)
        while level:
            if depth < len(layers):
                layers[depth].extend(level)
            else:
                layers.append(list(level))
            nxt = sorted({m for n in level for m in adj[n] if m not in seen})
            seen.update(nxt)
            level, depth = nxt, depth + 1
    return layers


def render_infra(model: dict, title_block: dict | None = None) -> str:
    doc = Doc("Netzwerk physisch · Infrastruktur", page=A3_LANDSCAPE)
    layers = _layers(model)
    width = max((len(l) for l in layers), default=1) * COL_GAP
    cell: dict[str, str] = {}
    x0, y0 = 40, 60
    for depth, layer in enumerate(layers):
        span = len(layer) * COL_GAP
        for i, did in enumerate(layer):
            dev = model["nodes"][did]
            x = x0 + (width - span) / 2 + i * COL_GAP + (COL_GAP - NODE_W) / 2
            y = y0 + depth * ROW_GAP
            label = f"<b>{esc(_name(dev))}</b><br>{esc(dev.get('ip') or '')}"
            tip = "\n".join(f"{k}: {v}" for k, v in (
                ("Gerät", _name(dev)), ("IP", dev.get("ip")),
                ("Hardware", dev.get("hardware")), ("OS", dev.get("os"))) if v)
            stencil, color = device_shape(dev)
            cell[did] = doc.vertex(label, NODE.format(stencil=stencil, color=color),
                                   x + (NODE_W - 72) / 2, y, 72, ICON_H, tooltip=tip)
    for e in model["edges"]:
        src, dst = cell.get(e["a"]), cell.get(e["b"])
        if not src or not dst:
            continue
        pairs = [f"{a or '?'} ↔ {b or '?'}" for a, b in e["ports"]][:3]
        doc.edge(src, dst, esc(" / ".join(pairs)), LINK)
    if title_block:
        bottom = y0 + max(1, len(layers)) * ROW_GAP
        titleblock.draw(doc, x0 + width + 2 * COL_GAP, max(y0, bottom - titleblock.HEIGHT),
                        title_block)
    return doc.to_xml()


# ── Ebene 2: Geräte an einem Switch ─────────────────────────────────────────

async def switch_model(client, cfg: dict, device_id, arp_by_mac, warnings: list[str],
                       dns=None) -> dict:
    """Ports eines Switches mit den Geräten, die dort in der FDB stehen.

    `arp_by_mac` liefert zu einer MAC-Liste die bekannten IPs — die Zuordnung
    MAC→Port macht LibreNMS, MAC→IP die Historie. `dns` löst die IPs, zu denen
    kein Name bekannt ist, per Reverse-DNS auf; ohne das trägt ein Gerät im
    Plan nur seine MAC, und die sagt beim Lesen niemandem etwas.
    """
    try:
        dev = await client.device(cfg, device_id)
        ports = await client.device_ports(cfg, device_id)
        fdb = await client.device_fdb(cfg, device_id)
        neighbours = await client.neighbours(cfg)
    except Exception as exc:
        warnings.append(f"LibreNMS nicht abrufbar: {exc}")
        return {"device": {}, "ports": [], "logical": 0}

    macs_by_port: dict[str, list[str]] = {}
    for row in fdb:
        pid = str(row.get("port_id") or "")
        mac = normalize_mac(str(row.get("mac_address") or ""))
        if pid and mac:
            macs_by_port.setdefault(pid, []).append(mac)

    all_macs = sorted({m for ms in macs_by_port.values() for m in ms})
    ips = await arp_by_mac(all_macs) if all_macs else {}

    out, logical = [], 0
    for p in ports:
        pid = str(p.get("port_id") or "")
        name = str(p.get("ifName") or p.get("ifDescr") or pid)
        if LOGICAL_PORT.match(name):
            logical += 1
            continue
        macs = macs_by_port.get(pid, [])
        nb = neighbours.get(int(pid)) if pid.isdigit() else None
        uplink = bool(nb and nb.get("monitored"))
        hosts = [] if uplink else [
            {"mac": m, "mac_readable": readable_mac(m), **(ips.get(m) or {})} for m in macs]
        out.append({
            "port_id": pid, "name": name,
            "alias": p.get("ifAlias") or None,
            "up": str(p.get("ifOperStatus") or "").lower() == "up",
            "mac_count": len(macs), "uplink": uplink,
            "neighbour": nb.get("label") if nb else None,
            "hosts": hosts,
        })

    if dns is not None:
        todo = [h for p in out for h in p["hosts"] if not h.get("name") and h.get("ip")]
        for host in todo[:300]:
            try:
                name = await dns(host["ip"])
            except Exception:
                name = None
            if name:
                host["name"] = name
    if not out:
        warnings.append("Keine physischen Ports zu diesem Gerät in LibreNMS.")
    return {"device": dev, "ports": out, "logical": logical}


def _attached_style(host: dict) -> tuple[str, str]:
    name = (host.get("name") or "").lower()
    if any(k in name for k in ("srv", "server", "vm")):
        return "mxgraph.networks.server", "#29AAE1"
    if any(k in name for k in ("sw", "switch", "ap-", "router")):
        return "mxgraph.cisco.switches.workgroup_switch", "#9673a6"
    return "mxgraph.networks.pc", "#6c8ebf"


def _attached_label(host: dict) -> str:
    """Name zuerst, sonst IP — die MAC ist die letzte Auskunft, nicht die erste."""
    lines = []
    if host.get("name"):
        lines.append(f"<b>{esc(str(host['name']).split('.')[0])}</b>")
    if host.get("ip"):
        lines.append(esc(host["ip"]))
    if not lines:
        lines.append(f"<b>{esc(host['mac_readable'])}</b>")
    else:
        lines.append(f"<span style='font-size:7px;color:#666'>"
                     f"{esc(host['mac_readable'])}</span>")
    return "<br>".join(lines)


def render_switch(model: dict, title_block: dict | None = None) -> str:
    dev = model["device"]
    doc = Doc(f"Netzwerk physisch · {_name(dev)}", page=A3_LANDSCAPE)
    ports = model["ports"]

    # Portnamen um ihr gemeinsames Präfix kürzen: aus
    # „Ten-GigabitEthernet1/0/24" wird „1/0/24", das Präfix steht am Panel.
    prefix = common_prefix([p["name"] for p in ports])
    rows = max(1, -(-len(ports) // PORTS_PER_ROW))
    cols = min(PORTS_PER_ROW, max(1, len(ports)))
    panel_w = cols * PORT_W + 2 * PANEL_PAD
    panel_h = PANEL_HEAD + rows * PORT_H + 2 * PANEL_PAD

    # Geräte abwechselnd über und unter das Panel, jeweils auf gleichmäßige
    # Plätze verteilt statt an die Port-Position geklebt — nebeneinander
    # liegende Ports sind 62 px auseinander, eine Beschriftung braucht 150.
    attached = [(p, h) for p in ports for h in p["hosts"][:4]]
    above = attached[0::2]
    below = attached[1::2]

    def rows_needed(items: list) -> int:
        per_row = max(1, int(panel_w // HOST_SLOT))
        return max(1, -(-len(items) // per_row)) if items else 0

    top_rows = rows_needed(above)
    x0, y0 = 60, 60
    panel_y = y0 + top_rows * HOST_ROW + 30

    stencil, color = device_shape(dev)
    head = (f"{esc(_name(dev))} &#160; {esc(dev.get('ip') or '')} &#160; "
            f"{len(ports)} Ports")
    if prefix:
        head += f" &#160; <span style='font-weight:normal'>({esc(prefix)}…)</span>"
    if model.get("logical"):
        head += (f" &#160; <span style='font-weight:normal;font-size:10px'>"
                 f"+ {model['logical']} logische Interfaces</span>")
    tip = "\n".join(f"{k}: {v}" for k, v in (
        ("Gerät", _name(dev)), ("IP", dev.get("ip")), ("Hardware", dev.get("hardware")),
        ("OS", dev.get("os"))) if v)
    panel = doc.vertex(head, PANEL, x0, panel_y, panel_w, panel_h, tooltip=tip)
    doc.vertex("", NODE.format(stencil=stencil, color=color).replace(
        "verticalLabelPosition=bottom;verticalAlign=top;", ""),
        x0 - 78, panel_y + 4, 64, 34, tooltip=tip)

    cell: dict[str, str] = {}
    for i, p in enumerate(ports):
        col, row = i % PORTS_PER_ROW, i // PORTS_PER_ROW
        fill = PORT_UPLINK if p["uplink"] else PORT_USED if p["hosts"] else PORT_FREE
        ptip = "\n".join(str(t) for t in (
            f"Port {p['name']}", p["alias"], f"{p['mac_count']} MACs",
            "Uplink zu " + str(p["neighbour"]) if p["uplink"] else None,
            "up" if p["up"] else "down") if t)
        cell[p["port_id"]] = doc.vertex(
            esc(strip_prefix(p["name"], prefix)), PORT.format(fill=fill),
            PANEL_PAD + col * PORT_W, PANEL_HEAD + PANEL_PAD + row * PORT_H,
            PORT_W - 3, PORT_H - 3, parent=panel, tooltip=ptip)

    def draw(items: list, upward: bool) -> None:
        per_row = max(1, int(panel_w // HOST_SLOT))
        slot = panel_w / max(1, min(len(items), per_row))
        for n, (port, host) in enumerate(items):
            col, row = n % per_row, n // per_row
            hx = x0 + col * slot + (slot - HOST_ICON) / 2
            hy = (panel_y - 30 - (row + 1) * HOST_ROW if upward
                  else panel_y + panel_h + 30 + row * HOST_ROW)
            stc, clr = _attached_style(host)
            htip = "\n".join(f"{k}: {v}" for k, v in (
                ("MAC", host["mac_readable"]), ("IP", host.get("ip")),
                ("Name", host.get("name")), ("Port", port["name"]),
                ("zuletzt gesehen", host.get("last_seen"))) if v)
            hid = doc.vertex(_attached_label(host),
                             ATTACHED.format(stencil=stc, color=clr),
                             hx, hy, HOST_ICON, HOST_ICON, tooltip=htip)
            doc.edge(hid, cell[port["port_id"]], "", WIRE)

    draw(above, True)
    draw(below, False)

    if title_block:
        bottom = panel_y + panel_h + rows_needed(below) * HOST_ROW + 60
        titleblock.draw(doc, x0 + panel_w + 80, max(y0, bottom - titleblock.HEIGHT),
                        title_block)
    return doc.to_xml()
