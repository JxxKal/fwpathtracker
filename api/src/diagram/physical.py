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

from diagram import titleblock
from diagram.mx import A3_LANDSCAPE, Doc, esc
from locate.mac import normalize_mac, readable_mac

log = logging.getLogger("diagram.physical")

# ── Ebene 1 ──────────────────────────────────────────────────────────────────
NODE_W, NODE_H, ICON_H = 170, 40, 40
ROW_GAP, COL_GAP = 190, 200
SWITCH = ("shape=mxgraph.cisco.switches.workgroup_switch;html=1;aspect=fixed;"
          "fillColor=#9673a6;strokeColor=#ffffff;strokeWidth=1;"
          "verticalLabelPosition=bottom;verticalAlign=top;fontSize=10;whiteSpace=wrap;")
ROUTER = SWITCH.replace("workgroup_switch", "router").replace("#9673a6", "#b85450")
LINK = ("edgeStyle=orthogonalEdgeStyle;rounded=0;html=1;endArrow=none;fontSize=9;"
        "labelBackgroundColor=#ffffff;strokeColor=#6c8ebf;")

# ── Ebene 2 ──────────────────────────────────────────────────────────────────
PORT_W, PORT_H, PORTS_PER_ROW = 38, 30, 24
PANEL_PAD, PANEL_HEAD = 14, 26
HOST_W, HOST_H, HOST_ICON = 150, 58, 26
STACK_GAP = 74
PANEL = ("rounded=0;html=1;fillColor=#d9d9d9;strokeColor=#666666;verticalAlign=top;"
         "align=left;spacingLeft=8;spacingTop=4;fontSize=11;fontStyle=1;")
PORT = "rounded=0;html=1;fillColor={fill};strokeColor=#666666;fontSize=8;"
PORT_FREE, PORT_USED, PORT_UPLINK = "#ffffff", "#d5e8d4", "#e1d5e7"
ATTACHED = ("shape={stencil};html=1;aspect=fixed;fillColor={color};strokeColor=none;"
            "verticalLabelPosition=bottom;verticalAlign=top;fontSize=9;whiteSpace=wrap;")
WIRE = "html=1;endArrow=none;strokeColor=#888888;"


def _name(dev: dict) -> str:
    return str(dev.get("sysName") or dev.get("hostname") or dev.get("device_id") or "?")


def _is_router(dev: dict) -> bool:
    text = " ".join(str(dev.get(k) or "") for k in ("os", "type", "hardware")).lower()
    return any(w in text for w in ("router", "firewall", "fortigate", "fortios"))


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
            style = ROUTER if _is_router(dev) else SWITCH
            cell[did] = doc.vertex(label, style, x + (NODE_W - 72) / 2, y, 72, ICON_H,
                                   tooltip=tip)
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

async def switch_model(client, cfg: dict, device_id, arp_by_mac, warnings: list[str]) -> dict:
    """Ports eines Switches mit den Geräten, die dort in der FDB stehen.

    `arp_by_mac` ist ein Callable, das zu einer MAC-Liste die bekannten IPs
    liefert — die Zuordnung MAC→Port macht LibreNMS, MAC→IP die Historie.
    """
    try:
        dev = await client.device(cfg, device_id)
        ports = await client.device_ports(cfg, device_id)
        fdb = await client.device_fdb(cfg, device_id)
        neighbours = await client.neighbours(cfg)
    except Exception as exc:
        warnings.append(f"LibreNMS nicht abrufbar: {exc}")
        return {"device": {}, "ports": []}

    macs_by_port: dict[str, list[str]] = {}
    for row in fdb:
        pid = str(row.get("port_id") or "")
        mac = normalize_mac(str(row.get("mac_address") or ""))
        if pid and mac:
            macs_by_port.setdefault(pid, []).append(mac)

    all_macs = sorted({m for ms in macs_by_port.values() for m in ms})
    ips = await arp_by_mac(all_macs) if all_macs else {}

    out = []
    for p in ports:
        pid = str(p.get("port_id") or "")
        macs = macs_by_port.get(pid, [])
        nb = neighbours.get(int(pid)) if pid.isdigit() else None
        uplink = bool(nb and nb.get("monitored"))
        hosts = [] if uplink else [
            {"mac": m, "mac_readable": readable_mac(m), **(ips.get(m) or {})} for m in macs]
        out.append({
            "port_id": pid,
            "name": p.get("ifName") or p.get("ifDescr") or pid,
            "alias": p.get("ifAlias") or None,
            "up": str(p.get("ifOperStatus") or "").lower() == "up",
            "mac_count": len(macs),
            "uplink": uplink,
            "neighbour": nb.get("label") if nb else None,
            "hosts": hosts,
        })
    if not out:
        warnings.append("Keine Ports zu diesem Gerät in LibreNMS.")
    return {"device": dev, "ports": out}


def _attached_style(host: dict) -> tuple[str, str]:
    name = (host.get("name") or "").lower()
    if any(k in name for k in ("srv", "server", "vm")):
        return "mxgraph.networks.server", "#29AAE1"
    if any(k in name for k in ("sw", "switch", "ap", "router")):
        return "mxgraph.cisco.switches.workgroup_switch", "#9673a6"
    return "mxgraph.networks.pc", "#6c8ebf"


def render_switch(model: dict, title_block: dict | None = None) -> str:
    dev = model["device"]
    doc = Doc(f"Netzwerk physisch · {_name(dev)}", page=A3_LANDSCAPE)
    ports = model["ports"]
    rows = max(1, -(-len(ports) // PORTS_PER_ROW))
    cols = min(PORTS_PER_ROW, max(1, len(ports)))
    panel_w = cols * PORT_W + 2 * PANEL_PAD
    panel_h = PANEL_HEAD + rows * PORT_H + 2 * PANEL_PAD

    # Geräte über UND unter dem Panel, damit sich die Beschriftungen nicht
    # überlagern — so hält es auch die Beispielzeichnung.
    above = [p for i, p in enumerate(ports) if p["hosts"] and i % 2 == 0]
    below = [p for i, p in enumerate(ports) if p["hosts"] and i % 2 == 1]
    top_h = max((len(p["hosts"]) for p in above), default=0) * STACK_GAP + 40
    x0, y0 = 60, 60
    panel_y = y0 + top_h

    label = (f"{esc(_name(dev))} &#160; {esc(dev.get('ip') or '')} &#160; "
             f"{len(ports)} Ports")
    panel = doc.vertex(label, PANEL, x0, panel_y, panel_w, panel_h,
                       tooltip="\n".join(f"{k}: {v}" for k, v in (
                           ("Gerät", _name(dev)), ("IP", dev.get("ip")),
                           ("Hardware", dev.get("hardware"))) if v))

    cell: dict[str, str] = {}
    for i, p in enumerate(ports):
        col, row = i % PORTS_PER_ROW, i // PORTS_PER_ROW
        fill = PORT_UPLINK if p["uplink"] else PORT_USED if p["hosts"] else PORT_FREE
        tip = "\n".join(str(t) for t in (
            f"Port {p['name']}", p["alias"], f"{p['mac_count']} MACs",
            "Uplink zu " + str(p["neighbour"]) if p["uplink"] else None,
            "up" if p["up"] else "down") if t)
        cell[p["port_id"]] = doc.vertex(
            esc(p["name"]), PORT.format(fill=fill),
            PANEL_PAD + col * PORT_W, PANEL_HEAD + PANEL_PAD + row * PORT_H,
            PORT_W - 2, PORT_H - 2, parent=panel, tooltip=tip)

    def draw_hosts(port: dict, upward: bool) -> None:
        i = ports.index(port)
        col = i % PORTS_PER_ROW
        hx = x0 + PANEL_PAD + col * PORT_W + (PORT_W - HOST_ICON) / 2
        for n, host in enumerate(port["hosts"][:4]):
            stencil, color = _attached_style(host)
            if upward:
                hy = panel_y - 40 - n * STACK_GAP
            else:
                hy = panel_y + panel_h + 40 + n * STACK_GAP
            bits = [host.get("name") or host["mac_readable"]]
            if host.get("ip"):
                bits.append(host["ip"])
            tip = "\n".join(f"{k}: {v}" for k, v in (
                ("MAC", host["mac_readable"]), ("IP", host.get("ip")),
                ("Name", host.get("name")), ("Port", port["name"]),
                ("zuletzt gesehen", host.get("last_seen"))) if v)
            hid = doc.vertex("<br>".join(esc(b) for b in bits),
                             ATTACHED.format(stencil=stencil, color=color),
                             hx, hy, HOST_ICON, HOST_ICON, tooltip=tip)
            doc.edge(hid, cell[port["port_id"]], "", WIRE)

    for p in above:
        draw_hosts(p, True)
    for p in below:
        draw_hosts(p, False)

    if title_block:
        bottom = panel_y + panel_h + max((len(p["hosts"]) for p in below), default=0) * STACK_GAP + 80
        titleblock.draw(doc, x0 + panel_w + 2 * PANEL_PAD + 40,
                        max(y0, bottom - titleblock.HEIGHT), title_block)
    return doc.to_xml()
