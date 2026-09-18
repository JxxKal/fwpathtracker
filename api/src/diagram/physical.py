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
TABLE_ROW_H = 20
TABLE_HEAD = ("rounded=0;html=1;fillColor=#e8e8e8;strokeColor=#666666;fontStyle=1;"
              "fontSize=10;align=left;spacingLeft=6;")
TABLE_CELL = ("rounded=0;html=1;fillColor=#ffffff;strokeColor=#bbbbbb;fontSize=10;"
              "align=left;spacingLeft=6;")

# ── Kalibriertes Modellbild ──────────────────────────────────────────────────
# Ein Bild allein trägt keine Information: die Leitung muss an der richtigen
# Buchse landen. Dafür bekommt eine Shape-Regel optional Blöcke mit dem
# Buchsenraster im Bild — Mittelpunkt der ersten Buchse, Abstand, Spalten,
# Reihen und die Zählrichtung. Die Zuordnung läuft über die PORTNUMMER aus dem
# Namen, nicht über die Reihenfolge der LibreNMS-Liste: die Liste darf sich
# sortieren, wie sie will, die Buchse bleibt dieselbe.
IMAGE_PANEL = ("shape=image;html=1;imageAspect=0;image={image};container=1;"
               "collapsible=0;movable=1;resizable=0;")
PANEL_TITLE = ("text;html=1;align=left;verticalAlign=middle;fontSize=12;fontStyle=1;"
               "spacingLeft=2;")
PORT_OVERLAY = ("rounded=0;html=1;fillColor={fill};strokeColor={line};strokeWidth=2;"
                "opacity={opacity};fontSize=0;")
OVERLAY_COLORS = {"used": ("#d5e8d4", "#2e8b57", 70),
                  "uplink": ("#e1d5e7", "#6a4c93", 70),
                  "free": ("none", "#999999", 45)}


# Stack-Namen: <Name><Einheit>/<Slot>/<Port>. Nur bei DREI Zahlengruppen ist
# die erste die Stack-Einheit — `Gi0/1` ist Slot/Port auf einem Einzelgerät.
UNIT_RE = re.compile(r"^(\D*)(\d+)/(\d+)/(\d+)$")
MAX_DEVICES_DRAWN = 24      # darüber: Geräte in die Tabelle statt an die Buchse


def port_unit(name: str) -> int:
    """Stack-Einheit eines Ports; 1, wenn der Name keine trägt."""
    m = UNIT_RE.match(name or "")
    return int(m.group(2)) if m else 1


def unit_key(name: str) -> str:
    """Portname auf Einheit 1 normiert — der Schlüssel der Buchsenzuordnung.

    Ein Stack ist mehrfach dasselbe Gerät: eingemessen wird EIN Blech, und
    `Ten-GigabitEthernet2/0/1` sitzt darauf an derselben Stelle wie
    `Ten-GigabitEthernet1/0/1`. Ohne diese Normierung fällt jede weitere
    Einheit durch die Zuordnung und landet in der Restzeile.
    """
    m = UNIT_RE.match(name or "")
    return f"{m.group(1)}1/{m.group(3)}/{m.group(4)}" if m else name


def port_number(name: str) -> int | None:
    """Portnummer aus dem Namen — die letzte Zahlengruppe.

    `Ten-GigabitEthernet1/0/24` → 24, `p25` → 25, `Gi1/0/1` → 1. Modul und
    Slot stehen davor und interessieren das Raster nicht; gibt es mehrere
    Module, bekommt jedes seinen eigenen Block.
    """
    groups = re.findall(r"\d+", name or "")
    return int(groups[-1]) if groups else None


def _blocks(rule: dict | None) -> list[dict]:
    if not rule or not rule.get("image"):
        return []
    blocks = rule.get("blocks")
    return [b for b in blocks if isinstance(b, dict)] if isinstance(blocks, list) else []


def port_position(number: int | None, blocks: list[dict]) -> tuple[float, float, dict] | None:
    """Mittelpunkt der Buchse im Bild — oder None, wenn die Nummer in keinem
    Block liegt. Solche Ports fallen nicht weg, sie kommen unter das Bild."""
    if number is None:
        return None
    for block in blocks:
        cols = max(1, int(block.get("cols") or 1))
        rows = max(1, int(block.get("rows") or 1))
        start = int(block.get("start") or 1)
        idx = number - start
        if idx < 0 or idx >= cols * rows:
            continue
        if str(block.get("order") or "rowwise") == "zigzag":
            col, row = idx // rows, idx % rows      # oben ungerade, unten gerade
        else:
            col, row = idx % cols, idx // cols
        x = float(block.get("x") or 0) + col * float(block.get("dx") or 0)
        y = float(block.get("y") or 0) + row * float(block.get("dy") or 0)
        return x, y, block
    return None


def _name(dev: dict) -> str:
    return str(dev.get("sysName") or dev.get("hostname") or dev.get("device_id") or "?")


def _haystack(dev: dict) -> str:
    return " ".join(str(dev.get(k) or "")
                    for k in ("hardware", "sysDescr", "os", "type", "sysName",
                              "hostname")).lower()


def match_rule(dev: dict, rules: list[dict] | None) -> dict | None:
    """Regel der Shape-Bibliothek zu einem Gerät.

    Zuerst der EXAKTE Hardware-String aus LibreNMS: die Regeln werden aus der
    Liste der tatsächlich erkannten Modelle angelegt, nicht von Hand getippt —
    ein Tippfehler im Muster fällt sonst erst auf, wenn die Zeichnung fertig
    ist und nichts passt. Danach der Teilstring-Weg für ältere Regeln.
    """
    hardware = str(dev.get("hardware") or "").strip().lower()
    if hardware:
        for rule in rules or []:
            key = str(rule.get("hardware") or "").strip().lower()
            if key and key == hardware and rule.get("image"):
                return rule
    text = _haystack(dev)
    for rule in rules or []:
        pattern = str(rule.get("match") or "").strip().lower()
        if pattern and pattern in text and rule.get("image"):
            return rule
    return None


def port_places(rule: dict | None):
    """Zuordnung Portname → Platz im Bild.

    Gearbeitet wird über den NAMEN, nicht über die Nummer: `HundredGigE1/0/1`
    und `GigabitEthernet1/0/1` tragen dieselbe Nummer und sind verschiedene
    Buchsen. Der Name ist bei Geräten desselben Modells identisch, also trägt
    eine einmal eingemessene Zuordnung für alle davon.

    Rückgabe: Funktion name → {x, y, w, h} oder None; None heißt, dass es für
    diese Regel keine Platzzuordnung gibt.
    """
    if not rule or not rule.get("image"):
        return None
    places = rule.get("ports")
    if isinstance(places, dict) and places:
        dw = float(rule.get("port_w") or 16)
        dh = float(rule.get("port_h") or 16)

        def by_name(name: str) -> dict | None:
            spot = places.get(name)
            if not isinstance(spot, dict):
                spot = places.get(unit_key(name))
            if not isinstance(spot, dict):
                return None
            return {"x": float(spot.get("x", 0)), "y": float(spot.get("y", 0)),
                    "w": float(spot.get("w") or dw), "h": float(spot.get("h") or dh)}
        return by_name

    blocks = _blocks(rule)          # Alt-Regeln mit Raster
    if not blocks:
        return None

    def by_grid(name: str) -> dict | None:
        hit = port_position(port_number(name), blocks)
        if hit is None:
            return None
        x, y, block = hit
        return {"x": x, "y": y, "w": float(block.get("w") or 20),
                "h": float(block.get("h") or 20)}
    return by_grid


def device_style(dev: dict, rules: list[dict] | None = None,
                 label_below: bool = True) -> str:
    """Vollständiger draw.io-Style für ein Gerät: das hinterlegte Modellbild,
    sonst das Klassensymbol."""
    rule = match_rule(dev, rules)
    if rule:
        image = str(rule["image"]).replace(";base64,", ",", 1)
        style = f"shape=image;html=1;imageAspect=1;image={image};"
        return style + ("verticalLabelPosition=bottom;verticalAlign=top;"
                        "fontSize=10;whiteSpace=wrap;" if label_below else "")
    stencil, color = device_shape(dev)
    style = NODE.format(stencil=stencil, color=color)
    if not label_below:
        style = style.replace("verticalLabelPosition=bottom;verticalAlign=top;", "")
    return style


def device_shape(dev: dict) -> tuple[str, str]:
    """(Stencil, Farbe) nach Hersteller/Hardware — eine Klassenaussage, kein
    modellgenaues Abbild. Das genaue Modell steht daneben."""
    text = _haystack(dev)
    for words, stencil, color in VENDOR_SHAPES:
        if any(w in text for w in words):
            return stencil, color
    return DEFAULT_SHAPE


# ── Ebene 1: Infrastruktur ───────────────────────────────────────────────────

async def infra_model(client, cfg: dict, warnings: list[str],
                      allow: set[str] | None = None) -> dict:
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
        if did and (allow is None or did in allow):
            by_id[did] = dev
    if allow is not None and not by_id:
        warnings.append("Kein überwachtes Gerät im gewählten Standort bzw. in der "
                        "gewählten Gruppe.")

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


def render_infra(model: dict, title_block: dict | None = None,
                 rules: list[dict] | None = None) -> str:
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
            style = device_style(dev, rules)
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


def _device_rows(items: list, width: float) -> int:
    """Geräte je Seite auf höchstens zwei Reihen — sonst wächst die Zeichnung
    nach oben und unten weg und die Leitungen laufen quer über alles. Breiter
    darf sie werden: ein Switchplan ist nun einmal breit."""
    if not items:
        return 0
    return 1 if len(items) * HOST_SLOT <= width else 2


def _draw_devices(doc: Doc, items: list, cell: dict, x0: float, width: float,
                  top: float, bottom: float, upward: bool) -> float:
    """Geräte über bzw. unter dem Blech. Gibt die belegte Höhe zurück."""
    rows = _device_rows(items, width)
    if not rows:
        return 0.0
    per_row = -(-len(items) // rows)
    band = max(width, per_row * HOST_SLOT)
    slot = band / per_row
    left = x0 + (width - band) / 2
    for n, (port, host) in enumerate(items):
        col, row = n % per_row, n // per_row
        hx = left + col * slot + (slot - HOST_ICON) / 2
        hy = (top - 30 - (rows - row) * HOST_ROW if upward
              else bottom + 30 + row * HOST_ROW)
        stc, clr = _attached_style(host)
        htip = "\n".join(f"{k}: {v}" for k, v in (
            ("MAC", host["mac_readable"]), ("IP", host.get("ip")),
            ("Name", host.get("name")), ("Port", port["name"]),
            ("zuletzt gesehen", host.get("last_seen"))) if v)
        hid = doc.vertex(_attached_label(host), ATTACHED.format(stencil=stc, color=clr),
                         hx, hy, HOST_ICON, HOST_ICON, tooltip=htip)
        doc.edge(hid, cell[port["port_id"]], "", WIRE)
    return rows * HOST_ROW + 30


def _device_table(doc: Doc, title: str, items: list) -> None:
    """Zu viele Geräte für die Zeichnung: dann in eine Tabelle, wie es die
    Hausvorgabe für lange Gerätelisten ohnehin vorsieht."""
    doc.page(f"Geräte {title}"[:50])
    cols = [("Port", 180), ("MAC", 150), ("IP", 140), ("Name", 260)]
    x, y = 40, 60
    doc.vertex(esc(title), "text;html=1;fontSize=14;fontStyle=1;align=left;",
               x, y - 28, sum(w for _c, w in cols), 24)
    cx = x
    for name, w in cols:
        doc.vertex(esc(name), TABLE_HEAD, cx, y, w, TABLE_ROW_H)
        cx += w
    for i, (port, host) in enumerate(items, 1):
        cx = x
        values = [port["name"], host["mac_readable"], host.get("ip") or "",
                  host.get("name") or ""]
        for (_n, w), value in zip(cols, values):
            doc.vertex(esc(value), TABLE_CELL, cx, y + i * TABLE_ROW_H, w, TABLE_ROW_H)
            cx += w


def _draw_unit(doc: Doc, dev: dict, rule: dict, place, ports: list[dict],
               x0: float, y_top: float, unit: int, units: int) -> tuple[float, float]:
    """Ein Blech: das Modellbild mit seinen Buchsen und den Geräten daran."""
    img_w = float(rule.get("width") or 800)
    img_h = float(rule.get("height") or 120)

    placed: list[tuple[dict, dict]] = []
    rest: list[dict] = []
    for p in ports:
        spot = place(p["name"])
        (placed.append((p, spot)) if spot else rest.append(p))

    attached = [(p, h) for p, _s in placed for h in p["hosts"][:4]]
    attached += [(p, h) for p in rest for h in p["hosts"][:4]]
    too_many = len(attached) > MAX_DEVICES_DRAWN
    above, below = ([], []) if too_many else (attached[0::2], attached[1::2])

    img_y = y_top + _device_rows(above, img_w) * HOST_ROW + (30 if above else 0) + 26
    head = (f"{esc(_name(dev))} &#160; {esc(dev.get('ip') or '')}"
            + (f" &#160; Einheit {unit}" if units > 1 else "")
            + f" &#160; {len(ports)} Ports")
    if too_many:
        head += (f" &#160; <span style='font-weight:normal;font-size:10px'>"
                 f"{len(attached)} Geräte — siehe Tabellenseite</span>")
    tip = "\n".join(f"{k}: {v}" for k, v in (
        ("Gerät", _name(dev)), ("IP", dev.get("ip")), ("Modell", rule.get("label")),
        ("Stack-Einheit", unit if units > 1 else None),
        ("Hardware", dev.get("hardware")), ("Standort", dev.get("location"))) if v)
    doc.vertex(head, PANEL_TITLE, x0, img_y - 24, img_w, 22)
    image = str(rule["image"]).replace(";base64,", ",", 1)
    panel = doc.vertex("", IMAGE_PANEL.format(image=image), x0, img_y, img_w, img_h,
                       tooltip=tip)

    cell: dict[str, str] = {}
    for p, spot in placed:
        w, h = spot["w"], spot["h"]
        kind = "uplink" if p["uplink"] else "used" if p["hosts"] else "free"
        fill, line, opacity = OVERLAY_COLORS[kind]
        ptip = "\n".join(str(t) for t in (
            f"Port {p['name']}", p["alias"], f"{p['mac_count']} MACs",
            "Uplink zu " + str(p["neighbour"]) if p["uplink"] else None,
            "up" if p["up"] else "down") if t)
        cell[p["port_id"]] = doc.vertex(
            "", PORT_OVERLAY.format(fill=fill, line=line, opacity=opacity),
            spot["x"] - w / 2, spot["y"] - h / 2, w, h, parent=panel, tooltip=ptip)

    bottom = img_y + img_h
    if rest:
        doc.vertex(f"{len(rest)} Ports ohne zugeordnete Buchse",
                   "text;html=1;fontSize=9;align=left;fontColor=#888888;",
                   x0, bottom + 6, 260, 16)
        for i, p in enumerate(rest):
            fill = PORT_UPLINK if p["uplink"] else PORT_USED if p["hosts"] else PORT_FREE
            cell[p["port_id"]] = doc.vertex(
                esc(p["name"]), PORT.format(fill=fill),
                x0 + (i % PORTS_PER_ROW) * PORT_W,
                bottom + 24 + (i // PORTS_PER_ROW) * PORT_H,
                PORT_W - 3, PORT_H - 3, tooltip=f"Port {p['name']}")
        bottom += 24 + (-(-len(rest) // PORTS_PER_ROW)) * PORT_H

    _draw_devices(doc, above, cell, x0, img_w, img_y, bottom, True)
    used = _draw_devices(doc, below, cell, x0, img_w, img_y, bottom, False)
    if too_many:
        name = _name(dev) + (f" Einheit {unit}" if units > 1 else "")
        _device_table(doc, name, attached)
    return bottom + used + 40, img_w


def _draw_image_panel(doc: Doc, model: dict, rule: dict, place,
                      x0: float, y_top: float) -> tuple[float, float]:
    """Kalibriertes Modellbild als Blech. Ein Stack ist mehrfach dasselbe
    Gerät — je Einheit ein Blech, alle mit derselben Zuordnung."""
    dev = model["device"]
    by_unit: dict[int, list[dict]] = {}
    for p in model["ports"]:
        by_unit.setdefault(port_unit(p["name"]), []).append(p)
    units = sorted(by_unit)
    y, width = y_top, 0.0
    for unit in units:
        y, w = _draw_unit(doc, dev, rule, place, by_unit[unit], x0, y, unit, len(units))
        width = max(width, w)
        y += 30
    return y, width


def _draw_panel(doc: Doc, model: dict, x0: float, y_top: float,
                rules: list[dict] | None) -> tuple[float, float]:
    """Ein Switch-Panel samt angeschlossener Geräte. Gibt (Unterkante, Breite)
    zurück, damit mehrere Panels gestapelt werden können."""
    dev = model["device"]
    ports = model["ports"]
    rule = match_rule(dev, rules)
    place = port_places(rule)
    if place is not None:
        return _draw_image_panel(doc, model, rule, place, x0, y_top)

    # Portnamen um ihr gemeinsames Präfix kürzen: aus
    # „Ten-GigabitEthernet1/0/24" wird „24", das Präfix steht am Panel.
    prefix = common_prefix([p["name"] for p in ports])
    rows = max(1, -(-len(ports) // PORTS_PER_ROW))
    cols = min(PORTS_PER_ROW, max(1, len(ports)))
    panel_w = cols * PORT_W + 2 * PANEL_PAD
    panel_h = PANEL_HEAD + rows * PORT_H + 2 * PANEL_PAD

    # Geräte abwechselnd über und unter das Panel, jeweils auf gleichmäßige
    # Plätze verteilt statt an die Port-Position geklebt — nebeneinander
    # liegende Ports sind 62 px auseinander, eine Beschriftung braucht 150.
    attached = [(p, h) for p in ports for h in p["hosts"][:4]]
    too_many = len(attached) > MAX_DEVICES_DRAWN
    above, below = ([], []) if too_many else (attached[0::2], attached[1::2])
    panel_y = y_top + _device_rows(above, panel_w) * HOST_ROW + (30 if above else 0)

    head = (f"{esc(_name(dev))} &#160; {esc(dev.get('ip') or '')} &#160; "
            f"{len(ports)} Ports")
    if prefix:
        head += f" &#160; <span style='font-weight:normal'>({esc(prefix)}…)</span>"
    if model.get("logical"):
        head += (f" &#160; <span style='font-weight:normal;font-size:10px'>"
                 f"+ {model['logical']} logische Interfaces</span>")
    if too_many:
        head += (f" &#160; <span style='font-weight:normal;font-size:10px'>"
                 f"{len(attached)} Geräte — siehe Tabellenseite</span>")
    tip = "\n".join(f"{k}: {v}" for k, v in (
        ("Gerät", _name(dev)), ("IP", dev.get("ip")), ("Hardware", dev.get("hardware")),
        ("Standort", dev.get("location")), ("OS", dev.get("os"))) if v)
    panel = doc.vertex(head, PANEL, x0, panel_y, panel_w, panel_h, tooltip=tip)
    # Hinterlegtes Modellbild bekommt mehr Platz als ein Klassensymbol — es ist
    # die Frontblende, die man wiedererkennen soll.
    icon_w = 170 if rule else 64
    doc.vertex("", device_style(dev, rules, label_below=False),
               x0 - icon_w - 14, panel_y + 2, icon_w, 38,
               tooltip=(rule.get("label") or tip) if rule else tip)

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

    _draw_devices(doc, above, cell, x0, panel_w, panel_y, panel_y + panel_h, True)
    used = _draw_devices(doc, below, cell, x0, panel_w, panel_y, panel_y + panel_h, False)
    if too_many:
        _device_table(doc, _name(dev), attached)
    return panel_y + panel_h + used + 40, panel_w


def render_switch(model: dict, title_block: dict | None = None,
                  rules: list[dict] | None = None) -> str:
    return render_switches([model], title_block, rules)


def render_switches(models: list[dict], title_block: dict | None = None,
                    rules: list[dict] | None = None, name: str | None = None) -> str:
    """Ein Panel je Switch, untereinander — für „alle Switches an Standort X".
    Ein Standort ist bei uns teils raumscharf gepflegt, dann ist das genau der
    Schrank, den jemand vor sich hat."""
    title = name or (f"Netzwerk physisch · {_name(models[0]['device'])}"
                     if models else "Netzwerk physisch")
    doc = Doc(title, page=A3_LANDSCAPE)
    x0, y = 60, 60
    widest = 0.0
    for model in models:
        y, w = _draw_panel(doc, model, x0, y, rules)
        widest = max(widest, w)
        y += 60
    if title_block:
        titleblock.draw(doc, x0 + widest + 80,
                        max(60.0, y - titleblock.HEIGHT), title_block)
    return doc.to_xml()
