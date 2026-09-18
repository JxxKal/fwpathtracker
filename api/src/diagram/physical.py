"""Physische Netzdokumentation nach der Hausvorgabe.

Gezeichnet wird eine Ebene: wie hängen die Netzwerkkomponenten untereinander?
Knoten sind die überwachten Geräte, Kanten die LLDP-Nachbarschaften mit den
Ports an beiden Enden. Die Anforderung nennt LLDP ausdrücklich als bevorzugte
Quelle — genau die liest LibreNMS.

Die zweite Ebene der Hausvorgabe — was hängt an EINEM Switch — ist hier nur
noch Modell, keine Zeichnung mehr: `switch_model` liefert Ports, FDB-Einträge
und Buchsenlage an die Switch-Ansicht in den Network Tools. Auf Papier war das
Blech entweder unlesbar klein oder die Leitungen liefen quer über alles; am
Bildschirm klickt man stattdessen die Buchse an.

Reine LibreNMS-Sicht: hier zählt das Kabel, nicht das Routing.
"""
from __future__ import annotations

import asyncio
import logging
import re

from diagram import titleblock
from diagram.mx import A3_LANDSCAPE, Doc, esc
from locate.mac import normalize_mac, readable_mac

log = logging.getLogger("diagram.physical")

# ── Zeichnung: LLDP-Topologie ────────────────────────────────────────────────
NODE_W, NODE_H, ICON_H = 170, 40, 40
ROW_GAP, COL_GAP = 190, 200
NODE = ("shape={stencil};html=1;aspect=fixed;fillColor={color};strokeColor=#ffffff;"
        "strokeWidth=1;verticalLabelPosition=bottom;verticalAlign=top;fontSize=10;"
        "whiteSpace=wrap;")
LINK = ("edgeStyle=orthogonalEdgeStyle;rounded=0;html=1;endArrow=none;fontSize=9;"
        "labelBackgroundColor=#ffffff;strokeColor=#6c8ebf;")

# Logische Interfaces gehören nicht in die Buchsenliste: sie haben keine Buchse.
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

# ── Buchsenlage im Modellbild ────────────────────────────────────────────────
# Ein Bild allein trägt keine Information: die Belegung muss an der richtigen
# Buchse landen. Dafür trägt eine Shape-Regel die Lage jeder Buchse im Bild.
# Ältere Regeln beschreiben sie als Raster (Mittelpunkt der ersten Buchse,
# Abstand, Spalten, Reihen, Zählrichtung), neuere Punkt für Punkt.
#
# Stack-Namen: <Name><Einheit>/<Slot>/<Port>. Nur bei DREI Zahlengruppen ist
# die erste die Stack-Einheit — `Gi0/1` ist Slot/Port auf einem Einzelgerät.
UNIT_RE = re.compile(r"^(\D*)(\d+)/(\d+)/(\d+)$")
DNS_MAX, DNS_CONCURRENCY = 300, 16


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


def location_name(value) -> str | None:
    """Standort als Zeichenkette.

    LibreNMS liefert das Feld je nach Version als Text ODER als eingebettetes
    Objekt ({id, location, lat, lng, …}). Ungeprüft durchgereicht landet das
    Objekt in der Oberfläche, und React bricht die Ansicht ab („Objects are
    not valid as a React child"). Hier wird es zu dem, was es meint.
    """
    if isinstance(value, dict):
        value = value.get("location")
    text = str(value or "").strip()
    return text or None


def clean_name(value) -> str | None:
    """Ein brauchbarer Gerätename — oder nichts.

    Manche Geräte liefern als sysName Müll: Steuerzeichen, Füllbytes, eine
    Reihe von Punkten. LibreNMS reicht das unverändert weiter, und in der
    Auswahlliste stehen dann drei Einträge „..............................",
    die niemand auseinanderhalten kann. Ein Name ohne einen einzigen Buchstaben
    oder eine Ziffer benennt nichts — dann ist die IP die ehrlichere Antwort.
    """
    text = "".join(c for c in str(value or "") if c.isprintable()).strip()
    return text if any(c.isalnum() for c in text) else None


def _name(dev: dict) -> str:
    return (clean_name(dev.get("sysName")) or clean_name(dev.get("hostname"))
            or clean_name(dev.get("ip")) or clean_name(dev.get("device_id")) or "?")


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


async def allowed_devices(client, cfg: dict, location: str | None,
                          group: str | None) -> set[str] | None:
    """Erlaubte LibreNMS-Geräte-Ids für Standort bzw. Gruppe — None heißt: alle.

    Gefiltert wird von LibreNMS selbst: das Standortfeld heißt je nach Version
    anders, der Filter nicht. Sind beide gesetzt, gilt der Schnitt.
    """
    sets: list[set[str]] = []
    if location:
        rows = await client.devices_by_location(cfg, location)
        sets.append({str(d.get("device_id")) for d in rows if d.get("device_id")})
    if group:
        rows = await client.devices_in_group(cfg, group)
        sets.append({str(d.get("device_id")) for d in rows if d.get("device_id")})
    if not sets:
        return None
    return set.intersection(*sets)


# ── Modell: LLDP-Topologie ───────────────────────────────────────────────────

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


# ── Modell: Geräte an einem Switch (Switch-Ansicht, keine Zeichnung) ────────

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
        # Nacheinander wären das 300 × 1,5 s Zeitüberschreitung — über sieben
        # Minuten, in denen die Ansicht scheinbar hängt. Also parallel und
        # gedeckelt; ein fehlender Name kostet nur den Namen.
        todo = [h for p in out for h in p["hosts"] if not h.get("name") and h.get("ip")][:DNS_MAX]
        sem = asyncio.Semaphore(DNS_CONCURRENCY)

        async def resolve(host: dict) -> None:
            async with sem:
                try:
                    name = await dns(host["ip"])
                except Exception:
                    return
            if name:
                host["name"] = name

        await asyncio.gather(*(resolve(h) for h in todo))
    if not out:
        warnings.append("Keine physischen Ports zu diesem Gerät in LibreNMS.")
    return {"device": dev, "ports": out, "logical": logical}
