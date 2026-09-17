"""Logische Netzdokumentation nach der Hausvorgabe (IEC-62443-Dokumentation).

Aus der Anforderung, Punkt für Punkt:

  * Netze als farbige Busleisten, jedes Netz eine eigene Farbe.
  * Je Netz die VLAN-ID und das Subnetz an der Leiste.
  * Endgeräte mit auf die signifikanten Stellen gekürzter IP — bei einem /24
    also `.73`, bei einem /16 `.58.73`.
  * KEINE Switche und keine einzelnen Ports: gezeichnet werden ausschließlich
    Router/Firewalls und Endgeräte. Ausgeblendete Switche werden gezählt und
    genannt, damit nichts stillschweigend verschwindet.
  * Wird die Geräteliste zu lang, steht je Geräteklasse EIN Symbol mit Anzahl
    und dem Verweis auf eine Tabelle; die Tabelle liegt auf einer eigenen
    Seite derselben Datei.
  * Druckformat DIN A3 quer.

Die Bänder sind die VDOMs: alle Netze eines VDOMs liegen hinter derselben
Firewall-Instanz und teilen damit deren Regelwerk — das ist die Grenze, die
in dieser Darstellung zählt.
"""
from __future__ import annotations

import ipaddress

from diagram import titleblock
from diagram.mx import A3_LANDSCAPE, Doc, esc

# Farben je Netz, in dieser Reihenfolge durchgereicht. Gewählt nach gut
# unterscheidbaren Farbtönen, die auf Papier ebenfalls tragen.
PALETTE = [
    ("#1f6fb4", "#d6e6f5"), ("#2e8b57", "#d9efe2"), ("#b8860b", "#f6ecd2"),
    ("#a03c3c", "#f5dcdc"), ("#6a4c93", "#e6dff0"), ("#0f7b7b", "#d5eeee"),
    ("#8a5a2b", "#efe2d5"), ("#41608a", "#dfe6f0"),
]
GREY = ("#999999", "#ededed")

BAND_HEAD = 34
BAR_H, BAR_GAP = 14, 118
HOST_W, HOST_H, ICON = 118, 46, 26
LABEL_W = 250
GAP = 24
MAX_HOSTS_DRAWN = 18          # darüber: je Klasse ein Symbol + Tabellenverweis
TABLE_ROW_H = 20

BAND = ("swimlane;html=1;startSize=34;fontStyle=1;fontSize=13;fillColor=#fafafa;"
        "strokeColor=#666666;")
BAR = "rounded=1;html=1;whiteSpace=wrap;fontSize=0;fillColor={fill};strokeColor={line};"
BAR_LABEL = ("text;html=1;align=left;verticalAlign=middle;fontSize=11;fontStyle=1;"
             "spacingLeft=6;fontColor={line};")
HOST = ("shape={stencil};html=1;aspect=fixed;fillColor={line};strokeColor=none;"
        "verticalLabelPosition=bottom;verticalAlign=top;fontSize=9;whiteSpace=wrap;")
GROUPED = ("rounded=1;html=1;whiteSpace=wrap;fontSize=9;fillColor={fill};"
           "strokeColor={line};fontColor=#333333;")
DROP = "html=1;endArrow=none;strokeColor={line};exitX=0.5;exitY=1;entryX=0.5;entryY=0;"
FW = ("shape=mxgraph.networks.firewall;html=1;aspect=fixed;fillColor=#b85450;"
      "strokeColor=none;verticalLabelPosition=bottom;verticalAlign=top;fontSize=11;")
UPLINK = ("html=1;endArrow=none;strokeColor=#b85450;dashed=1;fontSize=9;"
          "labelBackgroundColor=#ffffff;")
TABLE_HEAD = ("rounded=0;html=1;fillColor=#e8e8e8;strokeColor=#666666;fontStyle=1;"
              "fontSize=10;align=left;spacingLeft=6;")
TABLE_CELL = ("rounded=0;html=1;fillColor=#ffffff;strokeColor=#bbbbbb;fontSize=10;"
              "align=left;spacingLeft=6;")

STENCILS = {"server": "mxgraph.networks.server", "pc": "mxgraph.networks.pc",
            "switch": "mxgraph.networks.switch"}
CLASS_LABEL = {"server": "Server", "pc": "Endgerät", "switch": "Netzwerkgerät"}


def short_ip(ip: str, cidr: str) -> str:
    """IP auf die im Netz signifikanten Stellen kürzen: im /24 bleibt `.73`,
    im /16 `.58.73`. Das ist die Abkürzung, die die Anforderung verlangt —
    sie hält die Zeichnung lesbar, ohne mehrdeutig zu werden."""
    try:
        net = ipaddress.IPv4Network(cidr)
    except ValueError:
        return ip
    keep = max(1, min(4, (32 - net.prefixlen + 7) // 8))
    return "." + ".".join(ip.split(".")[-keep:])


def host_class(h: dict) -> str:
    kind = (h.get("kind") or "").lower()
    if kind in ("networkdevice", "switch"):
        return "switch"
    if kind == "server":
        return "server"
    desc = (h.get("description") or "").lower()
    if any(k in desc for k in ("server", "srv", "vm", "host")):
        return "server"
    return "pc"


def _colors(index: int, net: dict) -> tuple[str, str]:
    if not net.get("enabled", True) or net.get("link") is False:
        return GREY
    return PALETTE[index % len(PALETTE)]


def _bar_label(net: dict) -> str:
    bits = []
    if net.get("vlan") is not None:
        bits.append(f"VLAN {net['vlan']}")
    bits.append(net["cidr"])
    name = net.get("alias") or net.get("itop_name") or net.get("description")
    if name:
        bits.append(str(name))
    tail = ""
    if not net.get("enabled", True):
        tail = " · abgeschaltet"
    elif net.get("link") is False:
        tail = " · Link down"
    return esc(" · ".join(bits) + tail)


def _host_label(h: dict, cidr: str) -> str:
    name = h.get("name") or ""
    short = short_ip(h["ip"], cidr)
    return f"{esc(name)}<br>{esc(short)}" if name else esc(short)


def _host_tooltip(h: dict) -> str:
    rows = [("IP", h["ip"]), ("Name", h.get("name")), ("Typ", h.get("kind")),
            ("Beschreibung", h.get("description")), ("MAC", h.get("mac")),
            ("Quellen", ", ".join(h.get("sources") or []))]
    return "\n".join(f"{k}: {v}" for k, v in rows if v)


def _drawn_hosts(net: dict) -> list[dict]:
    """Switche fliegen raus — die Anforderung zeichnet in der logischen Sicht
    ausschließlich Router/Firewalls und Endgeräte."""
    return [h for h in net["hosts"] if host_class(h) != "switch"]


def render(model: dict, title_block: dict | None = None,
           max_hosts: int = MAX_HOSTS_DRAWN) -> str:
    sc = model["scope"]
    doc = Doc(sc.get("title") or "Netzplan (logisch)", page=A3_LANDSCAPE)
    tables: list[tuple[str, dict, list[dict]]] = []
    hidden_switches = 0
    x0, y0 = 40, 40
    y = y0
    color_index = 0

    for dev in model["devices"]:
        for vd in dev["vdoms"]:
            nets = vd["networks"]
            band_h = BAND_HEAD + GAP + max(1, len(nets)) * BAR_GAP
            band_w = max(HOST_W * 8, LABEL_W + 2 * GAP) + LABEL_W + 2 * GAP
            band = doc.vertex(f"{esc(dev['device'])} / {esc(vd['vdom'])}", BAND,
                              x0, y, band_w, band_h,
                              tooltip=f"{vd['id']} · {vd['network_count']} Netze")
            doc.vertex(esc(dev["device"]), FW, x0 - 96, y + BAND_HEAD + 8, 56, 40,
                       tooltip=f"FortiGate {dev['device']}"
                               + (f"\nHA {dev['ha']['mode']}" if dev.get("ha") else ""))

            by = BAND_HEAD + GAP
            for net in nets:
                line, fill = _colors(color_index, net)
                color_index += 1
                hosts = _drawn_hosts(net)
                hidden_switches += len(net["hosts"]) - len(hosts)
                grouped = len(hosts) > max_hosts
                cells = _group(hosts) if grouped else [(h, 1) for h in hosts]
                bar_w = max(len(cells) * HOST_W + GAP, 420)

                bar = doc.vertex("", BAR.format(fill=fill, line=line),
                                 GAP, by + HOST_H + 18, bar_w, BAR_H, parent=band,
                                 tooltip=_bar_label(net).replace(" · ", "\n"))
                doc.vertex(_bar_label(net), BAR_LABEL.format(line=line),
                           GAP + bar_w + 8, by + HOST_H + 8, LABEL_W, 34, parent=band)

                for i, (item, count) in enumerate(cells):
                    hx = GAP + i * HOST_W + (HOST_W - ICON) / 2
                    if count == 1:
                        cid = doc.vertex(_host_label(item, net["cidr"]),
                                         HOST.format(stencil=STENCILS[host_class(item)],
                                                     line=line),
                                         hx, by, ICON, ICON, parent=band,
                                         tooltip=_host_tooltip(item))
                    else:
                        label = (f"{count} × {CLASS_LABEL[item]}<br>"
                                 f"<span style='font-size:8px'>Tabelle {esc(net['cidr'])}</span>")
                        cid = doc.vertex(label, GROUPED.format(fill=fill, line=line),
                                         GAP + i * HOST_W, by, HOST_W - 10, HOST_H,
                                         parent=band,
                                         tooltip=f"{count} Geräte — siehe Tabellenseite "
                                                 f"{net['cidr']}")
                    doc.edge(cid, bar, "", DROP.format(line=line), parent=band)
                if grouped:
                    tables.append((f"{dev['device']}/{vd['vdom']}", net, hosts))
                by += BAR_GAP
            y += band_h + GAP

    # Uplink der Firewall: eine Wolke für den Weg nach draußen.
    if model["neighbors"]:
        cloud = doc.vertex("Uplink / andere Zonen",
                           "shape=mxgraph.networks.cloud;html=1;aspect=fixed;"
                           "fillColor=#b85450;strokeColor=none;"
                           "verticalLabelPosition=bottom;verticalAlign=top;fontSize=11;",
                           x0 - 120, y0 - 96, 104, 64,
                           tooltip="\n".join(n["label"] for n in model["neighbors"]))
        del cloud

    if title_block:
        info = dict(title_block)
        if hidden_switches:
            info["note"] = (info.get("note") or "") + \
                f"  ·  {hidden_switches} Switche nicht dargestellt (logische Sicht)"
        titleblock.draw(doc, x0 + 1200, max(y0, y - titleblock.HEIGHT), info)

    for band_name, net, hosts in tables:
        _table_page(doc, band_name, net, hosts)
    return doc.to_xml()


def _group(hosts: list[dict]) -> list[tuple[str, int]]:
    """Zu viele Geräte: je Klasse ein Symbol mit Anzahl."""
    counts: dict[str, int] = {}
    for h in hosts:
        cls = host_class(h)
        counts[cls] = counts.get(cls, 0) + 1
    return [(cls, n) for cls, n in sorted(counts.items(), key=lambda kv: -kv[1])]


def _table_page(doc: Doc, band: str, net: dict, hosts: list[dict]) -> None:
    """Gerätetabelle als eigene Seite — darauf verweist das Sammelsymbol."""
    doc.page(f"Tabelle {net['cidr']}")
    cols = [("IP", 140), ("Name", 240), ("Typ", 120), ("MAC", 150), ("Quellen", 200)]
    x, y = 40, 40
    doc.vertex(f"{esc(band)} · {esc(net['cidr'])}"
               + (f" · VLAN {net['vlan']}" if net.get("vlan") is not None else ""),
               "text;html=1;fontSize=14;fontStyle=1;align=left;", x, y - 28,
               sum(w for _c, w in cols), 24)
    cx = x
    for name, w in cols:
        doc.vertex(esc(name), TABLE_HEAD, cx, y, w, TABLE_ROW_H)
        cx += w
    for i, h in enumerate(sorted(hosts, key=lambda z: ipaddress.IPv4Address(z["ip"])), 1):
        cx = x
        values = [h["ip"], h.get("name") or "", CLASS_LABEL[host_class(h)],
                  h.get("mac") or "", ", ".join(h.get("sources") or [])]
        for (_name, w), value in zip(cols, values):
            doc.vertex(esc(value), TABLE_CELL, cx, y + i * TABLE_ROW_H, w, TABLE_ROW_H)
            cx += w
