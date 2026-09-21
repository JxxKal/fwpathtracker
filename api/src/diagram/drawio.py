"""draw.io-Renderer: Netzplan-Modell → mxGraph-XML (unkomprimierte .drawio-Datei).

Layout ist ein Schichtenmodell, das draw.io nicht selbst mitbringt — von
außen nach innen:
    Standort-Container (nur wenn der Scope mehrere Standorte zeigt)
      └ Firewall-Container
          └ VDOM-Container
              └ Netz-Kästen im Raster, darin die Hosts als Liste (einklappbar,
                ab HOST_COLLAPSE zugeklappt — der Plan bleibt lesbar, die Hosts
                sind trotzdem drin)
    im VDOM oben: die Uplink-Marke — wohin dieses VDOM nach außen koppelt
    unter jeder Firewall: ihre Switches per LLDP

Was AUSSERHALB des Scopes liegt, wird nicht mehr als Symbol gezeichnet. Eine
Firewall am Bildrand und eine Linie quer über das halbe Blatt sagen weniger als
eine Zeile an der Stelle, an der die Kopplung entsteht: bei vier Uplinks kreuzen
sich die Linien, laufen durch Netz-Kästen und treffen sich in einem Punkt, an
dem niemand mehr auseinanderhält, welche zu welchem VDOM gehört. Die Angabe
steht deshalb im VDOM selbst.
Gerechnet wird von innen nach außen: erst die Netz-Kästen, daraus die Größe
des VDOMs, daraus die der Firewall, daraus die des Standorts.

Jeder Knoten trägt einen Tooltip mit allem, was die Quellen wissen — die
Zeichnung ist damit gleichzeitig der Abgleich von FMG, iTop und LibreNMS.
"""
from __future__ import annotations

from diagram import titleblock
from diagram.mx import Doc as _Doc, esc as _esc

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
# Uplink-Marke im VDOM: Kopfzeile + eine Zeile je Kopplung nach außen.
UPLINK_HEAD, UPLINK_ROW, UPLINK_PAD = 18, 15, 8
UPLINK_MAX_ROWS = 6

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
    # HA-Cluster: kräftigerer Rahmen am Container plus ein Abzeichen neben dem
    # Symbol. Zwei Geräte, die als eines arbeiten, soll man im Plan sehen,
    # ohne den Tooltip zu öffnen.
    "ha": "rounded=1;html=1;whiteSpace=wrap;fontSize=10;fontStyle=1;"
          "fillColor=#d4e1f5;strokeColor=#3d6ea8;fontColor=#1f3f66;",
    "net": "swimlane;html=1;startSize=48;fontSize=10;align=left;spacingLeft=6;"
           "fillColor=#d5e8d4;strokeColor=#82b366;collapsible=1;",
    # Interface im Shutdown: dasselbe Netz, aber sichtbar stillgelegt — grau
    # und gestrichelt, damit es niemand für ein aktives Segment hält.
    "net-off": "swimlane;html=1;startSize=48;fontSize=10;align=left;spacingLeft=6;"
               "fillColor=#ededed;strokeColor=#999999;fontColor=#666666;dashed=1;"
               "collapsible=1;",
    # Konfiguriert und eingeschaltet, aber ohne Link: kein Kabel, kein Gegenüber.
    # Anderer Zustand als Shutdown, deshalb andere Farbe — bernstein wie die
    # Warnungen im Tracker.
    "net-down": "swimlane;html=1;startSize=48;fontSize=10;align=left;spacingLeft=6;"
                "fillColor=#fff2cc;strokeColor=#d6b656;fontColor=#7a5c00;dashed=1;"
                "collapsible=1;",
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
    # Uplink-Marke: rot wie die WAN-Kanten früher, damit die Farbsprache bleibt.
    "uplink": "rounded=1;html=1;align=left;verticalAlign=top;spacingLeft=6;spacingTop=2;"
              "fontSize=9;fillColor=#f8e4e4;strokeColor=#b85450;fontColor=#8a3b3b;"
              "dashed=1;whiteSpace=wrap;",
}


# Symbol → (Stencil, Malstil). Die Network-Bibliothek ist flächig (nur Füllung);
# der Cisco-Switch ist ein Linien-Piktogramm und braucht Füllung + weiße Linien.
SHAPES = {
    "firewall": ("mxgraph.networks.firewall", "fillColor=#b85450;strokeColor=none;"),
    "switch": ("mxgraph.cisco.switches.workgroup_switch",
               "fillColor=#9673a6;strokeColor=#ffffff;strokeWidth=1;"),
    "server": ("mxgraph.networks.server", "fillColor=#29AAE1;strokeColor=none;"),
    "pc": ("mxgraph.networks.pc", "fillColor=#6c8ebf;strokeColor=none;"),
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
    name = _esc(head or net["interface"])
    if not net.get("enabled", True):
        name += " <span style='font-weight:normal'>· abgeschaltet</span>"
    elif net.get("link") is False:
        name += " <span style='font-weight:normal'>· Link down</span>"
    return (f"<b>{name}</b><br>"
            f"{_esc(net['cidr'])} · GW {_esc(net['fw_ip'])}<br>{_esc(tail)}")


def _net_tooltip(net: dict) -> str:
    rows = [("Interface", net["interface"]),
            ("Status", "abgeschaltet (shutdown)" if not net.get("enabled", True)
             else "Link down (konfiguriert, aber kein Link)" if net.get("link") is False
             else None),
            ("Netz", net["cidr"]), ("Firewall-IP", net["fw_ip"]),
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

KIND_WORD = {"overlay": "Overlay", "transit": "Transit", "default": "Default"}


def _short_target(nid: str) -> str:
    """`EUGEBA1-FW-10001-1-OT/L3` → `EUGEBA1-FW-10001-1-OT / L3`. Der Name ist
    lang, aber er ist die Auskunft — gekürzt wird er nicht, nur lesbar
    gesetzt."""
    dev, _, vdom = nid.partition("/")
    return f"{dev} / {vdom}" if vdom else dev


def uplinks(model: dict) -> dict[str, list[dict]]:
    """Je VDOM seine Kopplungen nach außen — Default-Route, Transit, Overlay.

    „Außen" heißt: das Gegenüber liegt nicht im Scope und wäre deshalb ein
    freistehendes Symbol am Blattrand. Kopplungen INNERHALB des Scopes bleiben
    Linien; die sind kurz und sagen genau das, was eine Linie gut sagt.
    """
    in_scope = {vd["id"] for dev in model["devices"] for vd in dev["vdoms"]}
    labels = {n["id"]: n.get("label") or n["id"] for n in model["neighbors"]}
    out: dict[str, list[dict]] = {}
    for e in model["edges"]:
        near, far = e["from"], e["to"]
        if near not in in_scope:
            near, far = far, near
        if near not in in_scope or far in in_scope:
            continue
        word = KIND_WORD.get(e["kind"], e["kind"])
        if e["kind"] == "default":
            text = e["label"]                      # trägt „Default via …" schon
            tip = f"{e['label']}\n{labels.get(far, far)}"
        else:
            text = f"{word} → {_short_target(far)}"
            tip = f"{word} über {e.get('via') or '?'}\n{_short_target(far)}\n{e['label']}"
        out.setdefault(near, []).append({"text": text, "tooltip": tip, "kind": e["kind"]})
    for rows in out.values():
        # Default zuerst: der Weg nach draußen ist die häufigste Frage.
        rows.sort(key=lambda r: (r["kind"] != "default", r["text"]))
    return out


def _uplink_height(rows: list[dict]) -> float:
    if not rows:
        return 0.0
    shown = min(len(rows), UPLINK_MAX_ROWS) + (1 if len(rows) > UPLINK_MAX_ROWS else 0)
    return UPLINK_HEAD + shown * UPLINK_ROW + UPLINK_PAD


def _uplink_label(rows: list[dict], title: str) -> str:
    shown = rows[:UPLINK_MAX_ROWS]
    lines = [f"<b>{_esc(title)}</b>"]
    lines += [_esc(r["text"]) for r in shown]
    if len(rows) > len(shown):
        lines.append(_esc(f"… +{len(rows) - len(shown)} weitere"))
    return "<br>".join(lines)


def _measure_vdom(vd: dict, with_networks: bool,
                  collapse: bool = True, up_h: float = 0.0) -> tuple[tuple[float, float], list]:
    """Größe eines VDOM-Containers + Platzierung seiner Netz-Kästen (eine Spalte)."""
    nets = vd["networks"] if with_networks else []
    top = VDOM_HEAD + NET_M + (up_h + NET_SPACING if up_h else 0)
    if not nets:
        return (max(VDOM_MIN_W, NET_W + 2 * NET_M if up_h else VDOM_MIN_W),
                top - NET_SPACING + NET_M if up_h else VDOM_HEAD + 2 * NET_M), []
    placed = []
    y = top
    for net in nets:
        full, short = _net_height(net)
        collapsed = collapse and bool(net["hosts"])
        h = short if collapsed else full
        placed.append((net, NET_M, y, h, collapsed, full, short))
        y += h + NET_SPACING
    return (NET_W + 2 * NET_M, y - NET_SPACING + NET_M), placed


def _measure_device(dev: dict, with_networks: bool, collapse: bool = True,
                    ups: dict[str, list[dict]] | None = None
                    ) -> tuple[tuple[float, float], tuple[float, float], list]:
    """(Platzbedarf inkl. Symbol und Switch-Spalte, Container-Maß, VDOM-Kinder)."""
    ups = ups or {}
    measured = [_measure_vdom(vd, with_networks, collapse,
                              _uplink_height(ups.get(vd["id"], [])))
                for vd in dev["vdoms"]]
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


def _measure_site(group: dict, with_networks: bool, collapse: bool = True,
                  ups: dict[str, list[dict]] | None = None
                  ) -> tuple[tuple[float, float], list]:
    measured = [_measure_device(d, with_networks, collapse, ups) for d in group["devices"]]
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
               with_networks: bool, up_rows: list[dict] | None = None,
               up_title: str = "Uplink") -> None:
    label = _esc(vd["vdom"]) if with_networks else \
        f"{_esc(vd['vdom'])} <span style='color:#888'>· {vd['network_count']} Netze</span>"
    vd_id = doc.vertex(label, STYLE["vdom"], x, y, size[0], size[1], parent=parent,
                       tooltip=f"VDOM {vd['id']} · {vd['network_count']} Netze")
    cell_of[vd["id"]] = vd_id
    # Die Uplink-Marke steht VOR den Netzen: sie gehört zum VDOM als Ganzem und
    # ist im Stack-Layout damit die oberste Zeile.
    if up_rows:
        doc.vertex(_uplink_label(up_rows, up_title), STYLE["uplink"],
                   NET_M, VDOM_HEAD + NET_M, NET_W, _uplink_height(up_rows) - UPLINK_PAD,
                   parent=vd_id,
                   tooltip="\n\n".join(r["tooltip"] for r in up_rows))
    for net, nx, ny, nh, collapsed, full, short in nets:
        if not net.get("enabled", True):
            style = STYLE["net-off"]
        elif net.get("link") is False:
            style = STYLE["net-down"]
        else:
            style = STYLE["net"]
        net_id = doc.vertex(_net_label(net), style, nx, ny, NET_W, nh, parent=vd_id,
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


def _ha_text(ha: dict) -> tuple[str, str]:
    """(Abzeichen, Tooltip) für ein Gerät im HA-Cluster."""
    n = len(ha["members"])
    badge = f"HA {_esc(ha['mode'])}" + (f" · {n} Knoten" if n else "")
    lines = [f"HA-Cluster ({ha['mode']})"]
    if ha.get("group"):
        gid = f" (ID {ha['group_id']})" if ha.get("group_id") is not None else ""
        lines.append(f"Gruppe: {ha['group']}{gid}")
    for m in ha["members"]:
        bits = [m["name"]]
        if m.get("role"):
            bits.append(m["role"])
        if m.get("serial"):
            bits.append(m["serial"])
        if m.get("up") is not None:
            bits.append("up" if m["up"] else "down")
        lines.append(" · ".join(bits))
    return badge, "\n".join(lines)


def _draw_device(doc: _Doc, dev: dict, parent: str, x: float, y: float,
                 box: tuple[float, float], vdoms: list, cell_of: dict,
                 with_networks: bool, ups: dict[str, list[dict]] | None = None,
                 up_title: str = "Uplink") -> None:
    """Symbol über dem Container, VDOMs darin, Switches rechts daneben. Der
    Container enthält NUR VDOMs — alles andere würde das Stack-Layout mit
    einreihen."""
    ha = dev.get("ha")
    tip = " · ".join(p for p in (f"FortiGate {dev['device']}",
                                 f"ADOM {dev['adom']}" if dev.get("adom") else None,
                                 dev.get("site")) if p)
    if ha:
        badge, ha_tip = _ha_text(ha)
        tip = f"{tip}\n\n{ha_tip}"
    doc.vertex("", icon_style("firewall").replace(
        "verticalLabelPosition=bottom;verticalAlign=top;", ""), x, y, 44, 28,
        parent=parent, tooltip=tip)
    label = _esc(dev["device"])
    style = STYLE["fw"]
    if ha:
        doc.vertex(badge, STYLE["ha"], x + 52, y + 1, 150, 26, parent=parent, tooltip=ha_tip)
        style = style.replace("strokeColor=#6c8ebf;", "strokeColor=#3d6ea8;strokeWidth=3;")
    fw_id = doc.vertex(label, style, x, y + DEV_ICON_H, box[0], box[1],
                       parent=parent, tooltip=tip)
    cell_of[f"device:{dev['device']}"] = fw_id
    for vd, vx, vy, vsize, nets in vdoms:
        _draw_vdom(doc, vd, fw_id, vx, vy, vsize, nets, cell_of, with_networks,
                   (ups or {}).get(vd["id"]), up_title)
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


def render(model: dict, collapse: bool = True, title_block: dict | None = None,
           uplink_title: str = "Uplink") -> str:
    """collapse=False zeichnet die Hostlisten offen — für Ausdruck und PDF, wo
    niemand klicken kann. Die Zeichnung wird dann entsprechend groß.

    title_block: Schriftfeld unten rechts (siehe titleblock.info_from).
    uplink_title: Überschrift der Uplink-Marke — wer den Weg nach draußen
    betreibt, heißt bei jedem anders (Provider, „WAN", ein Produktname)."""
    doc = _Doc(model["scope"].get("title") or "Netzplan")
    cell_of: dict[str, str] = {}
    with_networks = model.get("with_networks", True)

    ups = uplinks(model)
    measured = [_measure_site(g, with_networks, collapse, ups) for g in model["sites"]]
    pos, total_w, _total_h = _pack([m[0] for m in measured], SITES_PER_ROW)
    x0, y0 = 40, 40
    for group, (px, py), (size, devs) in zip(model["sites"], pos, measured):
        gx, gy = x0 + px, y0 + py
        if group["name"]:
            tip = f"Standort {group['name']} · {len(group['devices'])} Firewalls"
            if group.get("description"):
                tip += f"\n{group['description']}"
            parent = doc.vertex(_esc(group["name"]), STYLE["site"], gx, gy, size[0], size[1],
                                tooltip=tip)
            cell_of[f"site:{group['name']}"] = parent
            ox, oy = 0.0, 0.0
        else:
            parent, ox, oy = "1", gx, gy
        for dev, dx, dy, box, vdoms in devs:
            _draw_device(doc, dev, parent, ox + dx, oy + dy, box, vdoms, cell_of,
                         with_networks, ups, uplink_title)

    # Kein Symbol für das, was außerhalb des Scopes liegt: die Kopplung steht
    # als Zeile im VDOM (siehe uplinks). Damit endet keine Linie am Blattrand.

    # ── Schriftfeld ────────────────────────────────────────────────────────
    # NEBEN die Zeichnung, nicht darunter: Container wachsen beim Aufklappen
    # nach unten, und ein Schriftfeld auf festen Koordinaten läge dann mitten
    # in der Hostliste. Rechts daneben kann das nie passieren — die Breite
    # ändert sich beim Aufklappen nicht. Unterkante bündig mit der Zeichnung,
    # damit es im geschlossenen Zustand unten rechts steht, wo es hingehört.
    if title_block:
        bottom = y0 + _total_h
        titleblock.draw(doc, x0 + total_w + 2 * GAP,
                        max(y0, bottom - titleblock.HEIGHT), title_block)

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
