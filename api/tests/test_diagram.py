"""Netzplan: Modell aus dem Lab-Inventar, Detailstufen, draw.io-Ausgabe."""
from __future__ import annotations

import re

import xml.etree.ElementTree as ET

import pytest

from diagram import drawio, model


async def _arp(cidr: str) -> list[dict]:
    if cidr == "10.1.1.0/24":
        return [{"ip": "10.1.1.77", "mac": "000c29aabbcc", "last_seen": "2026-09-01T10:00:00+00:00",
                 "age_s": 3600}]
    return []


ITOP_HOSTS = [
    {"name": "srv-web", "ip": "10.1.1.10", "description": "Webserver", "kind": "Server"},
    {"name": "sw-core", "ip": "10.1.1.2", "description": "", "kind": "NetworkDevice"},
]
ITOP_SUBNETS = [{"id": "5", "cidr": "10.1.1.0/24", "name": "Server-LAN", "gateway": "10.1.1.1"}]


async def _build(inventory, prefixes, **kw):
    args = dict(scope="vdom", device="fw-a", vdom="root", hosts="auto",
                itop_subnets=ITOP_SUBNETS, itop_hosts=ITOP_HOSTS,
                itop_addresses={"10.1.1.20": {"status": "allocated", "name": "plc-20"},
                                "10.1.1.21": {"status": "released", "name": "alt"}},
                arp=_arp)
    args.update(kw)
    return await model.build(inventory, prefixes, **args)


async def test_vdom_scope_has_networks_neighbors_and_hosts(inventory, prefixes):
    m = await _build(inventory, prefixes)
    assert [v["id"] for v in m["vdoms"]] == ["fw-a/root"]
    assert [d["device"] for d in m["devices"]] == ["fw-a"]
    nets = {n["cidr"]: n for n in m["vdoms"][0]["networks"]}
    assert {"10.1.1.0/24", "10.1.2.0/24", "203.0.113.0/30", "10.99.0.0/30"} <= set(nets)
    lan1 = nets["10.1.1.0/24"]
    assert lan1["zone"] == "inside-a" and lan1["itop_name"] == "Server-LAN"
    ips = {h["ip"]: h for h in lan1["hosts"]}
    assert set(ips) == {"10.1.1.10", "10.1.1.2", "10.1.1.20", "10.1.1.77"}   # released fehlt, FW-IP fehlt
    assert ips["10.1.1.77"]["sources"] == ["arp"] and ips["10.1.1.77"]["mac"] == "000c29aabbcc"
    assert ips["10.1.1.2"]["kind"] == "NetworkDevice"
    kinds = {e["kind"] for e in m["edges"]}
    assert {"vdom-link", "overlay", "default"} <= kinds
    targets = {e["to"] for e in m["edges"]}
    assert "fw-a/dmz" in targets and "fw-b/root" in targets     # VDOM-Link + Route übers Overlay
    assert any(n["kind"] == "default" for n in m["neighbors"])
    assert m["hosts_mode"] == "all" and m["stats"]["hosts_shown"] == 4


async def test_netdev_mode_keeps_only_network_devices(inventory, prefixes):
    m = await _build(inventory, prefixes, hosts="netdev")
    lan1 = next(n for n in m["vdoms"][0]["networks"] if n["cidr"] == "10.1.1.0/24")
    assert [h["ip"] for h in lan1["hosts"]] == ["10.1.1.2"]


async def test_auto_falls_back_to_netdev_above_the_limit(inventory, prefixes):
    m = await _build(inventory, prefixes, max_hosts=2)
    assert m["hosts_mode"] == "netdev" and m["stats"]["hosts_reduced"]
    assert m["stats"]["hosts_found"] == 4 and m["stats"]["hosts_shown"] == 1


async def test_none_mode_draws_only_networks(inventory, prefixes):
    m = await _build(inventory, prefixes, hosts="none")
    assert all(not n["hosts"] for v in m["vdoms"] for n in v["networks"])
    assert m["stats"]["hosts_found"] == 0


async def test_firewall_scope_covers_all_vdoms(inventory, prefixes):
    m = await _build(inventory, prefixes, scope="firewall", vdom=None)
    assert [v["id"] for v in m["vdoms"]] == ["fw-a/root", "fw-a/dmz"]
    # Der VDOM-Link zwischen root und dmz ist jetzt scope-intern: kein Nachbar dafür.
    assert all(n["id"] != "fw-a/dmz" for n in m["neighbors"])


async def test_unknown_device_or_vdom_is_an_error(inventory, prefixes):
    with pytest.raises(ValueError):
        await _build(inventory, prefixes, device="fw-x")
    with pytest.raises(ValueError):
        await _build(inventory, prefixes, vdom="nope")
    with pytest.raises(ValueError):
        await _build(inventory, prefixes, scope="nonsense")


SITES = [{"name": "Standort A", "cidr": "10.1.0.0/20"},
         {"name": "Standort B", "cidr": "10.2.0.0/20"}]


async def test_site_scope_collects_every_vdom_of_that_site(inventory, prefixes):
    m = await _build(inventory, prefixes, scope="site", site="Standort A", device=None,
                     vdom=None, sites=SITES)
    assert sorted(v["id"] for v in m["vdoms"]) == ["fw-a/dmz", "fw-a/root"]
    assert [g["name"] for g in m["sites"]] == ["Standort A"]
    assert m["scope"]["title"] == "Netzplan Standort Standort A"
    # fw-b hält 10.2.x — es gehört zu Standort B und erscheint nur als Nachbar.
    assert any(n["id"] == "fw-b/root" and n["site"] == "Standort B" for n in m["neighbors"])


async def test_unknown_site_is_an_error(inventory, prefixes):
    with pytest.raises(ValueError):
        await _build(inventory, prefixes, scope="site", site="Mond", device=None,
                     vdom=None, sites=SITES)
    with pytest.raises(ValueError):       # Scope 'site' ohne Standortnamen
        await _build(inventory, prefixes, scope="site", site=None, device=None,
                     vdom=None, sites=SITES)


async def test_global_scope_groups_by_site_and_drops_networks(inventory, prefixes):
    m = await _build(inventory, prefixes, scope="global", device=None, vdom=None, sites=SITES)
    assert m["hosts_mode"] == "none" and m["with_networks"] is False
    assert {d["device"] for d in m["devices"]} == {"fw-a", "fw-b", "fw-c", "fw-d", "fw-e"}
    groups = {g["name"] for g in m["sites"]}
    assert {"Standort A", "Standort B"} <= groups
    # Ohne Supernetz-Treffer landen Geräte in der Sammelgruppe — sichtbar, nicht still.
    assert "ohne Standort" in groups
    # Netze werden nicht gezeichnet, aber gezählt.
    assert all(v["networks"] == [] for v in m["vdoms"])
    assert m["stats"]["networks"] > 0 and m["stats"]["hosts_found"] == 0
    # Alles ist im Scope → als Nachbar bleibt nur das Internet.
    assert [n["kind"] for n in m["neighbors"]] == ["default"]
    # Die Standortkopplung ist die eigentliche Aussage des Gesamtplans.
    assert any(e["kind"] == "overlay" and e["from"] == "fw-a/root" and e["to"] == "fw-b/root"
               for e in m["edges"])


async def test_global_xml_has_site_containers(inventory, prefixes):
    m = await _build(inventory, prefixes, scope="global", device=None, vdom=None, sites=SITES)
    root = ET.fromstring(drawio.render(m))
    labels = [o.get("label", "") for o in root.findall(".//object")]
    assert "Standort A" in labels and "fw-a" in labels
    # VDOM-Köpfe nennen im Gesamtplan die Netzanzahl statt der Netze selbst.
    assert any("Netze" in lbl for lbl in labels)
    site_cells = [c for c in root.findall(".//mxCell") if "swimlane" in (c.get("style") or "")
                  and "dashed=1" in (c.get("style") or "")]
    assert len(site_cells) >= 2


async def test_drawio_xml_is_well_formed_and_complete(inventory, prefixes):
    m = await _build(inventory, prefixes)
    xml = drawio.render(m)
    root = ET.fromstring(xml)
    assert root.tag == "mxfile"
    cells = root.findall(".//mxCell")
    objects = root.findall(".//object")
    labels = " ".join(o.get("label", "") for o in objects)
    assert "fw-a" in labels and "10.1.1.0/24" in labels and "srv-web" in labels
    tips = " ".join(o.get("tooltip", "") for o in objects)
    assert "000c29aabbcc" in tips and "Server-LAN" in tips
    edges = [c for c in cells if c.get("edge") == "1"]
    assert len(edges) >= 3
    # Symbole aus der draw.io-Network-Bibliothek: Server, Switch, Firewall, Wolke.
    styles = " ".join(c.get("style", "") for c in cells)
    for shape in ("mxgraph.networks.server", "mxgraph.cisco.switches.workgroup_switch",
                  "mxgraph.networks.firewall", "mxgraph.networks.cloud"):
        assert shape in styles, shape
    # Jede Kante zeigt auf existierende Zellen.
    ids = {o.get("id") for o in objects} | {c.get("id") for c in cells}
    assert all(e.get("source") in ids and e.get("target") in ids for e in edges)


async def test_every_network_with_hosts_starts_collapsed(inventory, prefixes):
    """Beim Öffnen zählt die Struktur, nicht die Hostliste — Netze MIT Hosts
    starten zugeklappt, Netze ohne haben nichts zum Aufklappen."""
    m = await _build(inventory, prefixes)
    root = ET.fromstring(drawio.render(m))
    nets = {}
    for obj in root.findall(".//object"):
        cell = obj.find("mxCell")
        if "fillColor=#d5e8d4" in (cell.get("style") or ""):
            nets[obj.get("label")] = cell.get("collapsed") == "1"
    lan1 = next(k for k in nets if "10.1.1.0/24" in k)
    lan2 = next(k for k in nets if "10.1.2.0/24" in k)
    assert nets[lan1] is True and "4 Hosts" in lan1     # Anzahl steht am Kasten
    assert nets[lan2] is False and "Hosts" not in lan2  # ohne Hosts: nichts zu holen


async def test_many_hosts_collapse_the_network_box(inventory, prefixes):
    hosts = [{"name": f"h{i}", "ip": f"10.1.1.{i}", "description": "", "kind": "Server"}
             for i in range(10, 90)]
    m = await _build(inventory, prefixes, itop_hosts=hosts, itop_addresses={}, arp=_arp)
    xml = drawio.render(m)
    root = ET.fromstring(xml)
    collapsed = [c for c in root.findall(".//mxCell") if c.get("collapsed") == "1"]
    assert len(collapsed) == 1
    assert "+20 weitere" in " ".join(o.get("label", "") for o in root.findall(".//object"))


def _geo(cell):
    g = cell.find("mxGeometry")
    return tuple(float(g.get(k, 0)) for k in ("x", "y", "width", "height"))


async def test_containers_carry_the_stack_layout_that_reflows_on_expand(inventory, prefixes):
    """Ohne childLayout=stackLayout überdeckt ein aufgeklapptes Netz alles, was
    darunter liegt — die Positionen sind sonst fest. resizeParentMax=0 sorgt
    dafür, dass der Container beim Zuklappen wieder schrumpft."""
    m = await _build(inventory, prefixes)
    root = ET.fromstring(drawio.render(m))
    cells = root.findall(".//mxCell")
    fw = [c for c in cells if "fillColor=#dae8fc" in (c.get("style") or "")]
    vd = [c for c in cells if "fillColor=#f5f5f5" in (c.get("style") or "")]
    assert fw and vd
    for c in fw + vd:
        style = c.get("style")
        assert "childLayout=stackLayout" in style
        assert "resizeParent=1" in style and "resizeParentMax=0" in style
    assert "horizontalStack=1" in fw[0].get("style")    # VDOMs nebeneinander
    assert "horizontalStack=0" in vd[0].get("style")    # Netze untereinander


async def test_networks_are_one_column_and_do_not_overlap(inventory, prefixes):
    """Die vorberechnete Geometrie muss der entsprechen, die das Stack-Layout
    selbst erzeugen würde — sonst springt die Zeichnung beim ersten Klick."""
    hosts = [{"name": f"h{i}", "ip": f"10.1.1.{i}", "description": "", "kind": "Server"}
             for i in range(10, 40)]
    m = await _build(inventory, prefixes, itop_hosts=hosts, itop_addresses={})
    root = ET.fromstring(drawio.render(m))
    nets = [c for c in root.findall(".//mxCell") if "fillColor=#d5e8d4" in (c.get("style") or "")]
    assert len(nets) >= 3
    by_parent: dict[str, list] = {}
    for c in nets:
        by_parent.setdefault(c.get("parent"), []).append(_geo(c))
    for boxes in by_parent.values():
        boxes.sort(key=lambda g: g[1])
        assert len({g[0] for g in boxes}) == 1          # eine Spalte
        for a, b in zip(boxes, boxes[1:]):
            assert b[1] >= a[1] + a[3]                  # kein Überlappen


async def test_expanded_rendering_keeps_the_boxes_open_and_apart(inventory, prefixes):
    """Für Ausdruck/PDF: collapse=False zeichnet die Hostlisten offen — und die
    Kästen müssen dann von vornherein den vollen Platz bekommen."""
    m = await _build(inventory, prefixes)
    root = ET.fromstring(drawio.render(m, collapse=False))
    cells = [c for c in root.findall(".//mxCell") if "fillColor=#d5e8d4" in (c.get("style") or "")]
    assert cells and not any(c.get("collapsed") == "1" for c in cells)
    by_parent: dict[str, list] = {}
    for c in cells:
        by_parent.setdefault(c.get("parent"), []).append(_geo(c))
    for boxes in by_parent.values():
        boxes.sort(key=lambda g: g[1])
        for a, b in zip(boxes, boxes[1:]):
            assert b[1] >= a[1] + a[3]
    # Offen ist höher als zugeklappt — sonst wäre nichts zu sehen.
    closed = ET.fromstring(drawio.render(m))
    tall = max(_geo(c)[3] for c in cells)
    short = max(_geo(c)[3] for c in closed.findall(".//mxCell")
                if "fillColor=#d5e8d4" in (c.get("style") or ""))
    assert tall > short


TB = {"company": "Beispiel AG", "confidential": "Company confidential",
      "group": "WD2/DR PLT/IT OT", "drawing_no_prefix": "A38"}


async def test_title_block_carries_what_a38_knows_itself(inventory, prefixes):
    """Titel, Zahlen, Datum, Autor und Zeichnungsnummer soll niemand tippen —
    die kennt A38. Firma, Vermerk und Gruppe sind Stammdaten."""
    from datetime import date
    from diagram import titleblock
    m = await _build(inventory, prefixes)
    info = titleblock.info_from(TB, title=m["scope"]["title"], subtitle="Scope VDOM · 4 Netze",
                                author="jkaluza", drawing_no="A38-FW-A_ROOT")
    root = ET.fromstring(drawio.render(m, title_block=info))
    labels = [o.get("label", "") for o in root.findall(".//object")]
    text = " | ".join(labels)
    assert "Netzplan fw-a/root" in text and "Scope VDOM · 4 Netze" in text
    assert date.today().strftime("%d.%m.%Y") in text
    assert "jkaluza" in text and "A38-FW-A_ROOT" in text
    assert "Company confidential" in text and "Beispiel AG" in text
    assert "WD2/DR PLT/IT OT" in text
    for head in ("Rev", "Datum", "Name", "Gruppe", "Autor", "Check", "Blatt 1"):
        assert any(l == head or l.startswith(head) for l in labels), head
    # Revision A trägt Datum und Name, die leeren Zeilen darüber nicht.
    assert labels.count(date.today().strftime("%d.%m.%Y")) == 2   # Rev A + Autor-Zeile


async def test_without_title_block_nothing_is_drawn(inventory, prefixes):
    m = await _build(inventory, prefixes)
    assert "Zeichnungsnummer" not in drawio.render(m)


async def test_title_block_sits_beside_the_drawing_and_is_one_object(inventory, prefixes):
    """Neben der Zeichnung, nicht darunter: Container wachsen beim Aufklappen
    nach unten und würden ein Schriftfeld auf festen Koordinaten überdecken.
    Und es ist EINE Gruppe, damit man es in draw.io am Stück verschieben kann."""
    from diagram import titleblock
    m = await _build(inventory, prefixes)

    def top_level(xml):
        root = ET.fromstring(xml)
        return root, [(o, _geo(o.find("mxCell"))) for o in root.findall(".//object")
                      if o.find("mxCell").get("parent") == "1"]

    _r, plain = top_level(drawio.render(m))
    info = titleblock.info_from(TB, title="T", subtitle="S", author="a", drawing_no="N")
    root, withtb = top_level(drawio.render(m, title_block=info))

    # Genau EIN neues Objekt auf oberster Ebene: die Gruppe.
    added = [(o, g) for o, g in withtb if g not in [g2 for _o2, g2 in plain]]
    assert len(added) == 1
    group, (gx, gy, gw, gh) = added[0]
    assert "group" in group.find("mxCell").get("style")
    assert (gw, gh) == (titleblock.WIDTH, titleblock.HEIGHT)

    # Alle Zellen des Schriftfelds hängen in dieser Gruppe.
    gid = group.get("id")
    inside = [o for o in root.findall(".//object") if o.find("mxCell").get("parent") == gid]
    assert len(inside) > 20
    assert any(o.get("label", "").startswith("Zeichnungsnummer") for o in inside)

    # Und es liegt rechts von allem, was wachsen kann.
    content_right = max(g[0] + g[2] for _o, g in plain)
    assert gx >= content_right


def test_logo_data_uri_is_written_the_way_mxgraph_reads_it():
    """';base64,' würde den Style zerschneiden — draw.io schreibt ','."""
    from diagram import titleblock
    assert titleblock.normalize_logo("data:image/png;base64,AAAB") == "data:image/png,AAAB"
    assert titleblock.normalize_logo("data:image/png,AAAB") == "data:image/png,AAAB"
    assert titleblock.normalize_logo("https://example.net/logo.png") is None
    assert titleblock.normalize_logo("") is None


async def test_shutdown_interface_is_drawn_but_marked(inventory, prefixes):
    """Ein stillgelegtes Segment gehört in den Plan: sonst widerspricht das
    Dokument der Firewall-Konfiguration und niemand erfährt, warum es fehlt.
    Für die Pfad-Engine bleibt es unverändert kein connected Netz."""
    m = await _build(inventory, prefixes)
    nets = {n["cidr"]: n for n in m["vdoms"][0]["networks"]}
    assert nets["10.1.3.0/24"]["enabled"] is False
    assert nets["10.1.1.0/24"]["enabled"] is True
    assert m["stats"]["networks_off"] == 1
    # Abgeschaltete stehen am Ende der Spalte.
    order = [n["enabled"] for n in m["vdoms"][0]["networks"]]
    assert order == sorted(order, reverse=True)
    # Und die Pfad-Engine sieht es weiterhin nicht als connected.
    assert all(str(n) != "10.1.3.0/24" for n, _ in inventory.connected_networks("fw-a", "root"))

    root = ET.fromstring(drawio.render(m))
    off = [o for o in root.findall(".//object") if "10.1.3.0/24" in o.get("label", "")]
    assert len(off) == 1
    assert "abgeschaltet" in off[0].get("label")
    assert "shutdown" in off[0].get("tooltip", "")
    assert "fillColor=#ededed" in off[0].find("mxCell").get("style")


async def test_ha_cluster_is_highlighted_with_badge_and_frame(inventory, prefixes):
    m = await _build(inventory, prefixes, scope="firewall", device="fw-b", vdom=None)
    ha = m["devices"][0]["ha"]
    assert ha["mode"] == "A-P" and ha["group"] == "clu-b" and ha["group_id"] == 3
    assert [x["name"] for x in ha["members"]] == ["fw-b-1", "fw-b-2"]
    assert [x["role"] for x in ha["members"]] == ["Master", "Slave"]
    assert m["stats"]["ha_clusters"] == 1

    root = ET.fromstring(drawio.render(m))
    badge = [o for o in root.findall(".//object") if o.get("label", "").startswith("HA ")]
    assert len(badge) == 1 and badge[0].get("label") == "HA A-P · 2 Knoten"
    tip = badge[0].get("tooltip")
    assert "clu-b" in tip and "fw-b-1 · Master · FGVMB1 · up" in tip
    fw = [o for o in root.findall(".//object")
          if o.get("label") == "fw-b" and "swimlane" in o.find("mxCell").get("style")]
    assert "strokeWidth=3" in fw[0].find("mxCell").get("style")


async def test_standalone_firewall_gets_no_ha_marks(inventory, prefixes):
    m = await _build(inventory, prefixes, scope="firewall", device="fw-a", vdom=None)
    assert m["devices"][0]["ha"] is None and m["stats"]["ha_clusters"] == 0
    root = ET.fromstring(drawio.render(m))
    assert not [o for o in root.findall(".//object") if o.get("label", "").startswith("HA ")]


def test_ha_parsing_is_defensive_about_fmg_field_variants():
    """Feldnamen und Kodierung schwanken zwischen FMG-Versionen — ein falsch
    gelesenes HA-Feld darf nur das Abzeichen kosten, nie ein Gerät."""
    from inventory.store import parse_ha
    assert parse_ha({"ha_mode": 0}) is None
    assert parse_ha({"ha_mode": "standalone"}) is None
    assert parse_ha({}) is None
    assert parse_ha(None) is None
    assert parse_ha({"ha_mode": 2})["mode"] == "A-A"
    assert parse_ha({"ha_mode": "active-passive"})["mode"] == "A-P"
    assert parse_ha({"ha_mode": "irgendwas"})["mode"] == "IRGENDWAS"
    # Nur Mitglieder, kein Modus → trotzdem ein Cluster.
    only = parse_ha({"ha_slave": [{"name": "a"}, {"name": "b"}]})
    assert only["mode"] == "HA" and len(only["members"]) == 2
    assert only["members"][0]["role"] is None and only["members"][0]["up"] is None
    # Unbrauchbare Einträge fliegen raus, statt alles zu kippen.
    messy = parse_ha({"ha_mode": 1, "ha_slave": ["kaputt", {"sn": "ohne-name"}, {"name": "ok"}]})
    assert [x["name"] for x in messy["members"]] == ["ok"]


def _fw_rows(name: str, ips: list[str], vdom: str = "root") -> list[dict]:
    from conftest import _row
    return [
        _row("device", name, {"name": name, "vdom": [{"name": vdom}]}),
        _row("interface", name, [
            {"name": f"port{i}", "ip": [ip, "255.255.255.0"], "vdom": [vdom]}
            for i, ip in enumerate(ips, start=1)]),
    ]


# Feld-Fall: die EUGE*-Firewalls routen ihre Segmente in „Gas Nord", tragen
# aber eine Management-Adresse aus dem Hamburger Bereich. Dessen Supernetz ist
# enger geschnitten — nach der alten Regel („engstes Supernetz gewinnt") zog
# diese EINE Adresse die Firewall nach Hamburg.
FIELD_SITES = [{"name": "Gas Nord", "cidr": "10.180.16.0/20"},
               {"name": "Hamburg", "cidr": "10.180.32.0/21"}]


def test_site_follows_the_majority_of_locally_routed_segments():
    from inventory.store import Inventory
    from diagram.model import _supernets, site_of_device, site_scores
    rows = _fw_rows("EUGESH1", ["10.180.17.1", "10.180.18.1", "10.180.19.1",
                                "10.180.20.1", "10.180.32.9"])
    inv = Inventory.build(rows)
    sup = _supernets(FIELD_SITES)
    assert site_scores(inv, "EUGESH1", ["root"], sup) == {"Gas Nord": 4, "Hamburg": 1}
    assert site_of_device(inv, inv.build_prefix_table(), "EUGESH1", sup) == "Gas Nord"


def test_site_tie_goes_to_the_narrower_supernet():
    from inventory.store import Inventory
    from diagram.model import _supernets, site_of_device
    inv = Inventory.build(_fw_rows("xha002", ["10.180.17.1", "10.180.32.9"]))
    assert site_of_device(inv, inv.build_prefix_table(), "xha002",
                          _supernets(FIELD_SITES)) == "Hamburg"


def test_site_counts_across_all_vdoms_of_a_device():
    """Das Router-VDOM hält nur das Transfernetz, das Schutz-VDOM die
    Standortsegmente — zusammen zählen, nicht das erste VDOM entscheiden lassen."""
    from conftest import _row
    from inventory.store import Inventory
    from diagram.model import _supernets, site_of_device
    rows = [
        _row("device", "EUGEBA1", {"name": "EUGEBA1",
                                   "vdom": [{"name": "Router"}, {"name": "prot"}]}),
        _row("interface", "EUGEBA1", [
            {"name": "wan", "ip": ["10.180.32.9", "255.255.255.252"], "vdom": ["Router"]},
            {"name": "v1", "ip": ["10.180.17.1", "255.255.255.0"], "vdom": ["prot"]},
            {"name": "v2", "ip": ["10.180.18.1", "255.255.255.0"], "vdom": ["prot"]},
        ]),
    ]
    inv = Inventory.build(rows)
    sup = _supernets(FIELD_SITES)
    assert site_of_device(inv, inv.build_prefix_table(), "EUGEBA1", sup) == "Gas Nord"


def test_site_override_from_settings_still_wins():
    from inventory.store import Inventory
    from diagram.model import _supernets, site_of_device
    inv = Inventory.build(_fw_rows("xfk200", ["10.180.17.1", "10.180.18.1"]))
    prefixes = inv.build_prefix_table(
        [{"cidr": "10.180.17.0/24", "device": "xfk200", "vdom": "root", "name": "Sonderfall"}])
    assert site_of_device(inv, prefixes, "xfk200", _supernets(FIELD_SITES)) == "Sonderfall"


def test_site_detail_names_the_evidence_and_the_runner_up():
    from routers.diagram import _site_detail
    assert _site_detail("Gas Nord", {"Gas Nord": 7, "Hamburg": 1}) \
        == "Gas Nord · 7 von 8 Netzen · auch Hamburg (1)"
    assert _site_detail("Gas Nord", {"Gas Nord": 3}) == "Gas Nord · 3 von 3 Netzen"
    assert _site_detail(None, {}) is None


def test_nested_supernets_do_not_let_the_bigger_range_win():
    """Standort-/20 innerhalb eines Haus-/16: jedes Netz stimmt nur einmal ab,
    und zwar für den spezifischsten Bereich — sonst gewinnt der große immer."""
    from inventory.store import Inventory
    from diagram.model import _supernets, site_of_device, site_scores
    sites = [{"name": "Haus", "cidr": "10.180.0.0/16"},
             {"name": "Gas Nord", "cidr": "10.180.16.0/20"}]
    inv = Inventory.build(_fw_rows("EUGERN1", ["10.180.17.1", "10.180.18.1", "10.180.19.1"]))
    sup = _supernets(sites)
    assert site_scores(inv, "EUGERN1", ["root"], sup) == {"Gas Nord": 3}
    assert site_of_device(inv, inv.build_prefix_table(), "EUGERN1", sup) == "Gas Nord"


LINKS = {("fw-a", "root"): {"lan1": {"link": True}, "lan2": {"link": False},
                            "wan": {"link": None}}}


async def test_link_down_is_its_own_state_next_to_shutdown(inventory, prefixes):
    """Die Konfiguration kennt nur 'set status up|down'. Ob ein Kabel steckt,
    ist Laufzeitzustand — und ein Plan, der ein totes Interface wie ein
    lebendiges zeichnet, behauptet etwas Falsches."""
    m = await _build(inventory, prefixes, link_status=LINKS)
    nets = {n["cidr"]: n for n in m["vdoms"][0]["networks"]}
    assert nets["10.1.1.0/24"]["link"] is True      # aktiv
    assert nets["10.1.2.0/24"]["link"] is False     # Kabel ab
    assert nets["203.0.113.0/30"]["link"] is None   # nicht ermittelbar
    assert nets["10.1.3.0/24"]["enabled"] is False  # shutdown, davon unabhängig
    assert m["stats"]["networks_link_down"] == 1 and m["stats"]["networks_off"] == 1
    # Reihenfolge: aktiv, dann ohne Link, dann abgeschaltet.
    order = [(n["enabled"], n["link"] is not False) for n in m["vdoms"][0]["networks"]]
    assert order == sorted(order, key=lambda t: (not t[0], not t[1]))

    root = ET.fromstring(drawio.render(m))
    def box(cidr):
        return next(o for o in root.findall(".//object") if cidr in o.get("label", ""))
    down, off, up = box("10.1.2.0/24"), box("10.1.3.0/24"), box("10.1.1.0/24")
    assert "Link down" in down.get("label") and "fillColor=#fff2cc" in down.find("mxCell").get("style")
    assert "abgeschaltet" in off.get("label") and "fillColor=#ededed" in off.find("mxCell").get("style")
    assert "Link down" not in up.get("label") and "fillColor=#d5e8d4" in up.find("mxCell").get("style")
    assert "Link down" in down.get("tooltip")


async def test_unknown_link_state_is_not_treated_as_up_or_down(inventory, prefixes):
    """Ohne Antwort vom Gerät wird nach Konfiguration gezeichnet — aber nichts
    als 'ohne Link' behauptet, was niemand geprüft hat."""
    m = await _build(inventory, prefixes)          # gar kein link_status
    assert all(n["link"] is None for n in m["vdoms"][0]["networks"])
    assert m["stats"]["networks_link_down"] == 0
    assert "Link down" not in drawio.render(m)


def test_link_status_parsing_handles_both_fortios_shapes():
    from diagram import linkstatus
    as_list = [{"name": "wan2", "link": False, "status": "up"},
               {"name": "lan1", "link": True, "status": "up"},
               {"kaputt": 1}]
    as_dict = {"wan2": {"link": 0, "status": "up"}, "lan1": {"link": 1, "status": "up"}}
    for results in (as_list, as_dict):
        got = linkstatus.parse(results)
        assert got["wan2"]["link"] is False and got["lan1"]["link"] is True
    # Unbekannte Kodierung bleibt unbekannt, statt 'up' zu raten.
    assert linkstatus.parse([{"name": "x", "link": "vielleicht"}])["x"]["link"] is None
    assert linkstatus.parse([{"name": "y"}])["y"]["link"] is None
    assert linkstatus.parse(None) == {}


# ── Logische Netzdokumentation (Hausvorgabe) ─────────────────────────────────

def test_ip_is_shortened_to_the_significant_part():
    """„bei Endgeräten abgekürzt auf die signifikanten Anteile" — im /24 bleibt
    das letzte Oktett, im /16 die letzten zwei."""
    from diagram.logical import short_ip
    assert short_ip("10.124.58.73", "10.124.58.0/24") == ".73"
    assert short_ip("10.124.58.73", "10.124.0.0/16") == ".58.73"
    assert short_ip("10.124.58.73", "10.0.0.0/8") == ".124.58.73"
    assert short_ip("10.124.58.73", "10.124.58.64/26") == ".73"
    assert short_ip("10.124.58.73", "kaputt") == "10.124.58.73"


async def test_logical_view_draws_buses_with_vlan_and_colours(inventory, prefixes):
    from diagram import logical
    m = await _build(inventory, prefixes, scope="firewall", device="fw-a", vdom=None)
    root = ET.fromstring(logical.render(m))
    labels = [o.get("label", "") for o in root.findall(".//object")]
    assert any("10.1.1.0/24" in l for l in labels)
    assert any(l.startswith("VLAN ") or "10.1.2.0/24" in l for l in labels)
    # Je Netz eine eigene Farbe: mindestens zwei verschiedene Leistenfarben.
    bars = [c.get("style") for c in root.findall(".//mxCell")
            if "rounded=1" in (c.get("style") or "") and "fontSize=0" in (c.get("style") or "")]
    fills = {s.split("fillColor=")[1].split(";")[0] for s in bars}
    assert len(bars) >= 3 and len(fills) >= 3
    # DIN A3 quer.
    model_el = root.find(".//mxGraphModel")
    assert (model_el.get("pageWidth"), model_el.get("pageHeight")) == ("1169", "826")


async def test_logical_view_leaves_out_switches_and_says_so(inventory, prefixes):
    """„Switche und einzelne Netzwerkports werden hier nicht dargestellt" — aber
    stillschweigend verschwinden darf auch nichts."""
    from diagram import logical, titleblock
    hosts = [{"name": "srv-1", "ip": "10.1.1.10", "description": "", "kind": "Server"},
             {"name": "sw-core", "ip": "10.1.1.2", "description": "", "kind": "NetworkDevice"}]
    m = await _build(inventory, prefixes, itop_hosts=hosts, itop_addresses={})
    tb = titleblock.info_from(TB, title="T", subtitle="S", author="a", drawing_no="N")
    root = ET.fromstring(logical.render(m, title_block=tb))
    labels = " ".join(o.get("label", "") for o in root.findall(".//object"))
    assert "srv-1" in labels and "sw-core" not in labels
    assert "Switche nicht dargestellt" in labels


async def test_too_many_hosts_become_one_symbol_per_class_plus_a_table(inventory, prefixes):
    """„…können die Endgeräte tabellarisch erfasst werden und nur jeweils ein
    Symbol wird in der Grafik für die jeweilige Geräteklasse verwendet, mit
    einer Beschriftung, die einen Verweis auf die entsprechende Tabelle enthält."""
    from diagram import logical
    hosts = [{"name": f"plc-{i}", "ip": f"10.1.1.{i}", "description": "", "kind": "Server"}
             for i in range(10, 40)]
    hosts.append({"name": "hmi", "ip": "10.1.1.90", "description": "Panel", "kind": None})
    m = await _build(inventory, prefixes, itop_hosts=hosts, itop_addresses={})
    root = ET.fromstring(logical.render(m, max_hosts=18))
    pages = [d.get("name") for d in root.findall("diagram")]
    assert "Tabelle 10.1.1.0/24" in pages
    labels = [o.get("label", "") for o in root.findall(".//object")]
    assert any(l.startswith("30 × Server") and "Tabelle 10.1.1.0/24" in l for l in labels)
    assert any(re.match(r"^\d+ × Endgerät", l) for l in labels)
    # Die Tabelle nennt jedes Gerät mit voller IP.
    assert any("10.1.1.39" == l for l in labels) and any(l == "plc-39" for l in labels)


async def test_few_hosts_stay_individual_symbols(inventory, prefixes):
    from diagram import logical
    hosts = [{"name": f"plc-{i}", "ip": f"10.1.1.{i}", "description": "", "kind": "Server"}
             for i in range(10, 14)]
    m = await _build(inventory, prefixes, itop_hosts=hosts, itop_addresses={})
    root = ET.fromstring(logical.render(m, max_hosts=18))
    assert [d.get("name") for d in root.findall("diagram")] == ["Netzplan fw-a/root"]
    labels = [o.get("label", "") for o in root.findall(".//object")]
    # Gemeinsames Namenspräfix wandert an die Leiste, die Geräte tragen den Rest.
    assert any(l.startswith("13<br>.13") for l in labels)
    assert any("Namen ohne plc-" in l for l in labels)
    assert not any("×" in l for l in labels)


def test_common_prefix_only_strips_what_is_really_common():
    """Gerätenamen im Feld sind gebaut wie WD-OT-L3-SVO3036 — in einem Netz
    ist alles bis auf den letzten Teil gleich. Abgeschnitten wird aber nur am
    Trennzeichen, und nur wenn es sich lohnt."""
    from diagram.logical import common_prefix
    assert common_prefix(["WD-OT-L3-SVO3036", "WD-OT-L3-SVO3101", "WD-OT-L3-SVO3099"]) \
        == "WD-OT-L3-"
    # Mitten im Wort wird nicht geschnitten.
    assert common_prefix(["srv-alpha", "srv-alfred", "srv-alpine"]) == "srv-"
    # Zu wenige Namen, kein gemeinsamer Teil, oder ein Name wäre danach leer.
    assert common_prefix(["WD-OT-L3-A", "WD-OT-L3-B"]) == ""
    assert common_prefix(["alpha", "beta", "gamma"]) == ""
    assert common_prefix(["ab-", "ab-x", "ab-y"]) == ""
    assert common_prefix([]) == ""


async def test_hosts_alternate_height_and_drop_straight_down(inventory, prefixes):
    """Nebeneinander stoßen lange Namen aneinander, und ohne festen
    Einstiegspunkt zielt jede Linie auf die Leistenmitte — dann wird aus den
    Abgängen ein Sternchen."""
    from diagram import logical
    hosts = [{"name": f"WD-OT-L3-SVO30{i}", "ip": f"10.1.1.{i}", "description": "",
              "kind": "Server"} for i in range(10, 18)]
    m = await _build(inventory, prefixes, itop_hosts=hosts, itop_addresses={})
    root = ET.fromstring(logical.render(m))
    icons = [(o.get("label"), _geo(o.find("mxCell")))
             for o in root.findall(".//object")
             if "mxgraph.networks.server" in (o.find("mxCell").get("style") or "")]
    ys = sorted({g[1] for _l, g in icons})
    assert len(ys) == 2 and ys[1] - ys[0] == logical.STAGGER
    drops = [c.get("style") for c in root.findall(".//mxCell") if c.get("edge") == "1"]
    fracs = {s.split("entryX=")[1].split(";")[0] for s in drops if "entryX=" in s}
    assert len(fracs) >= 5 and "0.5000" not in fracs or len(fracs) >= 5


# ── Physische Netzdokumentation (Hausvorgabe, Ebene 1 und 2) ────────────────

class FakeLnms:
    """LibreNMS-Stub: ein Core, zwei Verteiler, ein Zugangsswitch, ein Router."""

    DEVICES = {
        "1": {"device_id": 1, "sysName": "core-01", "hostname": "core-01", "ip": "10.0.0.1",
              "hardware": "HP 5406", "os": "procurve"},
        "2": {"device_id": 2, "sysName": "dist-a", "hostname": "dist-a", "ip": "10.0.0.2",
              "hardware": "MOXA IKS", "os": "moxa"},
        "3": {"device_id": 3, "sysName": "dist-b", "hostname": "dist-b", "ip": "10.0.0.3",
              "hardware": "MOXA IKS", "os": "moxa"},
        "4": {"device_id": 4, "sysName": "acc-1", "hostname": "acc-1", "ip": "10.0.0.4",
              "hardware": "MOXA", "os": "moxa"},
        "9": {"device_id": 9, "sysName": "fw-edge", "hostname": "fw-edge", "ip": "10.0.0.9",
              "hardware": "FortiGate 60F", "os": "fortios"},
    }
    LINKS = [
        {"local_device_id": 2, "remote_device_id": 1, "local_port": "p25", "remote_port": "Gi1/0/1",
         "local_port_id": 201},
        {"local_device_id": 3, "remote_device_id": 1, "local_port": "p25", "remote_port": "Gi1/0/2",
         "local_port_id": 301},
        {"local_device_id": 4, "remote_device_id": 2, "local_port": "p26", "remote_port": "p1",
         "local_port_id": 401},
        {"local_device_id": 1, "remote_device_id": 9, "local_port": "Gi1/0/24", "remote_port": "port3",
         "local_port_id": 124},
        # Nachbar ohne Device-Id = Endgerät; gehört auf Ebene 2, nicht hierher.
        {"local_device_id": 4, "remote_device_id": None, "local_port": "p3",
         "remote_hostname": "irgendein-pc", "local_port_id": 403},
    ]
    PORTS = {"4": [
        {"port_id": 401, "ifName": "p1", "ifAlias": "Uplink", "ifOperStatus": "up"},
        {"port_id": 402, "ifName": "p2", "ifAlias": "Anlage 3", "ifOperStatus": "up"},
        {"port_id": 403, "ifName": "p3", "ifAlias": "", "ifOperStatus": "up"},
        {"port_id": 404, "ifName": "p4", "ifAlias": "", "ifOperStatus": "down"},
    ]}
    FDB = {"4": [
        {"port_id": 401, "mac_address": "000c29aaaa01"},
        {"port_id": 401, "mac_address": "000c29aaaa02"},
        {"port_id": 402, "mac_address": "000c29bbbb01"},
        {"port_id": 403, "mac_address": "000c29cccc01"},
    ]}

    async def links(self, cfg):
        return self.LINKS

    async def device_index(self, cfg):
        return {d["hostname"]: d for d in self.DEVICES.values()}

    async def device(self, cfg, device_id):
        return self.DEVICES[str(device_id)]

    async def device_ports(self, cfg, device_id):
        return self.PORTS[str(device_id)]

    async def device_fdb(self, cfg, device_id):
        return self.FDB[str(device_id)]

    async def neighbours(self, cfg):
        # Port 401 ist der Uplink zu dist-a (überwacht), 403 hängt an einem PC.
        return {401: {"label": "dist-a / p26", "monitored": True, "device_id": 2},
                403: {"label": "irgendein-pc", "monitored": False, "device_id": None}}


async def test_infra_view_uses_lldp_between_monitored_devices(inventory, prefixes):
    from diagram import physical
    warn: list[str] = []
    m = await physical.infra_model(FakeLnms(), {}, warn)
    assert set(m["nodes"]) == {"1", "2", "3", "4", "9"}
    assert len(m["edges"]) == 4 and not warn        # der PC-Nachbar zählt nicht
    ports = {tuple(sorted(p)) for e in m["edges"] for p in e["ports"]}
    assert ("Gi1/0/1", "p25") in ports

    root = ET.fromstring(physical.render_infra(m))
    labels = [o.get("label", "") for o in root.findall(".//object")]
    assert any("core-01" in l for l in labels) and any("fw-edge" in l for l in labels)
    edges = [c.get("value") for c in root.findall(".//mxCell") if c.get("edge") == "1"]
    assert any("Gi1/0/1 ↔ p25" in (v or "") for v in edges)   # Ports in Knotenreihenfolge
    # Der Core hat die meisten Nachbarn und steht deshalb ganz oben.
    tops = {o.get("label"): _geo(o.find("mxCell"))[1] for o in root.findall(".//object")}
    core_y = next(y for l, y in tops.items() if "core-01" in l)
    assert all(y >= core_y for l, y in tops.items() if l)
    # Firewalls bekommen ein anderes Symbol als Switche.
    styles = {o.get("label"): o.find("mxCell").get("style") for o in root.findall(".//object")}
    fw = next(s for l, s in styles.items() if "fw-edge" in (l or ""))
    assert "networks.firewall" in fw and "#b85450" in fw
    core = next(s for l, s in styles.items() if "core-01" in (l or ""))
    assert "switches" in core


def test_port_prefix_keeps_the_module_when_there_are_several():
    """Ein Chassis mit mehreren Modulen darf die Modulnummer nicht verlieren —
    gekürzt wird nur, was wirklich allen gemeinsam ist."""
    from diagram.labels import common_prefix, strip_prefix
    names = ["Ten-GigabitEthernet1/0/1", "Ten-GigabitEthernet1/0/2",
             "Ten-GigabitEthernet2/0/1"]
    prefix = common_prefix(names)
    assert prefix == "Ten-GigabitEthernet"
    assert [strip_prefix(n, prefix) for n in names] == ["1/0/1", "1/0/2", "2/0/1"]


def test_device_shape_follows_vendor_and_role():
    """Ein modellgenaues Faceplate gibt draw.io nicht her — aber die Klasse
    (Firewall, Layer-3-Switch, Access-Switch, AP) ist ablesbar."""
    from diagram.physical import device_shape
    assert device_shape({"os": "fortios"})[0].endswith("networks.firewall")
    assert device_shape({"hardware": "Juniper MX"})[0].endswith("networks.router")
    assert device_shape({"hardware": "Cisco Catalyst 9300"})[0].endswith("layer_3_switch")
    assert device_shape({"sysDescr": "Aruba AP-515 access point"})[0].endswith("wireless_hub")
    assert device_shape({"hardware": "MOXA IKS-6728"})[0].endswith("workgroup_switch")
    assert device_shape({})[0].endswith("workgroup_switch")


async def test_switch_view_maps_devices_to_ports_via_mac(inventory, prefixes):
    """„Die Zuordnung der Endgeräte erfolgt über die MAC Adressen, die an dem
    Switch sichtbar sind" — und die IP kommt aus der IP↔MAC-Historie."""
    from diagram import physical
    warn: list[str] = []

    async def arp(macs):
        assert "000c29bbbb01" in macs
        return {"000c29bbbb01": {"ip": "10.124.58.73", "name": None,
                                 "last_seen": "2026-09-01T10:00:00+00:00"}}

    m = await physical.switch_model(FakeLnms(), {}, 4, arp, warn)
    by_name = {p["name"]: p for p in m["ports"]}
    assert by_name["p1"]["uplink"] is True and by_name["p1"]["hosts"] == []
    assert by_name["p2"]["hosts"][0]["ip"] == "10.124.58.73"
    assert by_name["p2"]["hosts"][0]["mac_readable"] == "00:0c:29:bb:bb:01"
    assert by_name["p4"]["hosts"] == [] and by_name["p4"]["up"] is False

    root = ET.fromstring(physical.render_switch(m))
    labels = [o.get("label", "") for o in root.findall(".//object")]
    assert any("acc-1" in l and "4 Ports" in l for l in labels)
    assert any("10.124.58.73" in l for l in labels)
    # Uplink-Port anders eingefärbt als belegte und freie Ports.
    styles = {o.get("label"): o.find("mxCell").get("style") for o in root.findall(".//object")}
    assert "#e1d5e7" in styles["p1"] and "#d5e8d4" in styles["p2"] and "#ffffff" in styles["p4"]


class LongPortLnms(FakeLnms):
    """Wie im Feld: lange Portnamen und ein Haufen logischer Interfaces."""

    PORTS = {"4": (
        [{"port_id": 400 + i, "ifName": f"Ten-GigabitEthernet1/0/{i}", "ifAlias": "",
          "ifOperStatus": "up"} for i in range(1, 25)]
        + [{"port_id": 500, "ifName": "Bridge-Aggregation1", "ifOperStatus": "up"},
           {"port_id": 501, "ifName": "Vlan-interface100", "ifOperStatus": "up"},
           {"port_id": 502, "ifName": "NULL0", "ifOperStatus": "up"},
           {"port_id": 503, "ifName": "InLoopBack0", "ifOperStatus": "up"}])}
    FDB = {"4": [{"port_id": 400 + i, "mac_address": f"000c29aa00{i:02x}"}
                 for i in range(2, 12)]}

    async def neighbours(self, cfg):
        return {401: {"label": "core / Gi1/0/1", "monitored": True, "device_id": 1}}


async def test_long_port_names_are_shortened_and_logical_ports_left_out(inventory, prefixes):
    """„Ten-GigabitEthernet1/0/24" ist auf einem Port-Kästchen nicht zu lesen,
    und Bridge-Aggregation oder Vlan-interface haben gar keine Buchse."""
    from diagram import physical

    async def arp(macs):
        return {}

    warn: list[str] = []
    m = await physical.switch_model(LongPortLnms(), {}, 4, arp, warn)
    assert len(m["ports"]) == 24 and m["logical"] == 4
    root = ET.fromstring(physical.render_switch(m))
    labels = [o.get("label", "") for o in root.findall(".//object")]
    # Alle Ports auf einem Modul: übrig bleibt die Portnummer — wie auf der
    # echten Frontblende. Das Präfix steht einmal am Panel.
    assert "24" in labels and "Ten-GigabitEthernet1/0/24" not in labels
    head = next(l for l in labels if "acc-1" in l)
    assert "Ten-GigabitEthernet1/0/" in head and "4 logische Interfaces" in head
    # Die Geräte stehen auf gleichmäßigen Plätzen, nicht übereinander.
    icons = [_geo(o.find("mxCell")) for o in root.findall(".//object")
             if "networks.pc" in (o.find("mxCell").get("style") or "")]
    xs = sorted(g[0] for g in icons)
    assert len(xs) == 10
    assert all(b - a >= 120 for a, b in zip(xs, xs[1:]) if abs(b - a) > 1)


async def test_switch_view_resolves_names_via_dns(inventory, prefixes):
    """Ohne Namen trägt ein Gerät nur seine MAC — die sagt beim Lesen niemandem
    etwas. A38 kann Reverse-DNS, also wird es auch hier benutzt."""
    from diagram import physical

    async def arp(macs):
        return {"000c29bbbb01": {"ip": "10.124.58.73", "name": None}}

    async def dns(ip):
        return "hmi-panel-3.op-tech.com" if ip == "10.124.58.73" else None

    m = await physical.switch_model(FakeLnms(), {}, 4, arp, [], dns=dns)
    host = next(h for p in m["ports"] for h in p["hosts"] if h.get("ip"))
    assert host["name"] == "hmi-panel-3.op-tech.com"
    labels = [o.get("label", "") for o in ET.fromstring(
        physical.render_switch(m)).findall(".//object")]
    assert any("hmi-panel-3" in l and "10.124.58.73" in l for l in labels)


async def test_infra_view_without_lldp_says_so(inventory, prefixes):
    from diagram import physical

    class Empty(FakeLnms):
        async def links(self, cfg):
            return []

    warn: list[str] = []
    m = await physical.infra_model(Empty(), {}, warn)
    assert m["nodes"] == {} and any("LLDP" in w for w in warn)
    ET.fromstring(physical.render_infra(m))     # darf trotzdem eine Datei liefern


# ── Shape-Bibliothek und Standort-/Gruppenfilter ─────────────────────────────

RULES = [
    {"match": "IKS-6728A", "label": "MOXA IKS-6728A",
     "image": "data:image/png;base64,AAAB"},
    {"match": "5130", "label": "HPE 5130 EI", "image": "data:image/svg+xml;base64,BBBB"},
    {"match": "ohne-bild", "label": "kaputt"},          # ohne image -> greift nicht
]


def test_shape_rules_match_on_hardware_and_beat_the_class_symbol():
    """Erste passende Regel gewinnt; ohne Treffer bleibt es beim Klassensymbol,
    damit ein unbekanntes Gerät nicht aus der Zeichnung fällt."""
    from diagram.physical import device_style, match_rule
    moxa = {"hardware": "MOXA IKS-6728A-4GTXSFP-T", "os": "moxa"}
    assert match_rule(moxa, RULES)["label"] == "MOXA IKS-6728A"
    style = device_style(moxa, RULES)
    # ';base64,' würde den Style mitten im Bild zerschneiden.
    assert "shape=image" in style and "data:image/png,AAAB" in style
    assert ";base64," not in style
    assert match_rule({"hardware": "HPE 5130-48G-PoE+ EI"}, RULES)["label"] == "HPE 5130 EI"
    assert match_rule({"hardware": "ohne-bild 1"}, RULES) is None
    assert match_rule({"hardware": "Unbekannt 9000"}, RULES) is None
    assert "mxgraph" in device_style({"hardware": "Unbekannt 9000"}, RULES)
    assert "mxgraph" in device_style({"hardware": "MOXA IKS-6728A"}, None)


async def test_infra_view_can_be_limited_to_a_set_of_devices(inventory, prefixes):
    """Standort oder Gerätegruppe schränken die Infrastruktursicht ein — bei
    raumscharf gepflegten Standorten ist das der Unterschied zwischen einem
    Schrank und dem ganzen Werk."""
    from diagram import physical
    warn: list[str] = []
    m = await physical.infra_model(FakeLnms(), {}, warn, allow={"1", "2", "4"})
    assert set(m["nodes"]) == {"1", "2", "4"}
    assert all(e["a"] in m["nodes"] and e["b"] in m["nodes"] for e in m["edges"])
    assert not warn

    leer: list[str] = []
    empty = await physical.infra_model(FakeLnms(), {}, leer, allow={"999"})
    assert empty["nodes"] == {} and any("Standort" in w for w in leer)


async def test_switch_panel_uses_the_stored_model_picture(inventory, prefixes):
    from diagram import physical

    async def arp(macs):
        return {}

    m = await physical.switch_model(FakeLnms(), {}, 4, arp, [])
    m["device"] = {**m["device"], "hardware": "MOXA IKS-6728A-4GTXSFP-T"}
    root = ET.fromstring(physical.render_switch(m, rules=RULES))
    styles = [o.find("mxCell").get("style") for o in root.findall(".//object")]
    assert any("data:image/png,AAAB" in s for s in styles)
    # Ohne Bibliothek bleibt das Klassensymbol.
    plain = ET.fromstring(physical.render_switch(m))
    assert not any("shape=image" in (o.find("mxCell").get("style") or "")
                   for o in plain.findall(".//object"))


async def test_several_switch_panels_are_stacked_without_overlap(inventory, prefixes):
    """Standort oder Gruppe statt Einzelgerät: dann gehört je Switch ein Panel
    in die Zeichnung, untereinander und ohne Überschneidung."""
    from diagram import physical

    async def arp(macs):
        return {}

    m = await physical.switch_model(FakeLnms(), {}, 4, arp, [])
    second = {**m, "device": {**m["device"], "sysName": "acc-2"}}
    xml = physical.render_switches([m, second], name="Netzwerk physisch · Haus 1 OG")
    root = ET.fromstring(xml)
    assert root.find("diagram").get("name") == "Netzwerk physisch · Haus 1 OG"
    panels = [(o.get("label"), _geo(o.find("mxCell"))) for o in root.findall(".//object")
              if "fillColor=#d9d9d9" in (o.find("mxCell").get("style") or "")]
    assert len(panels) == 2
    (_l1, g1), (_l2, g2) = sorted(panels, key=lambda p: p[1][1])
    assert g2[1] >= g1[1] + g1[3]
    assert any("acc-2" in (l or "") for l, _g in panels)


# ── Kalibriertes Modellbild: Buchsen statt Kästchen ──────────────────────────

CALIBRATED = [{
    "match": "acc-1", "label": "MOXA IKS-6728A",
    "image": "data:image/png;base64,AAAB", "width": 800, "height": 120,
    # 4 Buchsen, zwei Reihen, oben ungerade / unten gerade
    "blocks": [{"cols": 2, "rows": 2, "order": "zigzag", "start": 1,
                "x": 100, "y": 40, "dx": 60, "dy": 40, "w": 24, "h": 24}],
}]


def test_port_number_comes_from_the_name_not_the_list_order():
    """Die LibreNMS-Liste darf sich sortieren, wie sie will — die Buchse bleibt
    dieselbe. Maßgeblich ist die letzte Zahlengruppe im Portnamen."""
    from diagram.physical import port_number
    assert port_number("Ten-GigabitEthernet1/0/24") == 24
    assert port_number("Gi1/0/1") == 1
    assert port_number("p25") == 25
    assert port_number("port-channel") is None
    assert port_number("") is None


def test_port_grid_maps_numbers_to_places_in_both_orders():
    from diagram.physical import port_position
    rowwise = [{"cols": 2, "rows": 2, "order": "rowwise", "start": 1,
                "x": 10, "y": 100, "dx": 50, "dy": 40}]
    # 1 2 / 3 4
    assert port_position(1, rowwise)[:2] == (10, 100)
    assert port_position(2, rowwise)[:2] == (60, 100)
    assert port_position(3, rowwise)[:2] == (10, 140)
    zig = [{"cols": 2, "rows": 2, "order": "zigzag", "start": 1,
            "x": 10, "y": 100, "dx": 50, "dy": 40}]
    # 1 3 oben / 2 4 unten
    assert port_position(1, zig)[:2] == (10, 100)
    assert port_position(2, zig)[:2] == (10, 140)
    assert port_position(3, zig)[:2] == (60, 100)
    assert port_position(5, zig) is None and port_position(None, zig) is None
    # Zweiter Block für abgesetzte SFP-Buchsen.
    two = zig + [{"cols": 2, "rows": 1, "start": 25, "x": 400, "y": 100, "dx": 30}]
    assert port_position(26, two)[:2] == (430, 100)


async def test_calibrated_image_replaces_the_schematic_panel(inventory, prefixes):
    from diagram import physical

    async def arp(macs):
        return {}

    m = await physical.switch_model(FakeLnms(), {}, 4, arp, [])
    root = ET.fromstring(physical.render_switch(m, rules=CALIBRATED))
    cells = [o.find("mxCell") for o in root.findall(".//object")]
    panel = next(c for c in cells if "shape=image" in (c.get("style") or ""))
    assert "data:image/png,AAAB" in panel.get("style") and "container=1" in panel.get("style")
    assert _geo(panel)[2:] == (800, 120)
    # Kein schematisches Panel mehr.
    assert not any("fillColor=#d9d9d9" in (c.get("style") or "") for c in cells)

    # Buchsen liegen im Bild, gemessen an der Kalibrierung.
    pid = next(o.get("id") for o in root.findall(".//object")
               if o.find("mxCell") is panel)
    kids = [(o.get("tooltip", ""), _geo(o.find("mxCell")))
            for o in root.findall(".//object") if o.find("mxCell").get("parent") == pid]
    assert len(kids) == 4
    p1 = next(g for t, g in kids if t.startswith("Port p1"))
    assert (p1[0] + p1[2] / 2, p1[1] + p1[3] / 2) == (100, 40)     # Buchse 1 oben links
    p2 = next(g for t, g in kids if t.startswith("Port p2"))
    assert (p2[0] + p2[2] / 2, p2[1] + p2[3] / 2) == (100, 80)     # Buchse 2 darunter
    # Uplink und belegte Buchse sind unterschiedlich markiert.
    styles = {o.get("tooltip", "").split("\n")[0]: o.find("mxCell").get("style")
              for o in root.findall(".//object") if o.find("mxCell").get("parent") == pid}
    assert "#6a4c93" in styles["Port p1"] and "#2e8b57" in styles["Port p2"]


async def test_ports_outside_the_grid_are_kept_below_the_picture(inventory, prefixes):
    """Ein Port ohne Rasterplatz darf nicht verschwinden — sonst behauptet die
    Zeichnung, es gäbe ihn nicht."""
    from diagram import physical

    async def arp(macs):
        return {}

    narrow = [{**CALIBRATED[0],
               "blocks": [{"cols": 1, "rows": 1, "start": 1,
                           "x": 100, "y": 40, "dx": 0, "dy": 0, "w": 20, "h": 20}]}]
    m = await physical.switch_model(FakeLnms(), {}, 4, arp, [])
    root = ET.fromstring(physical.render_switch(m, rules=narrow))
    labels = [o.get("label", "") for o in root.findall(".//object")]
    assert "3 Ports ohne zugeordnete Buchse" in labels
    assert {"p2", "p3", "p4"} <= set(labels)


BY_NAME = [{
    "hardware": "MOXA IKS-6728A-4GTXSFP-T", "label": "MOXA IKS-6728A",
    "image": "data:image/png;base64,AAAB", "width": 721, "height": 81,
    "port_w": 14, "port_h": 16,
    "ports": {
        "p1": {"x": 40, "y": 24},
        "p2": {"x": 40, "y": 56},
        # Sonderbuchse: breiter als RJ45, weil 40G.
        "p3": {"x": 300, "y": 40, "w": 34, "h": 22},
    },
}]


def test_rules_match_the_exact_hardware_string_from_librenms():
    """Freitext taugt als Schlüssel nicht — ein Tippfehler fällt erst auf, wenn
    die Zeichnung fertig ist. Deshalb exakt auf das, was LibreNMS meldet."""
    from diagram.physical import match_rule
    dev = {"hardware": "MOXA IKS-6728A-4GTXSFP-T"}
    assert match_rule(dev, BY_NAME)["label"] == "MOXA IKS-6728A"
    # Groß-/Kleinschreibung egal, Teiltreffer aber nicht.
    assert match_rule({"hardware": "moxa iks-6728a-4gtxsfp-t"}, BY_NAME) is not None
    assert match_rule({"hardware": "MOXA IKS-6728A"}, BY_NAME) is None
    # Alt-Regeln mit Teilstring greifen weiterhin.
    legacy = [{"match": "IKS-6728A", "image": "data:image/png;base64,X"}]
    assert match_rule({"hardware": "MOXA IKS-6728A-4GTXSFP-T"}, legacy) is not None


def test_ports_are_placed_by_name_not_by_number():
    """`HundredGigE1/0/1` und `GigabitEthernet1/0/1` tragen dieselbe Nummer und
    sind verschiedene Buchsen."""
    from diagram.physical import port_places
    place = port_places(BY_NAME[0])
    assert place("p1") == {"x": 40, "y": 24, "w": 14, "h": 16}
    assert place("p3")["w"] == 34 and place("p3")["h"] == 22   # Sondergröße
    assert place("p9") is None
    mixed = {"image": "x", "ports": {"GigabitEthernet1/0/1": {"x": 1, "y": 2},
                                     "HundredGigE1/0/1": {"x": 500, "y": 40}}}
    p = port_places(mixed)
    assert p("GigabitEthernet1/0/1")["x"] == 1 and p("HundredGigE1/0/1")["x"] == 500
    assert port_places({"image": "x"}) is None
    assert port_places(None) is None


async def test_named_port_map_drives_the_image_panel(inventory, prefixes):
    from diagram import physical

    async def arp(macs):
        return {}

    m = await physical.switch_model(FakeLnms(), {}, 4, arp, [])
    m["device"] = {**m["device"], "hardware": "MOXA IKS-6728A-4GTXSFP-T"}
    root = ET.fromstring(physical.render_switch(m, rules=BY_NAME))
    panel = next(o for o in root.findall(".//object")
                 if "shape=image" in (o.find("mxCell").get("style") or ""))
    assert _geo(panel.find("mxCell"))[2:] == (721, 81)
    kids = {o.get("tooltip", "").split("\n")[0]: _geo(o.find("mxCell"))
            for o in root.findall(".//object")
            if o.find("mxCell").get("parent") == panel.get("id")}
    assert (kids["Port p1"][0] + kids["Port p1"][2] / 2,
            kids["Port p1"][1] + kids["Port p1"][3] / 2) == (40, 24)
    assert kids["Port p3"][2:] == (34, 22)
    # p4 ist nicht zugeordnet und steht deshalb unter dem Bild, nicht nirgends.
    labels = [o.get("label", "") for o in root.findall(".//object")]
    assert "1 Ports ohne zugeordnete Buchse" in labels and "p4" in labels


# ── Stacks und Gerätemengen ──────────────────────────────────────────────────

def test_stack_unit_is_read_from_the_name_and_normalised():
    """Ein Stack ist mehrfach dasselbe Gerät: eingemessen wird EIN Blech, und
    Einheit 2 sitzt an denselben Stellen wie Einheit 1."""
    from diagram.physical import port_unit, unit_key
    assert port_unit("Ten-GigabitEthernet2/0/17") == 2
    assert unit_key("Ten-GigabitEthernet2/0/17") == "Ten-GigabitEthernet1/0/17"
    assert unit_key("Ten-GigabitEthernet1/0/17") == "Ten-GigabitEthernet1/0/17"
    # Zwei Zahlengruppen sind Slot/Port auf einem Einzelgerät, keine Einheit.
    assert port_unit("GigabitEthernet0/1") == 1
    assert unit_key("GigabitEthernet0/1") == "GigabitEthernet0/1"
    assert port_unit("p25") == 1 and unit_key("p25") == "p25"


class StackLnms(FakeLnms):
    """Zwei-Einheiten-Stack wie im Feld, 8 Ports je Einheit."""

    PORTS = {"4": [{"port_id": 1000 + u * 100 + i,
                    "ifName": f"Ten-GigabitEthernet{u}/0/{i}", "ifAlias": "",
                    "ifOperStatus": "up"}
                   for u in (1, 2) for i in range(1, 9)]}
    FDB = {"4": [{"port_id": 1000 + u * 100 + i, "mac_address": f"000c29{u}a00{i:02x}"}
                 for u in (1, 2) for i in range(2, 5)]}

    async def neighbours(self, cfg):
        return {}


STACK_RULE = [{
    "hardware": "stacked", "image": "data:image/png;base64,AAAB",
    "width": 400, "height": 60, "port_w": 12, "port_h": 14,
    "ports": {f"Ten-GigabitEthernet1/0/{i}": {"x": 20 + i * 20, "y": 30}
              for i in range(1, 9)},
}]


async def test_every_stack_unit_gets_its_own_faceplate(inventory, prefixes):
    from diagram import physical

    async def arp(macs):
        return {}

    m = await physical.switch_model(StackLnms(), {}, 4, arp, [])
    m["device"] = {**m["device"], "hardware": "stacked"}
    root = ET.fromstring(physical.render_switch(m, rules=STACK_RULE))
    panels = [o for o in root.findall(".//object")
              if "shape=image" in (o.find("mxCell").get("style") or "")]
    assert len(panels) == 2, "je Einheit ein Blech"
    heads = [o.get("label", "") for o in root.findall(".//object")]
    assert any("Einheit 1" in h for h in heads) and any("Einheit 2" in h for h in heads)
    # Jede Einheit trägt ihre 8 Buchsen — keine landet in der Restzeile.
    for panel in panels:
        kids = [o for o in root.findall(".//object")
                if o.find("mxCell").get("parent") == panel.get("id")]
        assert len(kids) == 8
    assert not any("ohne zugeordnete Buchse" in h for h in heads)
    # Und die Bleche liegen untereinander, nicht übereinander.
    (y1, h1), (y2, _h2) = sorted((_geo(p.find("mxCell"))[1], _geo(p.find("mxCell"))[3])
                                 for p in panels)
    assert y2 >= y1 + h1


async def test_many_devices_go_to_a_table_instead_of_the_drawing(inventory, prefixes):
    """70 Geräte an einem Blech ergaben 14 Reihen und Leitungen quer über alles.
    Die Hausvorgabe sieht für lange Listen ohnehin eine Tabelle vor."""
    from diagram import physical

    async def arp(macs):
        return {}

    class Busy(FakeLnms):
        PORTS = {"4": [{"port_id": 400 + i, "ifName": f"p{i}", "ifOperStatus": "up"}
                       for i in range(1, 41)]}
        FDB = {"4": [{"port_id": 400 + i, "mac_address": f"000c29aa{i:04x}"}
                     for i in range(1, 41)]}

        async def neighbours(self, cfg):
            return {}

    m = await physical.switch_model(Busy(), {}, 4, arp, [])
    root = ET.fromstring(physical.render_switch(m))
    assert any(d.get("name", "").startswith("Geräte ") for d in root.findall("diagram"))
    head = next(o.get("label") for o in root.findall(".//object")
                if "fillColor=#d9d9d9" in (o.find("mxCell").get("style") or ""))
    assert "40 Geräte — siehe Tabellenseite" in head
    # In der Zeichnung selbst hängt dann kein Gerät mehr.
    assert not any("mxgraph.networks.pc" in (o.find("mxCell").get("style") or "")
                   for o in root.findall(".//object"))


async def test_few_devices_stay_in_at_most_two_rows(inventory, prefixes):
    from diagram import physical

    async def arp(macs):
        return {}

    class Some(FakeLnms):
        PORTS = {"4": [{"port_id": 400 + i, "ifName": f"p{i}", "ifOperStatus": "up"}
                       for i in range(1, 13)]}
        FDB = {"4": [{"port_id": 400 + i, "mac_address": f"000c29bb{i:04x}"}
                     for i in range(1, 13)]}

        async def neighbours(self, cfg):
            return {}

    m = await physical.switch_model(Some(), {}, 4, arp, [])
    root = ET.fromstring(physical.render_switch(m))
    icons = [_geo(o.find("mxCell")) for o in root.findall(".//object")
             if "mxgraph.networks" in (o.find("mxCell").get("style") or "")
             and (o.get("tooltip") or "").startswith("MAC")]
    assert len(icons) == 12
    assert len({g[1] for g in icons}) <= 4     # höchstens zwei Reihen je Seite


async def test_switch_view_resolves_names_in_parallel_not_one_by_one(inventory, prefixes):
    """300 Adressen nacheinander bei 1,5 s Zeitüberschreitung sind über sieben
    Minuten, in denen die Ansicht scheinbar hängt."""
    import asyncio
    from diagram import physical

    class Many(FakeLnms):
        PORTS = {"4": [{"port_id": 400 + i, "ifName": f"p{i}", "ifOperStatus": "up"}
                       for i in range(1, 33)]}
        FDB = {"4": [{"port_id": 400 + i, "mac_address": f"000c29cc{i:04x}"}
                     for i in range(1, 33)]}

        async def neighbours(self, cfg):
            return {}

    async def arp(macs):
        return {m: {"ip": f"10.1.1.{i}"} for i, m in enumerate(macs, 1)}

    live = 0
    peak = 0

    async def dns(ip):
        nonlocal live, peak
        live += 1
        peak = max(peak, live)
        await asyncio.sleep(0.01)
        live -= 1
        return f"host-{ip.split('.')[-1]}.op-tech.com"

    m = await physical.switch_model(Many(), {}, 4, arp, [], dns=dns)
    named = [h for p in m["ports"] for h in p["hosts"] if h.get("name")]
    assert len(named) == 32
    assert peak > 1, "es wurde nacheinander aufgelöst"
    assert peak <= physical.DNS_CONCURRENCY


def test_librenms_location_may_be_an_object_and_becomes_text():
    """LibreNMS liefert das Standortfeld je nach Version als Text ODER als
    eingebettetes Objekt. Ungeprüft durchgereicht landet das Objekt in der
    Oberfläche, und React bricht die ganze Ansicht ab."""
    from diagram.physical import location_name
    assert location_name("Haus 1 OG") == "Haus 1 OG"
    assert location_name({"id": 3, "location": "Haus 1 OG", "lat": "53.1",
                          "lng": "8.7", "timestamp": "…",
                          "fixed_coordinates": 0}) == "Haus 1 OG"
    assert location_name({"id": 3, "location": ""}) is None
    assert location_name(None) is None and location_name("  ") is None
