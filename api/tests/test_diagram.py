"""Netzplan: Modell aus dem Lab-Inventar, Detailstufen, draw.io-Ausgabe."""
from __future__ import annotations

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


async def test_title_block_sits_below_the_drawing(inventory, prefixes):
    """Es gehört unter die Zeichnung, nicht darüber — verglichen wird gegen
    dieselbe Zeichnung ohne Schriftfeld."""
    from diagram import titleblock
    m = await _build(inventory, prefixes)

    def top_level(xml):
        return [_geo(o.find("mxCell")) for o in ET.fromstring(xml).findall(".//object")
                if o.find("mxCell").get("parent") == "1"]

    plain = top_level(drawio.render(m))
    info = titleblock.info_from(TB, title="T", subtitle="S", author="a", drawing_no="N")
    withtb = top_level(drawio.render(m, title_block=info))
    content_bottom = max(g[1] + g[3] for g in plain)
    added = [g for g in withtb if g not in plain]
    assert len(added) > 20                       # das Schriftfeld besteht aus vielen Zellen
    assert min(g[1] for g in added) >= content_bottom
    # Und es ist ein zusammenhängender Block in der erwarteten Größe.
    assert max(g[0] + g[2] for g in added) - min(g[0] for g in added) == titleblock.WIDTH
    assert max(g[1] + g[3] for g in added) - min(g[1] for g in added) == titleblock.HEIGHT


def test_logo_data_uri_is_written_the_way_mxgraph_reads_it():
    """';base64,' würde den Style zerschneiden — draw.io schreibt ','."""
    from diagram import titleblock
    assert titleblock.normalize_logo("data:image/png;base64,AAAB") == "data:image/png,AAAB"
    assert titleblock.normalize_logo("data:image/png,AAAB") == "data:image/png,AAAB"
    assert titleblock.normalize_logo("https://example.net/logo.png") is None
    assert titleblock.normalize_logo("") is None
