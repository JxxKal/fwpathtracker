"""mxGraph-Grundgerüst: eine .drawio-Datei schreiben, ohne Bibliothek.

Gemeinsam genutzt von allen Zeichnungsarten (Struktur-, Logik- und
Physik-Plan). Eine Datei kann mehrere Seiten tragen — genutzt für die
Gerätetabellen, auf die der Logikplan verweist, wenn ein Netz zu viele
Endgeräte für die Zeichnung hat.
"""
from __future__ import annotations

import html
import xml.etree.ElementTree as ET
from datetime import datetime, timezone

# DIN A3 quer — das bevorzugte Druckformat der Netzdokumentation.
A3_LANDSCAPE = (1169, 826)


def esc(s) -> str:
    return html.escape(str(s if s is not None else ""), quote=False)


class Doc:
    """mxfile mit einer oder mehreren Seiten."""

    def __init__(self, name: str, page: tuple[int, int] = A3_LANDSCAPE) -> None:
        self.mxfile = ET.Element("mxfile", host="A38",
                                 modified=datetime.now(timezone.utc).isoformat())
        self._page_size = page
        self._n = 1
        self._pages = 0
        self.root = None            # wird von page() gesetzt
        self.page(name)

    def page(self, name: str) -> None:
        """Neue Seite anlegen und zur aktiven machen."""
        self._pages += 1
        diagram = ET.SubElement(self.mxfile, "diagram", name=name,
                                id=f"a38-{self._pages}")
        w, h = self._page_size
        model = ET.SubElement(diagram, "mxGraphModel", grid="1", gridSize="10",
                              guides="1", tooltips="1", connect="1", arrows="1",
                              fold="1", page="1", pageScale="1",
                              pageWidth=str(w), pageHeight=str(h))
        # Erste Seite behält die klassischen Ids 0/1 — so bleiben Werkzeuge und
        # Tests, die "parent=1" als oberste Ebene lesen, gültig.
        suffix = "" if self._pages == 1 else f"p{self._pages}-"
        self.root = ET.SubElement(model, "root")
        ET.SubElement(self.root, "mxCell", id=f"{suffix}0")
        ET.SubElement(self.root, "mxCell", id=f"{suffix}1", parent=f"{suffix}0")
        self._layer = f"{suffix}1"

    @property
    def layer(self) -> str:
        return self._layer

    def _id(self) -> str:
        self._n += 1
        return f"c{self._n}"

    def vertex(self, label: str, style: str, x: float, y: float, w: float, h: float,
               parent: str | None = None, tooltip: str | None = None,
               collapsed: bool = False, alt: tuple[float, float] | None = None) -> str:
        cid = self._id()
        obj = ET.SubElement(self.root, "object", id=cid, label=label)
        if tooltip:
            obj.set("tooltip", tooltip)
        cell = ET.SubElement(obj, "mxCell", style=style, vertex="1",
                             parent=parent or self._layer)
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

    def edge(self, src: str, dst: str, label: str, style: str,
             parent: str | None = None) -> str:
        cid = self._id()
        cell = ET.SubElement(self.root, "mxCell", id=cid, style=style, edge="1",
                             parent=parent or self._layer, source=src, target=dst,
                             value=label)
        geo = ET.SubElement(cell, "mxGeometry", relative="1")
        geo.set("as", "geometry")
        return cid

    def to_xml(self) -> str:
        return ('<?xml version="1.0" encoding="UTF-8"?>\n'
                + ET.tostring(self.mxfile, encoding="unicode"))
