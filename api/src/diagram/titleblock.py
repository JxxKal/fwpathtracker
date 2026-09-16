"""Schriftfeld (Title Block) unten rechts in jeder erzeugten Zeichnung.

Aufbau wie im Engineering-Schriftfeld, das im Haus verwendet wird:

    ┌──────────────────┬────────────────┬──────────────────────────────┐
    │ G                │  Vertraulich   │        Datum │ Name │ Gruppe │
    │ F …              ├────────────────┤ Autor  …     │ …    │ …      │
    │ A  Datum   Name  │                │ Check        │      │        │
    ├──────────────────┤     Logo       ├──────────────────────────────┤
    │ Rev  Datum  Name │                │      TITEL / Untertitel      │
    │                  │                ├───────────────────┬──────────┤
    │                  │                │ Zeichnungsnummer  │  Blatt   │
    └──────────────────┴────────────────┴───────────────────┴──────────┘

Was A38 selbst weiß, füllt A38 selbst: Titel und Untertitel aus dem Scope,
Datum von heute, Autor aus dem angemeldeten Benutzer, Zeichnungsnummer aus
dem Dateinamen. Firmenname, Vertraulichkeitsvermerk, Gruppe und Logo sind
Stammdaten und kommen aus den Einstellungen — die kann kein System erraten.
"""
from __future__ import annotations

from datetime import date

WIDTH, HEIGHT = 1000.0, 208.0
ROW = HEIGHT / 8            # 26 — die Revisionstabelle gibt das Raster vor
REV_W = (70.0, 145.0, 125.0)
MID_W = 230.0
RIGHT_W = (70.0, 130.0, 150.0, 80.0)
REV_ROWS = ("G", "F", "E", "D", "C", "B", "A")

_BOX = ("rounded=0;html=1;whiteSpace=wrap;fillColor=#ffffff;strokeColor=#000000;"
        "fontColor=#000000;strokeWidth=1;")
CELL = _BOX + "fontSize=10;"
CELL_L = _BOX + "fontSize=10;align=left;spacingLeft=6;"
HEAD = _BOX + "fontSize=10;fontStyle=1;"
TITLE = _BOX + "fontSize=18;fontStyle=1;verticalAlign=middle;"
TINY = _BOX + "fontSize=7;"
LOGO_TEXT = _BOX + "fontSize=14;fontStyle=1;verticalAlign=middle;"


def normalize_logo(uri: str) -> str | None:
    """Data-URI so schreiben, wie mxGraph sie im Style verträgt.

    In einem mxGraph-Style trennt ';' die Schlüssel — ein
    'data:image/png;base64,…' würde den Style mitten im Bild zerschneiden.
    draw.io schreibt deshalb selbst 'data:image/png,<base64>'; genau das
    machen wir hier auch.
    """
    uri = (uri or "").strip()
    if not uri.startswith("data:image/"):
        return None
    return uri.replace(";base64,", ",", 1)


def _fmt_date(value: str | None = None) -> str:
    return value or date.today().strftime("%d.%m.%Y")


def draw(doc, x: float, y: float, info: dict) -> None:
    """Schriftfeld mit der linken oberen Ecke bei (x, y) zeichnen."""
    def box(dx: float, dy: float, w: float, h: float, text: str = "",
            style: str = CELL, tooltip: str | None = None) -> None:
        doc.vertex(text, style, x + dx, y + dy, w, h, tooltip=tooltip)

    # ── Links: Revisionstabelle ───────────────────────────────────────────
    c0, c1, c2 = REV_W
    for i, rev in enumerate(REV_ROWS):
        dy = i * ROW
        filled = rev == info.get("revision", "A")
        box(0, dy, c0, ROW, rev, HEAD)
        box(c0, dy, c1, ROW, info["date"] if filled else "")
        box(c0 + c1, dy, c2, ROW, info["author"] if filled else "")
    box(0, 7 * ROW, c0, ROW, "Rev", HEAD)
    box(c0, 7 * ROW, c1, ROW, "Datum", HEAD)
    box(c0 + c1, 7 * ROW, c2, ROW, "Name", HEAD)

    # ── Mitte: Vertraulichkeit + Logo ─────────────────────────────────────
    mx = c0 + c1 + c2
    box(mx, 0, MID_W, 2 * ROW, info.get("confidential") or "", CELL)
    logo = normalize_logo(info.get("logo") or "")
    if logo:
        box(mx, 2 * ROW, MID_W, 6 * ROW, "",
            f"shape=image;html=1;imageAspect=1;image={logo};"
            "strokeColor=#000000;fillColor=#ffffff;")
    else:
        box(mx, 2 * ROW, MID_W, 6 * ROW, info.get("company") or "", LOGO_TEXT)

    # ── Rechts: Autor/Check, Titel, Zeichnungsnummer ──────────────────────
    rx = mx + MID_W
    r0, r1, r2, r3 = RIGHT_W
    box(rx, 0, r0, ROW, "")
    box(rx + r0, 0, r1, ROW, "Datum", HEAD)
    box(rx + r0 + r1, 0, r2, ROW, "Name", HEAD)
    box(rx + r0 + r1 + r2, 0, r3, ROW, "Gruppe", HEAD)

    box(rx, ROW, r0, ROW, "Autor", CELL_L)
    box(rx + r0, ROW, r1, ROW, info["date"])
    box(rx + r0 + r1, ROW, r2, ROW, info["author"])
    box(rx + r0 + r1 + r2, ROW, r3, 2 * ROW, info.get("group") or "", TINY)

    box(rx, 2 * ROW, r0, ROW, "Check", CELL_L)
    box(rx + r0, 2 * ROW, r1, ROW, "")
    box(rx + r0 + r1, 2 * ROW, r2, ROW, "")

    right_w = r0 + r1 + r2 + r3
    subtitle = info.get("subtitle") or ""
    label = info["title"] + (f"<br><span style='font-size:11px;font-weight:normal'>"
                             f"{subtitle}</span>" if subtitle else "")
    box(rx, 3 * ROW, right_w, 3 * ROW, label, TITLE, tooltip=info.get("tooltip"))
    box(rx, 6 * ROW, right_w, ROW, info.get("note") or "", CELL_L)
    box(rx, 7 * ROW, right_w - r3, ROW,
        f"Zeichnungsnummer &#160;&#160; {info.get('drawing_no') or '—'}", CELL_L)
    box(rx + right_w - r3, 7 * ROW, r3, ROW, f"Blatt {info.get('sheet') or '1'}", CELL)


def info_from(cfg: dict, *, title: str, subtitle: str, author: str,
              drawing_no: str, note: str = "", tooltip: str | None = None) -> dict:
    """Stammdaten (Einstellungen) + das, was A38 selbst weiß, zusammenführen."""
    return {
        "title": title, "subtitle": subtitle, "author": author or "—",
        "date": _fmt_date(), "drawing_no": drawing_no, "sheet": "1",
        "note": note, "tooltip": tooltip,
        "company": cfg.get("company") or "",
        "confidential": cfg.get("confidential", "Company confidential"),
        "group": cfg.get("group") or "",
        "logo": cfg.get("logo") or "",
        "revision": cfg.get("revision") or "A",
    }
