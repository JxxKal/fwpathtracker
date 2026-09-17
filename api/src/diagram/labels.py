"""Beschriftungen kürzen, ohne Information zu verlieren.

Gerätenamen und Portbezeichnungen im Feld tragen lange, immer gleiche
Präfixe: `WD-OT-L3-SVO3036`, `Ten-GigabitEthernet1/0/24`. Ausgeschrieben
kosten sie die Lesbarkeit und sagen nichts, was nicht schon im Kontext steht.
Gekürzt wird deshalb am gemeinsamen Präfix — und das Präfix wird einmal
genannt, statt es stillschweigend zu schlucken.
"""
from __future__ import annotations

import ipaddress

SEPARATORS = "-_./"


def common_prefix(names: list[str], min_len: int = 4, min_count: int = 3) -> str:
    """Gemeinsames Präfix, am Trennzeichen abgeschnitten — sonst "".

    Mitten im Wort wird nicht geschnitten: aus `srv-alpha`/`srv-alfred` wird
    `srv-`, nicht `srv-al`. Und wenn nach dem Schnitt ein Name leer bliebe,
    wird gar nicht gekürzt.
    """
    real = [n for n in names if n]
    if len(real) < min_count:
        return ""
    prefix = real[0]
    for name in real[1:]:
        while prefix and not name.upper().startswith(prefix.upper()):
            prefix = prefix[:-1]
        if not prefix:
            return ""
    # Endet das gemeinsame Stück auf einem Buchstaben und folgt überall eine
    # Ziffer, sitzt der Schnitt genau an der Grenze Name/Nummer — so bleibt aus
    # `Ten-GigabitEthernet1/0/1` und `…2/0/1` das Modul erhalten. Sonst wird am
    # letzten Trennzeichen geschnitten, sonst zerlegte es `WD-OT-L3-SVO3036`
    # mitten in der Gerätenummer.
    at_number = prefix[-1:].isalpha() and all(
        len(n) > len(prefix) and n[len(prefix)].isdigit() for n in real)
    if not at_number:
        cut = max(prefix.rfind(c) for c in SEPARATORS)
        prefix = prefix[:cut + 1] if cut > 0 else ""
    if len(prefix) < min_len or any(len(n) <= len(prefix) for n in real):
        return ""
    return prefix


def strip_prefix(name: str, prefix: str) -> str:
    if prefix and name.upper().startswith(prefix.upper()):
        return name[len(prefix):]
    return name


def short_ip(ip: str, cidr: str) -> str:
    """IP auf die im Netz signifikanten Stellen kürzen: im /24 bleibt `.73`,
    im /16 `.58.73`."""
    try:
        net = ipaddress.IPv4Network(cidr)
    except ValueError:
        return ip
    keep = max(1, min(4, (32 - net.prefixlen + 7) // 8))
    return "." + ".".join(ip.split(".")[-keep:])
