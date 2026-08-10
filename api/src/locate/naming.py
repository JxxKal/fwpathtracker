"""Namens-Aliase des gesuchten Ziels — für den Abgleich mit Topologie-Daten.

Ein Switch heißt an drei Stellen unterschiedlich: `bpvo004.op-tech.com` in
LibreNMS, `bpvo004` als FMG-Adressobjekt, `BPVO004` in einer Port-Description.
Für den Abgleich brauchen wir alle Schreibweisen in einer Form.

Wozu: Wenn der LLDP-Nachbar eines Ports das gesuchte Gerät IST, ist dieser Port
die Antwort — nicht ein auszuschließender Uplink. Dasselbe gilt schwächer für
Port-Descriptions wie `uplink-bpvo300` oder `bpvo049-Head-P24`, die die
Gegenstelle beim Namen nennen.
"""
from __future__ import annotations

import re

# Kürzer als das taugt nicht als Substring-Suche in Beschreibungen — `lan`
# oder `sw` würden in jeder zweiten Description treffen.
MIN_ALIAS_LEN = 4

_MAC_LIKE = re.compile(r"^[0-9a-f]{12}$|^([0-9a-f]{2}[\s:.\-]){5}[0-9a-f]{2}$")


def is_mac_like(value: str | None) -> bool:
    """LLDP-Nachbarn ohne sysName melden ihre Chassis-MAC als Hostname."""
    if not value:
        return False
    return bool(_MAC_LIKE.match(value.strip().lower()))


def normalize_host(value: str | None) -> str | None:
    """`BPVO004.op-tech.com` → `bpvo004`. Domain weg, klein, getrimmt."""
    if not value:
        return None
    short = str(value).strip().lower().split(".")[0]
    return short or None


def build_aliases(names: list[str], extra: list[str | None] | None = None) -> set[str]:
    """Alle bekannten Namen des Ziels → Alias-Menge für den Abgleich.

    Nimmt sowohl die volle Schreibweise als auch den Kurznamen ohne Domain auf,
    weil Port-Descriptions mal so und mal so benennen.
    """
    out: set[str] = set()
    for raw in [*names, *(extra or [])]:
        if not raw:
            continue
        full = str(raw).strip().lower()
        if is_mac_like(full):
            continue
        for cand in (full, normalize_host(full)):
            if cand and len(cand) >= MIN_ALIAS_LEN:
                out.add(cand)
    return out


def matches_description(aliases: set[str], *texts: str | None) -> str | None:
    """Erster Alias, der in einer der Beschreibungen vorkommt — sonst None."""
    haystack = " ".join(t.strip().lower() for t in texts if t)
    if not haystack:
        return None
    for alias in sorted(aliases, key=len, reverse=True):   # längster Treffer gewinnt
        if alias in haystack:
            return alias
    return None
