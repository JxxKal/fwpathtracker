"""Resolver-Quelle 1: FortiManager-Adress-Objekte (aus dem Inventory-Cache)."""
from __future__ import annotations

from inventory.store import Inventory, parse_subnet


def resolve_name(inv: Inventory, name: str) -> dict | None:
    """Objektname → IP (nur /32-Subnets sind eindeutig)."""
    needle = name.strip().lower()
    for adom, objs in inv.addresses.items():
        for oname, obj in objs.items():
            if oname.lower() != needle:
                continue
            net = parse_subnet(obj.get("subnet"))
            if net and net.prefixlen == 32:
                return {"ip": str(net.network_address), "name": oname,
                        "provenance": "fmg", "adom": adom}
    return None


def resolve_ip(inv: Inventory, ip: str) -> dict | None:
    """IP → Objektname (exaktes /32-Objekt)."""
    for adom, objs in inv.addresses.items():
        for oname, obj in objs.items():
            net = parse_subnet(obj.get("subnet"))
            if net and net.prefixlen == 32 and str(net.network_address) == ip:
                return {"name": oname, "provenance": "fmg", "adom": adom}
    return None


def search(inv: Inventory, q: str, limit: int = 10) -> list[dict]:
    """Teilstring-Suche über FMG-Adress-Objekte — über Name, IP UND FQDN.

    Die IP mitzusuchen ist kein Zusatz, sondern der halbe Zweck: Wer eine
    Adresse aus einem Log hat, sucht genau danach das Objekt. Vorher traf die
    Suche nur den Namen, sodass ein Objekt per Name auffindbar war, über seine
    eigene IP aber nicht.

    Ranking: exakter Treffer (Name oder IP) < Präfix < Teilstring, danach
    alphabetisch — so steht bei 'svo3101' das Objekt 'WD-OT-L3-SVO3101'
    sinnvoll einsortiert, ein exakt gleichnamiges aber immer oben.
    """
    needle = q.strip().lower()
    # Nur bei ziffern-/punktartiger Eingabe auch IP-Präfixe matchen — sonst
    # würde ein Namensfragment quer durch alle Adressen streuen.
    looks_ip = bool(needle) and all(ch.isdigit() or ch == "." for ch in needle)
    scored: list[tuple[int, str, dict]] = []
    for adom in inv.adoms:
        for entry in inv.object_names(adom):
            name_l = entry["name"].lower()
            ip = (entry.get("ip") or "").lower()
            fqdn = (entry.get("fqdn") or "").lower()
            if name_l == needle or (ip and ip == needle):
                rank = 0
            elif name_l.startswith(needle) or (looks_ip and ip.startswith(needle)):
                rank = 1
            elif needle in name_l or (fqdn and needle in fqdn):
                rank = 2
            else:
                continue
            scored.append((rank, entry["name"], {**entry, "provenance": "fmg"}))
    scored.sort(key=lambda t: (t[0], t[1].lower()))
    return [entry for _, _, entry in scored[:limit]]
