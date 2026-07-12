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
    """Teilstring-Suche über FMG-Adress-Objekte (Host /32 + FQDN).

    Ranking: exakter Name < Präfix < Teilstring, danach alphabetisch — so steht
    z.B. bei Suche 'svo3101' das Objekt 'WD-OT-L3-SVO3101' (Teilstring) sinnvoll
    einsortiert, ein exakt gleichnamiges Objekt aber immer oben.
    """
    needle = q.strip().lower()
    scored: list[tuple[int, str, dict]] = []
    for adom in inv.adoms:
        for entry in inv.object_names(adom):
            name_l = entry["name"].lower()
            if needle not in name_l:
                continue
            rank = 0 if name_l == needle else 1 if name_l.startswith(needle) else 2
            scored.append((rank, entry["name"], {**entry, "provenance": "fmg"}))
    scored.sort(key=lambda t: (t[0], t[1].lower()))
    return [entry for _, _, entry in scored[:limit]]
