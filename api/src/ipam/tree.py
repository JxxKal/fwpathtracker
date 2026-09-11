"""IPAM-Baum für die Bereichsauswahl: Standort-Supernetze → iTop-Subnetze → Ranges.

iTop kennt keine Standort-Zuordnung (nur den Subnetz-Baum), die Standort-
Supernetze kommen aus den Tracker-Einstellungen. Verschachtelt wird rein über
CIDR-Enthaltensein: das ist unabhängig davon, ob TeemIP-Blöcke gepflegt sind,
und ordnet auch Subnetze ein, die niemand einem Block zugewiesen hat.
"""
from __future__ import annotations

import ipaddress


def _node(kind: str, cidr: ipaddress.IPv4Network, name: str, **extra) -> dict:
    return {"kind": kind, "cidr": str(cidr), "name": name, "children": [], **extra}


def build_tree(sites: list[dict], subnets: list[dict], ranges: list[dict]) -> list[dict]:
    """sites: [{name, cidr}], subnets: [{id, cidr, name, gateway}],
    ranges: [{subnet_id, first, last, name, dhcp}] → Wurzelknoten.

    Größere Netze werden zuerst eingehängt, jedes weitere landet im kleinsten
    bereits vorhandenen Netz, das es enthält. Subnetze ohne Standort sammeln
    sich unter „Weitere Netze"; Ranges hängen unter ihrem Subnetz.
    """
    roots: list[dict] = []
    nets: list[tuple[ipaddress.IPv4Network, dict]] = []

    def insert(net: ipaddress.IPv4Network, node: dict, into: list[dict]) -> None:
        parent = None
        for n, cand in nets:
            if n != net and net.subnet_of(n) and (parent is None or n.prefixlen > parent[0].prefixlen):
                parent = (n, cand)
        (parent[1]["children"] if parent else into).append(node)
        nets.append((net, node))

    for s in sites:
        try:
            net = ipaddress.IPv4Network(str(s.get("cidr")), strict=False)
        except ValueError:
            continue
        insert(net, _node("site", net, str(s.get("name") or net)), roots)

    others = _node("site", ipaddress.IPv4Network("0.0.0.0/0"), "Weitere Netze")
    by_id: dict[str, dict] = {}
    for s in sorted(subnets, key=lambda x: ipaddress.IPv4Network(x["cidr"]).prefixlen):
        net = ipaddress.IPv4Network(s["cidr"])
        node = _node("subnet", net, s.get("name") or "", id=s.get("id"),
                     gateway=s.get("gateway"))
        by_id[str(s.get("id"))] = node
        insert(net, node, others["children"])
    if others["children"]:
        roots.append(others)

    for r in ranges:
        parent = by_id.get(str(r.get("subnet_id")))
        if parent is None:
            continue
        parent["children"].append({
            "kind": "range", "cidr": parent["cidr"], "name": r.get("name") or "",
            "first": r["first"], "last": r["last"], "dhcp": bool(r.get("dhcp")),
            "children": [],
        })
    return roots
