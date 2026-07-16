"""Deep-Tracker: Alle-Ports-Analyse (TCP/UDP), statisch aus dem Cache.

Statt eines einzelnen 5-Tupels (Live-`policy-lookup`) bestimmen wir pro Hop die
komplette Menge erlaubter Ports und schneiden sie über den Pfad: ein Port kommt
nur durch, wenn ihn JEDE Firewall im Pfad erlaubt. Innerhalb eines Hops gilt
First-Match wie in FortiOS — die erste Policy (in Package-Reihenfolge), deren
Src/Dst/Service einen Port abdeckt, entscheidet ihn (accept/deny).

Intervalle sind inklusive Integer-Ranges (lo, hi), 1..65535.
"""
from __future__ import annotations

Interval = tuple[int, int]

FULL: list[Interval] = [(1, 65535)]
PROTOS = ("tcp", "udp")


# ── Intervall-Algebra (auf sortierten, disjunkten Range-Listen) ───────────────

def merge(intervals: list[Interval]) -> list[Interval]:
    """Sortiert + verschmilzt überlappende/angrenzende Ranges."""
    ivs = sorted((lo, hi) for lo, hi in intervals if lo <= hi)
    out: list[Interval] = []
    for lo, hi in ivs:
        if out and lo <= out[-1][1] + 1:
            out[-1] = (out[-1][0], max(out[-1][1], hi))
        else:
            out.append((lo, hi))
    return out


def intersect(a: list[Interval], b: list[Interval]) -> list[Interval]:
    a, b = merge(a), merge(b)
    out: list[Interval] = []
    i = j = 0
    while i < len(a) and j < len(b):
        lo, hi = max(a[i][0], b[j][0]), min(a[i][1], b[j][1])
        if lo <= hi:
            out.append((lo, hi))
        if a[i][1] < b[j][1]:
            i += 1
        else:
            j += 1
    return out


def subtract(a: list[Interval], b: list[Interval]) -> list[Interval]:
    """a ∖ b."""
    b = merge(b)
    out: list[Interval] = []
    for lo, hi in merge(a):
        cur = lo
        for blo, bhi in b:
            if bhi < cur or blo > hi:
                continue
            if blo > cur:
                out.append((cur, blo - 1))
            cur = max(cur, bhi + 1)
            if cur > hi:
                break
        if cur <= hi:
            out.append((cur, hi))
    return out


# ── Pro Hop: erlaubte Portmenge aus den geordneten Policies ───────────────────

def hop_allowed(inv, adom: str, policies: list[dict], src_ip: str, dst_ip: str) -> dict:
    """Erlaubte TCP/UDP-Ranges eines Hops. `policies` sind die geordneten,
    zonen-gematchten Kandidaten (inv.candidate_policies). First-Match:
    unentschiedene Ports werden von der ersten abdeckenden Policy entschieden.

    Nicht enumerierbare Policies (Internet-Service/ISDB) und negierte Adress-/
    Service-Felder werden übersprungen und gemeldet (warnings)."""
    allowed: dict[str, list[Interval]] = {"tcp": [], "udp": []}
    undecided: dict[str, list[Interval]] = {"tcp": list(FULL), "udp": list(FULL)}
    warnings: list[str] = []

    for p in policies:
        if not undecided["tcp"] and not undecided["udp"]:
            break
        pid = p.get("policyid")
        if p.get("internet_service"):
            warnings.append(f"Policy #{pid} nutzt Internet-Service/ISDB — "
                            "Ports nicht auflösbar, übersprungen.")
            continue
        if p.get("srcaddr_negate") or p.get("dstaddr_negate") or p.get("service_negate"):
            warnings.append(f"Policy #{pid} hat negierte Adress-/Service-Felder — "
                            "übersprungen (Port-Analyse ggf. unvollständig).")
            continue
        if not inv.addr_matches(adom, p["srcaddr"], src_ip):
            continue
        if not inv.addr_matches(adom, p["dstaddr"], dst_ip):
            continue
        svc = inv.service_intervals(adom, p["service"])
        accept = p["action"] == "accept"
        for proto in PROTOS:
            if not undecided[proto]:
                continue
            decided = intersect(undecided[proto], svc[proto])
            if not decided:
                continue
            if accept:
                allowed[proto] = merge(allowed[proto] + decided)
            undecided[proto] = subtract(undecided[proto], decided)

    return {"tcp": merge(allowed["tcp"]), "udp": merge(allowed["udp"]), "warnings": warnings}


# ── Über den Pfad: Schnittmenge + „wo stirbt Port X" ──────────────────────────

def combine(hops: list[dict]) -> dict:
    """`hops` in Pfad-Reihenfolge, je Hop {'label', 'tcp':[...], 'udp':[...]}.

    Liefert end-to-end erlaubte Ranges (Schnitt über alle Hops) je Proto sowie
    `limits`: Ranges, die bis zu einem Hop offen waren, dort aber blockiert
    wurden — inkl. blockierendem Hop-Label (für „bis wohin kommt Port X")."""
    end: dict[str, list[Interval]] = {"tcp": list(FULL), "udp": list(FULL)}
    limits: dict[str, list[dict]] = {"tcp": [], "udp": []}
    for hop in hops:
        for proto in PROTOS:
            before = end[proto]
            allowed = hop.get(proto, [])
            dropped = subtract(before, allowed)
            for iv in dropped:
                limits[proto].append({"range": list(iv), "hop": hop.get("label")})
            end[proto] = intersect(before, allowed)
    return {"tcp": end["tcp"], "udp": end["udp"], "limits": limits}
