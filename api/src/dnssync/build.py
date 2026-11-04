"""Aus iTop-Adressobjekten, CIs, Domains und DNS die Vorschlagsliste bauen
(reine Funktion — testbar ohne iTop und DNS)."""
from __future__ import annotations

import ipaddress

# Adressen, die niemand mehr nutzt, bekommen keinen Namen.
SKIP_STATUS = {"released", "unassigned"}

SECTIONS = {"missing": "Ohne DNS-Namen im iTop", "mismatch": "Name weicht vom DNS ab",
            "orphan": "IP-Objekte ohne CI"}


def split_fqdn(fqdn: str, domains: dict[str, str]) -> tuple[str, str, str] | None:
    """'srv1.ot.corp.com' + Domains {'corp.com': '3', 'ot.corp.com': '7'} →
    ('srv1', 'ot.corp.com', '7'). Längster Treffer; der Kurzname darf keinen
    Punkt enthalten (TeemIP)."""
    fqdn = fqdn.lower().rstrip(".")
    best = None
    for name, did in domains.items():
        n = name.lower().rstrip(".")
        if fqdn.endswith("." + n) and (best is None or len(n) > len(best[1])):
            best = (fqdn[: -len(n) - 1], n, did)
    if best and best[0] and "." not in best[0]:
        return best
    return None


def _itop_fqdn(a: dict) -> str:
    f = str(a.get("fqdn") or "").strip().lower().rstrip(".")
    if f:
        return f
    short = str(a.get("short_name") or "").strip().lower()
    dom = str(a.get("domain_name") or "").strip().lower()
    return f"{short}.{dom}" if short and dom else short


def items(addresses: list[dict], cis: list[dict], domains_rows: list[dict],
          dns: dict[str, dict], ignored: set[str]) -> tuple[list[dict], dict]:
    domains = {str(d.get("name") or "").strip(): str(d.get("_key") or "")
               for d in domains_rows if d.get("name")}
    ci_by_ip: dict[str, list[dict]] = {}
    for c in cis:
        ci_by_ip.setdefault(c["ip_id"], []).append(c)
    out: list[dict] = []
    stats = {"addresses": 0, "checked": 0, "no_ptr": 0, "ok": 0, "ignored": 0}
    no_ptr: list[dict] = []
    for a in addresses:
        ip_id = str(a.get("_key") or "")
        ip = str(a.get("ip") or "").strip()
        try:
            ipaddress.IPv4Address(ip)
        except ValueError:
            continue
        if str(a.get("status") or "").lower() in SKIP_STATUS:
            continue
        stats["addresses"] += 1
        linked = ci_by_ip.get(ip_id, [])
        current = _itop_fqdn(a)
        if ip_id in ignored:
            stats["ignored"] += 1
            continue
        d = dns.get(ip)
        if d is None:
            continue
        stats["checked"] += 1
        ptrs = d.get("ptr") or []
        if not ptrs:
            stats["no_ptr"] += 1
            if not current and len(no_ptr) < 500:
                no_ptr.append({"ip": ip, "ci": linked[0]["name"] if linked else None})
            continue
        # Bevorzugt ein PTR, dessen A wieder auf die IP zeigt.
        confirmed = [n for n in ptrs if ip in (d.get("forward") or {}).get(n, [])]
        name = confirmed[0] if confirmed else ptrs[0]
        if current == name or (current and current.split(".")[0] == name.split(".")[0]
                               and "." not in current):
            stats["ok"] += 1
            continue
        section = "mismatch" if current else ("missing" if linked else "orphan")
        split = split_fqdn(name, domains)
        if split is None:
            status, reason = "no_domain", (
                f"Für {name} gibt es im iTop keine passende Domain — erst die Domain anlegen.")
        elif confirmed:
            status, reason = "confirmed", "PTR und A-Record stimmen überein."
        else:
            fwd = (d.get("forward") or {}).get(name) or []
            status, reason = "unconfirmed", (
                f"PTR {name}, aber A-Record zeigt auf {', '.join(fwd)}." if fwd
                else f"PTR {name}, aber kein A-Record dazu.")
        if len(ptrs) > 1:
            reason += f" Mehrere PTR: {', '.join(ptrs)}."
        out.append({
            "id": ip_id, "ip": ip, "section": section, "status": status, "reason": reason,
            "itop_status": str(a.get("status") or ""), "itop_name": current or None,
            "itop_short": str(a.get("short_name") or "") or None,
            "itop_domain_id": str(a.get("domain_id") or "0"),
            "dns_name": name, "short_name": split[0] if split else None,
            "domain": split[1] if split else None, "domain_id": split[2] if split else None,
            "cis": [{"class": c["class"], "id": c["id"], "name": c["name"]} for c in linked],
            # Vorausgewählt nur Bestätigtes — Abweichungen überschreibt niemand nebenbei.
            "selected": status == "confirmed" and section != "mismatch",
            "selectable": status in ("confirmed", "unconfirmed"),
        })
    out.sort(key=lambda r: (list(SECTIONS).index(r["section"]),
                            ipaddress.IPv4Address(r["ip"])))
    stats.update({s: sum(1 for r in out if r["section"] == s) for s in SECTIONS})
    stats["no_ptr_sample"] = no_ptr
    return out, stats
