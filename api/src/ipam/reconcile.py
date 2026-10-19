"""Bestandsabgleich: was im iTop steht gegen das, was im Netz lebt.

Vier Quellen sagen je etwas anderes über dieselbe IP:

- iTop (CIs mit Management-IP, IPv4Address-Objekte) — das Soll,
- ARP-Historie (FortiGate/LibreNMS) — wer je mit der Firewall gesprochen hat,
- FortiAnalyzer (Asset Identity Center) — wen die Fabric gerade sieht,
- DNS (PTR) — wie der Host heißt, wenn man ihn fragt.

Keine davon ist für sich richtig. Erst der Vergleich zeigt, wo die CMDB lügt:
Geräte, die laufen, aber nirgends geführt sind; Einträge, deren Gerät es
längst nicht mehr gibt; zwei MACs an einer IP; Namen, die auseinanderlaufen.
A38 meldet das — es korrigiert nichts.

Rein funktional: Quellen rein, Zeilen mit Befunden raus.
"""
from __future__ import annotations

import ipaddress
import re
from datetime import datetime, timezone
from typing import Any

ACTIVE_STATUS = ("allocated", "reserved")

SEVERITY = {"ip_conflict": "error", "not_in_itop": "warn", "itop_released": "warn",
            "stale_in_itop": "info", "mac_changed": "info", "name_mismatch": "info"}

_MACLIKE = re.compile(r"^[0-9a-f]{2}([:-]?[0-9a-f]{2}){5}$", re.I)


def short_name(name: Any) -> str | None:
    """Vergleichbarer Kurzname: klein, ohne Domain. IP- und MAC-artige
    „Namen" (FAZ trägt die gern ein) zählen nicht."""
    n = str(name or "").strip().lower().rstrip(".")
    if not n or n in ("unknown", "n/a", "-"):
        return None
    try:
        ipaddress.ip_address(n)
        return None
    except ValueError:
        pass
    if _MACLIKE.match(n):
        return None
    return n.split(".")[0]


def _ts(value: Any) -> datetime | None:
    if not value:
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    try:
        ts = datetime.fromisoformat(str(value))
    except ValueError:
        return None
    return ts if ts.tzinfo else ts.replace(tzinfo=timezone.utc)


def _in(cidr: ipaddress.IPv4Network, ip: Any) -> bool:
    try:
        return ipaddress.IPv4Address(str(ip).strip()) in cidr
    except ValueError:
        return False


def reconcile(cidr: str, *, itop_hosts: list[dict], itop_addresses: dict[str, dict],
              arp_rows: list[dict], faz_hosts: list[dict] | None,
              dns_names: dict[str, str | None], librenms_devices: dict[str, dict],
              fmg_names: dict[str, str], firewall_ips: dict[str, str] | None = None,
              active_days: int = 7, stale_days: int = 30,
              now: datetime | None = None) -> dict:
    """firewall_ips: Interface-IPs der FortiGates (ip → „gerät/interface"). Sie
    stehen in keiner ARP-Tabelle — die Firewall sieht sich nicht selbst — und
    wären sonst jedes Mal „verwaist"."""
    net = ipaddress.IPv4Network(cidr, strict=False)
    now = now or datetime.now(timezone.utc)
    active_s, stale_s = active_days * 86400, stale_days * 86400
    rows: dict[str, dict] = {}

    def slot(ip: str) -> dict:
        return rows.setdefault(ip, {
            "ip": ip, "names": {}, "kind": None, "itop_id": None, "itop_status": None,
            "macs": [], "last_seen": None, "age_s": None, "os": None,
            "sources": [], "findings": []})

    def seen(row: dict, ts: datetime | None) -> None:
        if ts is None:
            return
        age = max(0, int((now - ts).total_seconds()))
        if row["age_s"] is None or age < row["age_s"]:
            row["last_seen"], row["age_s"] = ts.isoformat(), age

    for h in itop_hosts:
        if not _in(net, h.get("ip")):
            continue
        r = slot(str(ipaddress.IPv4Address(h["ip"].strip())))
        r["names"]["itop"] = h.get("name")
        r["kind"], r["itop_id"] = h.get("kind"), h.get("id") or None
        r["sources"].append("itop-ci")
    for ip, rec in itop_addresses.items():
        if not _in(net, ip):
            continue
        r = slot(ip)
        r["itop_status"] = rec.get("status") or None
        if rec.get("name"):
            r["names"]["itop_ip"] = rec["name"]
        r["sources"].append("itop-ip")
    for b in arp_rows:
        if not _in(net, b.get("ip")):
            continue
        r = slot(b["ip"])
        r["macs"].append({"mac": b["mac"], "source": "arp", "first_seen": b.get("first_seen"),
                          "last_seen": b.get("last_seen"), "device": b.get("device"),
                          "vdom": b.get("vdom"), "interface": b.get("interface")})
        seen(r, _ts(b.get("last_seen")))
        if "arp" not in r["sources"]:
            r["sources"].append("arp")
    for f in faz_hosts or []:
        if not _in(net, f.get("ip")):
            continue
        r = slot(f["ip"])
        if f.get("name"):
            r["names"]["faz"] = f["name"]
        r["os"] = f.get("os") or r["os"]
        ts = _ts(f.get("last_seen"))
        if f.get("mac") and not any(m["mac"] == f["mac"] for m in r["macs"]):
            r["macs"].append({"mac": f["mac"], "source": "faz", "first_seen": None,
                              "last_seen": f.get("last_seen"), "device": None,
                              "vdom": None, "interface": None})
        # Ohne Zeitstempel führt der FAZ den Endpoint als aktuell.
        seen(r, ts or now)
        r["sources"].append("faz")
    for dev in librenms_devices.values():
        ip = str(dev.get("ip") or "").strip()
        if not _in(net, ip):
            continue
        r = slot(ip)
        r["names"]["librenms"] = dev.get("sysName") or dev.get("hostname")
        r["kind"] = r["kind"] or "switch"
        if "librenms" not in r["sources"]:
            r["sources"].append("librenms")
    if net.prefixlen <= 30:
        rows.pop(str(net.network_address), None)
        rows.pop(str(net.broadcast_address), None)
    for ip, label in (firewall_ips or {}).items():
        if _in(net, ip):
            r = slot(ip)
            r["kind"], r["names"]["firewall"] = "firewall", label
            r["sources"].append("fmg-intf")
    for ip, r in rows.items():
        if dns_names.get(ip):
            r["names"]["dns"] = dns_names[ip]
        if ip in fmg_names:
            r["names"]["fmg"] = fmg_names[ip]

    observed = any(r["macs"] for r in rows.values())
    for r in rows.values():
        _findings(r, active_s, stale_s, observed, now)
        r["display_name"] = next((r["names"][k] for k in ("itop", "itop_ip", "dns", "faz",
                                                          "librenms", "fmg", "firewall")
                                  if r["names"].get(k)), None)

    out = sorted(rows.values(), key=lambda r: ipaddress.IPv4Address(r["ip"]))
    counts: dict[str, int] = {}
    for r in out:
        for f in r["findings"]:
            counts[f["code"]] = counts.get(f["code"], 0) + 1
    return {
        "network": str(net), "rows": out, "counts": counts,
        "stats": {"hosts": len(out),
                  "in_itop": sum(1 for r in out if _in_itop(r)),
                  "active": sum(1 for r in out if _active(r, active_s)),
                  "with_findings": sum(1 for r in out if r["findings"])},
        "observed": observed, "faz": faz_hosts is not None,
        "active_days": active_days, "stale_days": stale_days,
    }


def _in_itop(r: dict) -> bool:
    return "itop-ci" in r["sources"] or (r["itop_status"] in ACTIVE_STATUS)


def _active(r: dict, active_s: int) -> bool:
    return r["age_s"] is not None and r["age_s"] <= active_s


def _add(r: dict, code: str, text: str) -> None:
    r["findings"].append({"code": code, "severity": SEVERITY[code], "text": text})


def _findings(r: dict, active_s: int, stale_s: int, observed: bool, now: datetime) -> None:
    if r["kind"] == "firewall":
        return
    active = _active(r, active_s)
    if active and not _in_itop(r):
        if r["itop_status"]:
            _add(r, "itop_released",
                 f"Aktiv, im iTop aber als „{r['itop_status']}“ geführt.")
        else:
            _add(r, "not_in_itop", "Aktiv, aber weder als CI noch als IP-Adresse im iTop.")
    # Nur wenn in diesem Netz überhaupt jemand beobachtet wird — sonst wäre
    # jeder iTop-Eintrag „verwaist", bloß weil der ARP-Sweep das Netz nicht sieht.
    # Reserviert heißt: absichtlich frei gehalten — Stille ist dort kein Befund.
    reserved_only = "itop-ci" not in r["sources"] and r["itop_status"] == "reserved"
    if observed and _in_itop(r) and not reserved_only \
            and (r["age_s"] is None or r["age_s"] > stale_s):
        when = (f"zuletzt vor {r['age_s'] // 86400} Tagen gesehen" if r["age_s"] is not None
                else "nie gesehen")
        _add(r, "stale_in_itop", f"Im iTop geführt, im Netz {when}.")

    recent = [m for m in r["macs"]
              if (ts := _ts(m.get("last_seen"))) and (now - ts).total_seconds() <= active_s]
    macs = {m["mac"] for m in recent}
    if len(macs) > 1:
        if _overlap(recent):
            _add(r, "ip_conflict", f"{len(macs)} MACs gleichzeitig an dieser IP: "
                                   + ", ".join(sorted(macs)))
        else:
            newest = max(recent, key=lambda m: m["last_seen"])
            _add(r, "mac_changed", f"MAC gewechselt — jetzt {newest['mac']} "
                                   f"(Gerät getauscht oder DHCP neu vergeben).")

    shorts = {k: short_name(v) for k, v in r["names"].items()}
    shorts = {k: v for k, v in shorts.items() if v}
    ref = shorts.get("itop") or shorts.get("itop_ip")
    if ref:
        other = {k: v for k, v in shorts.items()
                 if k in ("dns", "faz") and v != ref}
        if other:
            _add(r, "name_mismatch", "Name weicht vom iTop ab: " + ", ".join(
                f"{_SRC_LABEL[k]} „{r['names'][k]}“" for k in other))


_SRC_LABEL = {"dns": "DNS", "faz": "FortiAnalyzer"}


def _overlap(macs: list[dict]) -> bool:
    """Liegen die Sichtungszeiträume zweier MACs übereinander? Nacheinander ist
    ein Tausch, gleichzeitig ein Konflikt. Ohne first_seen (FAZ) zählt der
    Zeitpunkt der letzten Sichtung als Zeitraum."""
    spans = []
    for m in macs:
        last = _ts(m.get("last_seen"))
        first = _ts(m.get("first_seen")) or last
        if last:
            spans.append((m["mac"], first, last))
    for i, (ma, fa, la) in enumerate(spans):
        for mb, fb, lb in spans[i + 1:]:
            if ma != mb and fa <= lb and fb <= la:
                return True
    return False
