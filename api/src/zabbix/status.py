"""Zabbix-Zustand je Host: Zuordnung über IP, sonst über den Namen.

Unbekannt bleibt unbekannt: ein Host, den Zabbix nicht kennt, bekommt keinen
Status — er wird nicht grün gemalt, nur weil nichts Schlechtes über ihn
bekannt ist.
"""
from __future__ import annotations

from collections.abc import Iterable

SEVERITY = {0: "nicht klassifiziert", 1: "Information", 2: "Warnung", 3: "Durchschnitt",
            4: "Hoch", 5: "Katastrophe"}
# Farben wie im Zabbix-Frontend.
SEVERITY_COLOR = {0: "#97AAB3", 1: "#7499FF", 2: "#FFC859", 3: "#FFA059", 4: "#E97659",
                  5: "#E45959"}
OK_COLOR = "#59DB8F"
DOWN_COLOR = "#B71C1C"
OFF_COLOR = "#BBBBBB"
MAINT_COLOR = "#7A5CC4"
PROBLEMS_SHOWN = 5


def _name_keys(name: str) -> list[str]:
    low = (name or "").strip().lower()
    if not low:
        return []
    short = low.split(".", 1)[0]
    return [low] if short == low else [low, short]


def index(hosts: list[dict], triggers: list[dict]) -> dict:
    """Hosts nach IP und Name, je Host der Zustand samt aktiver Probleme."""
    probs: dict[str, list[dict]] = {}
    for t in triggers:
        ev = t.get("lastEvent") or {}
        if str(ev.get("suppressed") or "0") == "1":
            continue
        p = {"name": t.get("description") or "?", "severity": int(t.get("priority") or 0),
             "since": int(t.get("lastchange") or 0) or None,
             "ack": str(ev.get("acknowledged") or "0") == "1"}
        for h in t.get("hosts") or []:
            probs.setdefault(str(h.get("hostid")), []).append(p)
    by_ip: dict[str, dict] = {}
    by_name: dict[str, dict] = {}
    for h in hosts:
        hid = str(h.get("hostid"))
        ifaces = h.get("interfaces") or []
        mine = sorted(probs.get(hid, []), key=lambda p: (-p["severity"], -(p["since"] or 0)))
        disabled = str(h.get("status") or "0") == "1"
        st = {
            "hostid": hid, "host": h.get("host") or "", "name": h.get("name") or h.get("host"),
            "disabled": disabled,
            "maintenance": str(h.get("maintenance_status") or "0") == "1",
            # available: 0 unbekannt, 1 erreichbar, 2 nicht erreichbar — je Interface.
            "unavailable": bool(ifaces) and all(str(i.get("available")) == "2" for i in ifaces),
            "problems": mine,
            "severity": mine[0]["severity"] if mine else None,
        }
        st["state"] = ("disabled" if disabled else "maintenance" if st["maintenance"]
                       else "down" if st["unavailable"] else "problem" if mine else "ok")
        for i in ifaces:
            if i.get("ip") and i["ip"] not in ("127.0.0.1", "0.0.0.0"):
                # Ein aktiver Host schlägt einen abgeschalteten mit derselben IP.
                if i["ip"] not in by_ip or by_ip[i["ip"]]["disabled"]:
                    by_ip[i["ip"]] = st
            for k in _name_keys(i.get("dns") or ""):
                by_name.setdefault(k, st)
        for n in (h.get("host"), h.get("name")):
            for k in _name_keys(n or ""):
                by_name.setdefault(k, st)
    return {"by_ip": by_ip, "by_name": by_name}


def lookup(idx: dict | None, ip: str | None, name: str | None = None) -> dict | None:
    if not idx:
        return None
    if ip and ip in idx["by_ip"]:
        return idx["by_ip"][ip]
    for k in _name_keys(name or ""):
        if k in idx["by_name"]:
            return idx["by_name"][k]
    return None


def annotate(idx: dict | None, hosts: Iterable[dict]) -> dict:
    """Setzt `zabbix` an jedem Host, den Zabbix kennt. Liefert Zähler."""
    out = {"monitored": 0, "problems": 0, "down": 0, "unmonitored": 0}
    if not idx:
        return out
    seen: set[int] = set()
    for h in hosts:
        if id(h) in seen:
            continue
        seen.add(id(h))
        st = lookup(idx, h.get("ip"), h.get("name"))
        if st is None:
            h.pop("zabbix", None)
            out["unmonitored"] += 1
            continue
        h["zabbix"] = st
        out["monitored"] += 1
        out["problems"] += st["state"] == "problem"
        out["down"] += st["state"] == "down"
    return out


def color(st: dict | None) -> str | None:
    if not st:
        return None
    return {"disabled": OFF_COLOR, "maintenance": MAINT_COLOR, "down": DOWN_COLOR,
            "ok": OK_COLOR}.get(st["state"]) or SEVERITY_COLOR.get(st["severity"] or 0)


def summary(st: dict | None) -> str:
    """Eine Zeile für Tooltips und Listen."""
    if not st:
        return ""
    if st["state"] == "disabled":
        return "in Zabbix deaktiviert"
    head = {"maintenance": "in Wartung", "down": "NICHT ERREICHBAR (Agent/SNMP)",
            "ok": "ok, keine aktiven Probleme"}.get(st["state"], "")
    if st["problems"]:
        n = len(st["problems"])
        head = (head + " · " if head and st["state"] != "ok" else "") + (
            f"{n} Problem{'e' if n > 1 else ''}, höchstes: {SEVERITY[st['severity']]}")
    return head


def tooltip(st: dict | None) -> str:
    if not st:
        return ""
    lines = [f"Zabbix ({st['name']}): {summary(st)}"]
    for p in st["problems"][:PROBLEMS_SHOWN]:
        lines.append(f"  • [{SEVERITY[p['severity']]}] {p['name']}"
                     + (" (quittiert)" if p["ack"] else ""))
    if len(st["problems"]) > PROBLEMS_SHOWN:
        lines.append(f"  … +{len(st['problems']) - PROBLEMS_SHOWN} weitere")
    return "\n".join(lines)
