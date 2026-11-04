"""Kapitel „Was hat sich auf den Windows-Rechnern geändert?" — Vergleich der
Stände aus dem Windows-Inventar (win_inventory_history) im Zeitraum."""
from __future__ import annotations

import re
from collections import Counter
from datetime import datetime, timedelta

from report.chapters import TABLE_MAX, Ctx, _n, _top, empty
from wininv import parse

Q_WINDOWS = "Was hat sich auf den Windows-Rechnern geändert?"
SOURCE = "Windows-Inventar"

ADMIN_GROUPS = {"administratoren", "administrators"}
RDP_GROUPS = {"remotedesktopbenutzer", "remote desktop users"}
# Ports, deren neues Lauschen eine Zeile wert ist.
WATCH_PORTS = {21: "FTP", 22: "SSH", 23: "Telnet", 80: "HTTP", 102: "S7", 135: "RPC",
               443: "HTTPS", 445: "SMB", 502: "Modbus", 1433: "MSSQL", 3389: "RDP",
               4840: "OPC UA", 5900: "VNC", 5985: "WinRM", 5986: "WinRM/TLS"}
# Eingebaute Konten — ein Dienst unter ihnen ist kein Domänenkonto.
BUILTIN_RE = re.compile(r"(?i)^(localsystem|system|nt[ -]?(authority|autorität|service)\\.*|"
                        r"(lokaler dienst|netzwerkdienst|local ?service|network ?service)|"
                        r"vordefiniert\\.*|builtin\\.*|users|benutzer|interaktiv|interactive|"
                        r"administratoren|administrators|-|)$")
EVERYONE_WRITE = re.compile(r"(?i)(everyone|jeder|authenticated users|authentifizierte benutzer)"
                            r":allow\((full|change)")


def _key(kind: str, row: dict) -> tuple:
    return {
        "groups": lambda r: (r.get("GroupName"), r.get("MemberName")),
        "tasks": lambda r: (r.get("TaskPath"), r.get("TaskName")),
    }.get(kind, lambda r: (r.get(parse.KEY_COLUMN.get(kind, "Name")),))(row)


# Was eine Zeile „geändert" macht — Laufzustand (State) zählt nicht, er
# wechselt täglich.
COMPARE = {"services": ("StartName", "PathName", "StartMode"),
           "tasks": ("Run_As_User", "Action"), "shares": ("Path", "Permissions"),
           "software": ("DisplayVersion",), "secpol": ("Accounts",),
           "users": ("Disabled",), "certificates": ("ValidUntil",)}


def diff(kind: str, old: list[dict], new: list[dict]) -> list[tuple[str, dict, dict | None]]:
    """(added | removed | changed, neue Zeile bzw. alte bei removed, alte Zeile)."""
    a = {_key(kind, r): r for r in old}
    b = {_key(kind, r): r for r in new}
    out = [("added", r, None) for k, r in b.items() if k not in a]
    out += [("removed", r, None) for k, r in a.items() if k not in b]
    fields = COMPARE.get(kind, ())
    for k, r in b.items():
        if k in a and any((a[k].get(f) or "") != (r.get(f) or "") for f in fields):
            out.append(("changed", r, a[k]))
    return out


def _domain_account(name: str | None) -> bool:
    n = (name or "").strip()
    return bool(n) and not BUILTIN_RE.match(n) and ("\\" in n or "@" in n or "." in n)


def _system_kind(rows: list[dict]) -> dict:
    s = parse.system(rows)
    return {"os": s["os"], "ips": ", ".join(s["ips"])}


def events(win: dict, frm: datetime) -> tuple[list[dict], list[dict]]:
    """Alle Änderungen im Zeitraum, dazu die Hosts, die im Zeitraum zum ersten
    Mal im Inventar auftauchen."""
    base = {(r["hostname"], r["kind"]): r["rows"] for r in win["base"]}
    history_start = win["history_start"]
    out, new_hosts = [], []
    prev = dict(base)
    for r in win["inside"]:
        key = (r["hostname"], r["kind"])
        old = prev.get(key)
        prev[key] = r["rows"]
        if old is None:
            # Ohne Vorgänger: neuer Host — außer der Verlauf beginnt erst hier.
            if r["kind"] == "system" and history_start and history_start < frm:
                new_hosts.append({"ts": r["valid_from"], "host": r["hostname"],
                                  **_system_kind(r["rows"])})
            continue
        if r["kind"] == "system":
            a, b = _system_kind(old), _system_kind(r["rows"])
            for f, label in (("os", "Betriebssystem"), ("ips", "IP-Adressen")):
                if a[f] != b[f]:
                    out.append({"ts": r["valid_from"], "host": r["hostname"], "kind": "system",
                                "action": "changed", "item": label,
                                "detail": f"{a[f] or '—'} → {b[f] or '—'}", "row": {}, "old": {}})
            continue
        for action, row, before in diff(r["kind"], old, r["rows"]):
            out.append({"ts": r["valid_from"], "host": r["hostname"], "kind": r["kind"],
                        "action": action, "row": row, "old": before or {}})
    return out, new_hosts


ACTION = {"added": "neu", "removed": "entfernt", "changed": "geändert"}


def _item(e: dict) -> str:
    r, k = e["row"], e["kind"]
    if e.get("item"):
        return e["item"]
    if k == "groups":
        return f"{r.get('GroupName')}: {r.get('MemberName')}"
    if k == "tasks":
        return f"{(r.get('TaskPath') or '').rstrip(chr(92))}\\{r.get('TaskName')}".lstrip("\\")
    if k == "ports":
        p = int(r.get("Port") or 0)
        return f"TCP/{p}" + (f" ({WATCH_PORTS[p]})" if p in WATCH_PORTS else "")
    if k == "services":
        return f"{r.get('DisplayName') or r.get('Name')}"
    return str(r.get(parse.KEY_COLUMN.get(k, "Name")) or "?")


def _detail(e: dict) -> str:
    r, o, k = e["row"], e["old"], e["kind"]
    if e.get("detail"):
        return e["detail"]
    if e["action"] == "changed":
        parts = [f"{f}: {o.get(f) or '—'} → {r.get(f) or '—'}" for f in COMPARE.get(k, ())
                 if (o.get(f) or "") != (r.get(f) or "")]
        return "; ".join(parts)
    if k == "services":
        return f"Konto {r.get('StartName') or '—'} · {r.get('StartMode') or ''} · {r.get('PathName') or ''}"
    if k == "tasks":
        return f"als {r.get('Run_As_User') or '—'} · {r.get('Action') or ''}"
    if k == "shares":
        return f"{r.get('Path') or ''} · {r.get('Permissions') or ''}"
    if k == "software":
        return " ".join(p for p in (r.get("DisplayVersion"), r.get("Publisher")) if p)
    if k == "secpol":
        return r.get("Accounts") or ""
    if k == "users":
        return "deaktiviert" if r.get("Disabled") == "True" else "aktiv"
    if k == "certificates":
        return f"gültig bis {r.get('ValidUntil') or '?'} · {r.get('Issuer') or ''}"
    return ""


def _attention(e: dict) -> tuple[str, str] | None:
    """(Stufe, Titel) für die Liste „Was sollte sich jemand ansehen?" — oder None."""
    r, k, act = e["row"], e["kind"], e["action"]
    host = e["host"]
    if k == "groups" and act == "added" and r.get("MemberName"):
        g = (r.get("GroupName") or "").lower()
        if g in ADMIN_GROUPS:
            return "high", f"Neuer lokaler Admin auf {host}: {r['MemberName']}"
        if g in RDP_GROUPS:
            return "medium", f"Neu in Remotedesktopbenutzer auf {host}: {r['MemberName']}"
    if k == "users" and r.get("Disabled") == "False" and (
            act == "added" or (act == "changed" and e["old"].get("Disabled") == "True")):
        return "medium", f"Lokales Konto {'neu' if act == 'added' else 'wieder aktiviert'} auf {host}: {r.get('Name')}"
    if k == "secpol" and act in ("changed", "removed") and (r.get("Right") or "").startswith("SeDeny"):
        return "high", f"Anmeldesperre geändert auf {host}: {r.get('Right')}"
    if k == "shares" and act in ("added", "changed") and not (r.get("Name") or "").endswith("$"):
        if EVERYONE_WRITE.search(r.get("Permissions") or ""):
            return "high", f"Freigabe mit Schreibrecht für alle auf {host}: {r.get('Name')}"
        if act == "added":
            return "medium", f"Neue Freigabe auf {host}: {r.get('Name')}"
    if k in ("services", "tasks") and act in ("added", "changed"):
        acct = r.get("StartName") if k == "services" else r.get("Run_As_User")
        if _domain_account(acct):
            what = "Dienst" if k == "services" else "Geplante Aufgabe"
            return "medium", f"{what} mit Domänenkonto auf {host}: {_item(e)} als {acct}"
    if k == "ports" and act == "added" and int(r.get("Port") or 0) in WATCH_PORTS:
        return "medium", f"{host} lauscht neu auf {_item(e)}"
    return None


TABLES = [("groups", "Lokale Gruppen"), ("users", "Lokale Benutzer"),
          ("secpol", "Anmelderechte"), ("services", "Dienste"), ("tasks", "Geplante Aufgaben"),
          ("ports", "Lauschende Ports"), ("shares", "Freigaben"),
          ("certificates", "Zertifikate"), ("system", "System"), ("features", "Rollen & Features"),
          ("software", "Software")]


def windows_chapter(win: dict, ctx: Ctx, *, stale_days: int, now: datetime) -> dict:
    evs, new_hosts = events(win, ctx.frm)
    start = win["history_start"]
    status, note = "ok", None
    if start is None:
        return empty("windows", Q_WINDOWS, SOURCE, "partial",
                     "Das Windows-Inventar hat noch keinen Stand eingelesen.")
    if start >= ctx.frm:
        status = "partial"
        note = (f"Der Verlauf des Windows-Inventars beginnt erst am {ctx.local(start)} — "
                "Änderungen davor kennt A38 nicht.")
    limit = min(ctx.to, now) - timedelta(days=stale_days)
    stale = sorted(((h, t) for h, t in win["newest"].items() if t < limit), key=lambda x: x[1])

    attention, flagged = [], 0
    for e in evs:
        a = _attention(e)
        if a:
            flagged += 1
            if len(attention) < 40:
                attention.append({"title": a[1], "why": f"{ctx.local(e['ts'])} · {_detail(e)}"[:300],
                                  "source": SOURCE, "level": a[0]})
    admins = [e for e in evs if e["kind"] == "groups" and e["action"] == "added"
              and (e["row"].get("GroupName") or "").lower() in ADMIN_GROUPS
              and e["row"].get("MemberName")]
    software = [e for e in evs if e["kind"] == "software"]
    config = [e for e in evs if e["kind"] != "software"]
    hosts_changed = Counter(e["host"] for e in config)
    by_kind = Counter(parse.KIND_LABEL.get(e["kind"], e["kind"]) for e in config)

    answer = (f"{_n(len(config), 'Änderung', 'Änderungen')} an Konten, Diensten, Aufgaben, "
              f"Ports und Freigaben auf {_n(len(hosts_changed), 'Rechner', 'Rechnern')}, "
              f"{_n(len(software), 'Software-Änderung', 'Software-Änderungen')}"
              + (f"; {_n(len(admins), 'neuer lokaler Admin', 'neue lokale Admins')}" if admins else "")
              + (f"; {_n(len(stale), 'Rechner liefert', 'Rechner liefern')} seit über "
                 f"{stale_days} Tagen keine Daten" if stale else "") + ".")
    if new_hosts:
        answer += f" Neu im Inventar: {_n(len(new_hosts), 'Rechner', 'Rechner')}."

    def rows_of(kind: str) -> list[list[str]]:
        sel = [e for e in evs if e["kind"] == kind]
        return [[ctx.local(e["ts"]), e["host"], ACTION[e["action"]], _item(e), _detail(e)[:300]]
                for e in sel[-TABLE_MAX:]]

    cols = ["Stand", "Rechner", "", "Was", "Details"]
    tables = []
    for kind, title in TABLES:
        n = sum(1 for e in evs if e["kind"] == kind)
        if n:
            tables.append({"title": title, "columns": cols, "rows": rows_of(kind), "total": n})
    if new_hosts:
        tables.append({"title": "Neu im Inventar", "columns": ["Erstmals", "Rechner", "OS", "IPs"],
                       "total": len(new_hosts),
                       "rows": [[ctx.local(h["ts"]), h["host"], h["os"] or "", h["ips"]]
                                for h in new_hosts[:TABLE_MAX]]})
    if stale:
        tables.append({"title": f"Liefern seit über {stale_days} Tagen keine Daten",
                       "columns": ["Letzte Datei", "Rechner"], "total": len(stale),
                       "rows": [[ctx.local(t), h] for h, t in stale[:TABLE_MAX]]})
    for h, t in stale[:10]:
        attention.append({"title": f"Windows-Inventar: {h} liefert keine Daten mehr",
                          "why": f"letzte Datei {ctx.local(t)} — läuft der geplante Task noch?",
                          "source": SOURCE, "level": "medium"})
    daily = ctx.daily(e["ts"] for e in config)
    return {
        "id": "windows", "question": Q_WINDOWS, "source": SOURCE, "status": status,
        "note": note, "answer": answer,
        "hints": ["Die Daten meldet jeder Rechner selbst (Collector-Skript, nachts) — eine "
                  "Änderung erscheint mit dem Stand der Datei, nicht zum genauen Zeitpunkt."],
        "kpis": [{"key": "win_changes", "label": "Windows-Änderungen", "value": len(config)},
                 {"key": "win_admins", "label": "Neue lokale Admins", "value": len(admins)},
                 {"key": "win_software", "label": "Software-Änderungen", "value": len(software)},
                 {"key": "win_stale", "label": "Rechner ohne neue Daten", "value": len(stale)}],
        "daily": daily,
        "charts": [c for c in (
            {"type": "daily", "title": "Änderungen je Tag (ohne Software)",
             "series": [{"label": "Änderungen", "color": "#0078d4", "values": daily}]}
            if config else None,
            {"type": "top", "title": "Nach Art", "items": _top(by_kind)} if config else None,
            {"type": "top", "title": "Rechner mit den meisten Änderungen",
             "items": _top(hosts_changed)} if config else None,
        ) if c],
        "tables": tables,
        "attention": attention,
        "_flagged": flagged,
    }


async def windows(state, ctx: Ctx, read_config) -> dict:
    cfg = await read_config("wininv")
    if not cfg.get("path"):
        return empty("windows", Q_WINDOWS, SOURCE, "off", "Das Windows-Inventar ist nicht eingerichtet.")
    try:
        win = await state.wininv_store.window(ctx.frm, ctx.to)
    except Exception as exc:
        return empty("windows", Q_WINDOWS, SOURCE, "error", f"Windows-Inventar nicht lesbar: {exc}")
    from datetime import timezone
    return windows_chapter(win, ctx, stale_days=int(cfg.get("stale_days") or 3),
                           now=datetime.now(timezone.utc))
