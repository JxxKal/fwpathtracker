"""Winlogbeat-Nachrichten in Graylog: Feldschreibweise und Rollen (AD, iFIX).

AD und iFIX kommen beide über Winlogbeat — ein Schema, getrennt wird über
Filter: AD am Security-Kanal der Domain Controller, iFIX am Absender bzw. den
SCADA-Knoten. Alles liegt im Stream „All messages“.

Der Beats-Input in Graylog stellt den Feldern je nach Einstellung den
Beat-Typ voran: `winlogbeat_winlog_event_id` statt `winlog_event_id`. Die
Filter in der Config schreiben deshalb `{p}` für das Präfix; welches gilt,
erkennt der Verbindungstest an den Nachrichten selbst.
"""
from __future__ import annotations

from datetime import datetime, timedelta

PREFIXES = ("winlogbeat_", "")
ROLES = {
    "ad": {"label": "Active Directory", "filter": "{p}winlog_channel:Security"},
    # iFIX erkennt man am Rechner, der über Winlogbeat sendet.
    "ifix": {"label": "iFIX (SCADA)", "filter": ""},
}
TEST_WINDOW = timedelta(hours=24)
SAMPLE = 200
HOSTS_SHOWN = 100


def prefix_of(cfg: dict, detected: str | None) -> str:
    """`field_prefix` in der Config: auto (Default), winlogbeat_ oder leer."""
    fixed = cfg.get("field_prefix")
    if fixed in PREFIXES:
        return fixed
    return detected if detected is not None else PREFIXES[0]


def field(name: str, prefix: str) -> str:
    """`winlog.event_id` → `winlogbeat_winlog_event_id` bzw. `winlog_event_id`."""
    return prefix + name.replace(".", "_")


def role_hosts(cfg: dict, role: str) -> list[str]:
    """Rechner einer Rolle (Domain Controller, iFIX-Knoten) — Graylog setzt
    `source` auf den Winlogbeat-Hostnamen."""
    hosts = ((cfg.get("roles") or {}).get(role) or {}).get("hosts") or []
    return list(dict.fromkeys(str(h).strip() for h in hosts if str(h).strip()))


def role_query(cfg: dict, role: str, prefix: str) -> str:
    """Filter der Rolle UND ihre Rechner. Ohne Rechner gilt der Filter allein —
    für AD heißt das: Security-Log aller Rechner, nicht nur der DCs."""
    raw = ((cfg.get("roles") or {}).get(role) or {}).get("filter")
    if raw is None:
        raw = ROLES[role]["filter"]
    parts = []
    if raw.strip():
        parts.append(raw.replace("{p}", prefix).strip())
    hosts = role_hosts(cfg, role)
    if hosts:
        parts.append("source:(" + " OR ".join(f'"{h}"' for h in hosts) + ")")
    if len(parts) == 2:
        return f"({parts[0]}) AND {parts[1]}"
    return parts[0] if parts else ""


async def detect_prefix(client, cfg: dict, now: datetime) -> str | None:
    """Welche Schreibweise liefern die Nachrichten? None = kein Winlogbeat gesehen."""
    for p in PREFIXES:
        if await client.count(cfg, f"_exists_:{field('winlog.event_id', p)}",
                              now - TEST_WINDOW, now):
            return p
    return None


async def diagnose(client, cfg: dict, now: datetime) -> dict:
    """Verbindungstest: Streams, Feldschreibweise, Treffer je Rolle, Vorschläge
    für den iFIX-Filter und ob die Views-API (Aggregation) erlaubt ist."""
    out: dict = {"version": (await client.test(cfg))["version"], "streams": [],
                 "streams_error": None, "prefix": None, "winlogbeat": False, "roles": {},
                 "hosts": [], "providers": [], "aggregation": {"ok": False, "error": None}}
    try:
        out["streams"] = await client.streams(cfg)
    except Exception as exc:
        out["streams_error"] = str(exc)
    detected = await detect_prefix(client, cfg, now)
    out["winlogbeat"] = detected is not None
    p = prefix_of(cfg, detected)
    out["prefix"] = p
    frm = now - TEST_WINDOW
    for role, meta in ROLES.items():
        q = role_query(cfg, role, p)
        r = {"label": meta["label"], "query": q, "hits": None, "error": None,
             "computers": []}
        if not q:
            r["error"] = "Weder Rechner noch Filter eingetragen."
        else:
            try:
                r["hits"] = await client.count(cfg, q, frm, now)
                msgs = await client.sample(cfg, q, frm, now, SAMPLE)
                names: dict[str, int] = {}
                for m in msgs:
                    c = m.get(field("winlog.computer_name", p)) or m.get("source")
                    if c:
                        names[str(c)] = names.get(str(c), 0) + 1
                r["computers"] = sorted(names, key=lambda n: -names[n])[:10]
            except Exception as exc:
                r["error"] = str(exc)
        out["roles"][role] = r
    # Vorschläge für iFIX: alle Rechner, die über Winlogbeat senden (Graylog
    # setzt `source` auf den Winlogbeat-Hostnamen), dazu die Absender im
    # Application-Kanal.
    beats = f"_exists_:{field('winlog.event_id', p)}"
    try:
        out["hosts"] = [{"name": n, "hits": c} for n, c in await client.aggregate(
            cfg, beats, frm, now, "source", HOSTS_SHOWN)]
    except Exception:
        try:
            seen_h: dict[str, int] = {}
            for m in await client.sample(cfg, beats, frm, now, SAMPLE):
                if m.get("source"):
                    seen_h[str(m["source"])] = seen_h.get(str(m["source"]), 0) + 1
            out["hosts"] = [{"name": n, "hits": c, "sampled": True}
                            for n, c in sorted(seen_h.items(), key=lambda kv: -kv[1])]
        except Exception:
            pass
    app = f"{field('winlog.channel', p)}:Application"
    try:
        out["providers"] = [{"name": n, "hits": c} for n, c in await client.aggregate(
            cfg, app, frm, now, field("winlog.provider_name", p), 25)]
        out["aggregation"]["ok"] = True
    except Exception as exc:
        out["aggregation"]["error"] = str(exc)
        # Ohne Aggregation: Stichprobe zählen — ungenau, aber ein Anfang.
        try:
            seen: dict[str, int] = {}
            for m in await client.sample(cfg, app, frm, now, SAMPLE):
                n = m.get(field("winlog.provider_name", p))
                if n:
                    seen[str(n)] = seen.get(str(n), 0) + 1
            out["providers"] = [{"name": n, "hits": c, "sampled": True}
                                for n, c in sorted(seen.items(), key=lambda kv: -kv[1])[:25]]
        except Exception:
            pass
    return out
