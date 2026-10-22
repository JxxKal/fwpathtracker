"""Kapitel aus Graylog/Winlogbeat: Active Directory und iFIX.

Gezählt wird in Graylog (Trefferzahl, Pivot über die Views-API), nicht hier —
eine Woche Security-Log sind Millionen Zeilen. Rohnachrichten werden nur für
die Ereignisse geholt, die namentlich genannt werden.
"""
from __future__ import annotations

import logging
from collections import Counter
from datetime import datetime, timedelta, timezone

from graylog import winlog
from report import period
from report.chapters import TABLE_MAX, Ctx, _n, empty

log = logging.getLogger("report.winlog")

Q_AD = "Was ist im Active Directory passiert?"
Q_IFIX = "Was meldet iFIX?"
NAMED_MAX = 500


def _ts(m: dict) -> datetime | None:
    raw = m.get("timestamp")
    try:
        return datetime.fromisoformat(str(raw).replace("Z", "+00:00"))
    except ValueError:
        return None


def _ids_query(ids) -> str:
    return "(" + " OR ".join(str(i) for i in sorted(ids)) + ")"


async def _daily(client, cfg: dict, query: str, ctx: Ctx) -> list[int]:
    """Zählung je Kalendertag — ein Count je Tag, Grenzen in Ortszeit."""
    out = []
    for d in ctx.days:
        day = datetime.fromisoformat(d["date"]).replace(tzinfo=period.tz_of(ctx.cfg))
        a = max(day.astimezone(timezone.utc), ctx.frm)
        b = min((day + timedelta(days=1)).astimezone(timezone.utc), ctx.to)
        out.append(await client.count(cfg, query, a, b) if a < b else 0)
    return out


async def _setup(state, read_config, role: str):
    cfg = await read_config("graylog")
    if not cfg.get("base_url"):
        return None, None, "Graylog ist nicht eingerichtet."
    client = state.graylog
    try:
        detected = await winlog.detect_prefix(client, cfg, datetime.now(timezone.utc))
    except Exception as exc:
        return None, None, f"Graylog nicht abrufbar: {exc}"
    return cfg, winlog.prefix_of(cfg, detected), None


# ── 7. Active Directory ──────────────────────────────────────────────────────

def ad_rows(msgs: list[dict], p: str, ctx: Ctx, privileged: set[str]) -> tuple[list, list]:
    """Namentliche Zeilen und Hinweise aus Rohnachrichten."""
    f = winlog.field
    rows, attention = [], []
    for m in msgs:
        try:
            eid = int(m.get(f("winlog.event_id", p)) or 0)
        except ValueError:
            continue
        label, mode = winlog.AD_EVENTS.get(eid, (str(eid), "count"))
        if mode == "count":
            continue
        ts = _ts(m)
        target = m.get(f("winlog.event_data.TargetUserName", p)) or ""
        member = (m.get(f("winlog.event_data.MemberName", p)) or "")
        member = member.split(",", 1)[0].removeprefix("CN=") if member else ""
        by = m.get(f("winlog.event_data.SubjectUserName", p)) or ""
        dc = m.get(winlog.host_field({}, p)) or m.get("source") or ""
        rows.append([ctx.local(ts), label, member or target,
                     target if eid in winlog.GROUP_MEMBER_EVENTS else "", by, dc])
        priv = eid in winlog.GROUP_MEMBER_EVENTS and target.lower() in privileged
        if mode == "alert" or priv:
            attention.append({
                "title": (f"Privilegierte Gruppe {target}: {label}" if priv
                          else f"AD: {label}"),
                "why": f"{ctx.local(ts)} · {member or target} · durch {by or '?'} auf {dc}",
                "source": "Active Directory", "level": "high"})
    return rows, attention


async def ad(state, ctx: Ctx, read_config) -> dict:
    cfg, p, err = await _setup(state, read_config, "ad")
    if err:
        return empty("ad", Q_AD, "Graylog (Winlogbeat)", "off" if "eingerichtet" in err
                     else "error", err)
    base = winlog.role_query(cfg, "ad", p)
    if not winlog.role_hosts(cfg, "ad"):
        note = "Keine Domain Controller eingetragen — gezählt wird das Security-Log aller Rechner."
    else:
        note = None
    eid = winlog.field("winlog.event_id", p)
    client = state.graylog
    try:
        by_id = dict(await client.aggregate(
            cfg, f"({base}) AND {eid}:{_ids_query(winlog.AD_EVENTS)}", ctx.frm, ctx.to, eid, 100))
        changes = {i for i, (_, mode) in winlog.AD_EVENTS.items() if mode != "count"}
        named_q = f"({base}) AND {eid}:{_ids_query(changes)}"
        daily = await _daily(client, cfg, named_q, ctx)
        msgs = await client.sample(cfg, named_q, ctx.frm, ctx.to, NAMED_MAX)
        tops = {}
        for i, title in ((4740, "Am häufigsten gesperrte Konten"),
                         (4625, "Konten mit den meisten Fehlanmeldungen")):
            if int(by_id.get(str(i), 0)):
                tops[title] = await client.aggregate(
                    cfg, f"({base}) AND {eid}:{i}", ctx.frm, ctx.to,
                    winlog.field("winlog.event_data.TargetUserName", p), 10)
    except Exception as exc:
        return empty("ad", Q_AD, "Graylog (Winlogbeat)", "error", f"Graylog-Abfrage fehlgeschlagen: {exc}")
    counts = {int(k): int(v) for k, v in by_id.items() if str(k).isdigit()}
    privileged = {g.lower() for g in (ctx.cfg.get("privileged_groups") or winlog.PRIVILEGED_GROUPS)}
    rows, attention = ad_rows(msgs, p, ctx, privileged)
    total_changes = sum(n for i, n in counts.items() if winlog.AD_EVENTS[i][1] != "count")
    member = sum(counts.get(i, 0) for i in winlog.GROUP_MEMBER_EVENTS)
    created = counts.get(4720, 0)
    deleted = counts.get(4726, 0)
    alerts = sum(n for i, n in counts.items() if winlog.AD_EVENTS[i][1] == "alert")
    answer = (f"{_n(total_changes, 'Änderung', 'Änderungen')} an Konten und Gruppen: "
              f"{created} Konten angelegt, {deleted} gelöscht, {member} Gruppenmitgliedschaften "
              f"geändert; {counts.get(4740, 0)} Sperrungen, {counts.get(4625, 0)} Fehlanmeldungen"
              + (f". {alerts} sicherheitskritische Ereignisse." if alerts else "."))
    status = "partial" if note or len(msgs) >= NAMED_MAX else "ok"
    if len(msgs) >= NAMED_MAX:
        note = (note + " " if note else "") + f"Nur die jüngsten {NAMED_MAX} Änderungen namentlich."
    order = sorted(counts, key=lambda i: ({"alert": 0, "named": 1, "count": 2}[
        winlog.AD_EVENTS[i][1]], -counts[i]))
    return {
        "id": "ad", "question": Q_AD, "source": "Graylog (Winlogbeat, Domain Controller)",
        "status": status, "note": note, "answer": answer,
        "kpis": [{"key": "ad_changes", "label": "AD-Änderungen", "value": total_changes},
                 {"key": "ad_lockouts", "label": "Kontosperrungen", "value": counts.get(4740, 0)},
                 {"key": "ad_failed", "label": "Fehlanmeldungen", "value": counts.get(4625, 0)}],
        "daily": daily,
        "charts": [c for c in (
            {"type": "daily", "title": "Änderungen an Konten und Gruppen je Tag",
             "series": [{"label": "Änderungen", "color": "#7A5CC4", "values": daily}]}
            if any(daily) else None,
            *({"type": "top", "title": t, "items": [{"label": k, "value": v} for k, v in items]}
              for t, items in tops.items() if items),
        ) if c],
        "tables": [t for t in (
            {"title": "Ereignisse nach Art", "columns": ["EventID", "Bedeutung", "Anzahl"],
             "total": None, "rows": [[str(i), winlog.AD_EVENTS[i][0], counts[i]] for i in order]}
            if counts else None,
            {"title": "Änderungen an Konten und Gruppen",
             "columns": ["Zeit", "Ereignis", "Konto / Mitglied", "Gruppe", "durch", "DC"],
             "total": total_changes, "rows": rows[:TABLE_MAX]} if rows else None,
        ) if t],
        "attention": attention[:30],
    }


# ── 8. iFIX ──────────────────────────────────────────────────────────────────

async def ifix(state, ctx: Ctx, read_config) -> dict:
    cfg, p, err = await _setup(state, read_config, "ifix")
    if err:
        return empty("ifix", Q_IFIX, "Graylog (Winlogbeat)", "off" if "eingerichtet" in err
                     else "error", err)
    client = state.graylog
    q = winlog.role_query(cfg, "ifix", p)
    nodes_q = winlog.hosts_query(cfg, "ifix", p)
    hf = winlog.host_field(cfg, p)
    eid = winlog.field("winlog.event_id", p)
    try:
        total = await client.count(cfg, q, ctx.frm, ctx.to)
        daily = await _daily(client, cfg, q, ctx)
        per_node = await client.aggregate(cfg, q, ctx.frm, ctx.to, hf, 20)
        per_kw = []
        for kw in winlog.IFIX_KEYWORDS:
            n = await client.count(cfg, f'({q}) AND message:"*{kw}*"', ctx.frm, ctx.to)
            if n:
                per_kw.append({"label": kw, "value": n})
        latest = await client.sample(cfg, q, ctx.frm, ctx.to, 100)
        node_counts, node_msgs = {}, []
        if nodes_q:
            ids = _ids_query(winlog.NODE_EVENTS)
            node_counts = {int(k): int(v) for k, v in await client.aggregate(
                cfg, f"({nodes_q}) AND {eid}:{ids}", ctx.frm, ctx.to, eid, 20) if str(k).isdigit()}
            named = [i for i, (_, m) in winlog.NODE_EVENTS.items() if m != "count"]
            if any(node_counts.get(i) for i in named):
                node_msgs = await client.sample(
                    cfg, f"({nodes_q}) AND {eid}:{_ids_query(named)}", ctx.frm, ctx.to, 200)
    except Exception as exc:
        return empty("ifix", Q_IFIX, "Graylog (Winlogbeat)", "error",
                     f"Graylog-Abfrage fehlgeschlagen: {exc}")
    note = None if nodes_q else ("Keine iFIX-Rechner eingetragen — gezählt werden die "
                                 "iFIX-Meldungen aller Rechner, der Knotenzustand fehlt.")
    reboots = node_counts.get(6008, 0) + node_counts.get(41, 0)
    crashes = sum(node_counts.get(i, 0) for i in (7031, 7034, 1000, 1002))
    answer = (f"{_n(total, 'iFIX-Meldung', 'iFIX-Meldungen')} auf "
              f"{_n(len(per_node), 'Knoten', 'Knoten')}"
              + (f"; {_n(reboots, 'unerwarteter Neustart', 'unerwartete Neustarts')} und "
                 f"{_n(crashes, 'Dienst- oder Anwendungsabsturz', 'Dienst- oder Anwendungsabstürze')}."
                 if nodes_q else "."))

    def msg_row(m):
        return [ctx.local(_ts(m)), str(m.get(hf) or m.get("source") or ""),
                str(m.get(winlog.field("event.code", p)) or m.get(eid) or ""),
                str(m.get("message") or "")[:240]]

    node_rows, attention = [], []
    for m in node_msgs:
        try:
            i = int(m.get(eid) or 0)
        except ValueError:
            continue
        label, mode = winlog.NODE_EVENTS.get(i, (str(i), "count"))
        node = str(m.get(hf) or m.get("source") or "?")
        node_rows.append([ctx.local(_ts(m)), node, label, str(m.get("message") or "")[:240]])
        if mode == "alert":
            attention.append({"title": f"iFIX-Knoten {node}: {label}",
                              "why": ctx.local(_ts(m)), "source": "iFIX", "level": "high"})
    return {
        "id": "ifix", "question": Q_IFIX, "source": "Graylog (Winlogbeat, iFIX-Knoten)",
        "status": "partial" if note else "ok", "note": note, "answer": answer,
        "kpis": [{"key": "ifix_msgs", "label": "iFIX-Meldungen", "value": total},
                 {"key": "ifix_reboots", "label": "Unerwartete Neustarts (iFIX)",
                  "value": reboots}],
        "daily": daily,
        "charts": [c for c in (
            {"type": "daily", "title": "iFIX-Meldungen je Tag",
             "series": [{"label": "Meldungen", "color": "#d4762c", "values": daily}]}
            if any(daily) else None,
            {"type": "top", "title": "Nach Knoten",
             "items": [{"label": k, "value": v} for k, v in per_node[:10]]} if per_node else None,
            {"type": "top", "title": "Nach Stichwort", "items": sorted(
                per_kw, key=lambda x: -x["value"])} if per_kw else None,
        ) if c],
        "tables": [t for t in (
            {"title": "Zustand der Knoten (Windows-Ereignisse)",
             "columns": ["EventID", "Bedeutung", "Anzahl"], "total": None,
             "rows": [[str(i), winlog.NODE_EVENTS[i][0], n] for i, n in sorted(
                 node_counts.items(), key=lambda kv: -kv[1])]} if node_counts else None,
            {"title": "Neustarts und Abstürze", "columns": ["Zeit", "Knoten", "Ereignis",
                                                            "Meldung"],
             "total": len(node_rows), "rows": node_rows[:TABLE_MAX]} if node_rows else None,
            {"title": "Jüngste iFIX-Meldungen", "columns": ["Zeit", "Knoten", "Code", "Meldung"],
             "total": total, "rows": [msg_row(m) for m in latest]} if latest else None,
        ) if t],
        "attention": attention[:15],
    }
