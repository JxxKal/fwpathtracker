"""Einen Wochenbericht erzeugen: Kapitel parallel sammeln, querprüfen, ablegen.

Jedes Kapitel hat ein eigenes Zeitlimit. Hängt eine Quelle, fehlt ihr Kapitel
mit Vermerk; der Bericht entsteht trotzdem.
"""
from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timedelta

from report import chapters as ch, period, winlog_chapters as wch

log = logging.getLogger("report.build")

TITLE = "Stephan fragt, A38 antwortet"
VERSION = 1
CHAPTER_TIMEOUT_S = 240
# Kacheln der Titelseite, in dieser Reihenfolge (Schlüssel aus den Kapiteln).
TILES = ["fw_changes", "fw_off_hours", "zbx_problems", "zbx_high", "hosts_new",
         "hosts_unmanaged", "ad_changes", "ad_lockouts", "ifix_msgs", "ifix_reboots",
         "lnms_port_down", "wd_errors"]
# Kurze Zeilennamen für die Heatmap Tag × Quelle.
HEAT_LABEL = {"firewall": "Firewall-Änderungen", "hosts": "Neue Hosts", "zabbix": "Zabbix",
              "librenms": "LibreNMS", "ad": "Active Directory", "ifix": "iFIX",
              "webdrive": "Webdrive"}
NEAR = timedelta(minutes=60)


async def _zabbix_index(state, read_config):
    """Nur die IPs, die Zabbix überwacht — für „neu, aber nicht überwacht"."""
    cfg = await read_config("zabbix")
    if not cfg.get("base_url"):
        return None
    try:
        hosts = await state.zabbix.hosts(cfg)
    except Exception as exc:
        log.warning("Report: Zabbix-Hosts nicht abrufbar: %s", exc)
        return None
    return {"by_ip": {i["ip"]: True for h in hosts for i in h.get("interfaces") or []
                      if i.get("ip")}}


async def _guarded(coro, cid: str, question: str, source: str) -> dict:
    try:
        return await asyncio.wait_for(coro, CHAPTER_TIMEOUT_S)
    except asyncio.TimeoutError:
        return ch.empty(cid, question, source, "error",
                        f"Zeitüberschreitung nach {CHAPTER_TIMEOUT_S} s.")
    except Exception as exc:              # ein Kapitel darf den Bericht nie kosten
        log.exception("Report-Kapitel %s fehlgeschlagen", cid)
        return ch.empty(cid, question, source, "error", f"Fehler: {exc}")


def cross_checks(chapters: dict[str, dict], ctx: ch.Ctx) -> list[dict]:
    """Was erst aus dem Abgleich zweier Quellen sichtbar wird."""
    out = []
    changes = [(datetime.fromisoformat(c["ts"]), c["device"])
               for c in chapters.get("firewall", {}).get("_changes", [])]
    for p in chapters.get("zabbix", {}).get("_high", []):
        ts = datetime.fromisoformat(p["ts"])
        near = [d for t, d in changes if timedelta(0) <= ts - t <= NEAR]
        if near:
            out.append({
                "title": f"Zabbix-Problem kurz nach Firewall-Änderung: {p['host']}",
                "why": f"{p['name']} um {ctx.local(ts)}; davor geändert: "
                       f"{', '.join(sorted(set(d or '?' for d in near)))}. Zeitliche Nähe — "
                       "ein Hinweis, kein Beweis.",
                "source": "Zabbix × FortiAnalyzer", "level": "medium"})
    return out[:15]


def summarize(chapters: list[dict], prev: dict | None) -> dict:
    kpis = {k["key"]: k for c in chapters for k in c.get("kpis") or []}
    prev_kpis = {k["key"]: k.get("value") for k in ((prev or {}).get("summary") or {}).get(
        "kpis", [])}
    tiles = []
    for key in TILES:
        if key in kpis:
            tiles.append({**kpis[key], "prev": prev_kpis.get(key)})
    statuses = [c["status"] for c in chapters]
    live = [s for s in statuses if s != "off"]
    if live and all(s == "error" for s in live):
        status = "failed"
    elif any(s in ("error", "partial") for s in live):
        status = "partial"
    else:
        status = "ok"
    return {"kpis": tiles, "status": status,
            "attention": sum(len(c.get("attention") or []) for c in chapters)}


async def build(state, read_config, start: datetime, end: datetime, cfg: dict,
                prev: dict | None = None) -> dict:
    ctx = ch.Ctx(start, end, cfg)
    zbx = await _zabbix_index(state, read_config)
    jobs = [
        (ch.firewall(state, ctx, read_config), "firewall", ch.Q_FIREWALL, "FortiAnalyzer"),
        (ch.hosts(state, ctx, read_config, zbx), "hosts", ch.Q_HOSTS, "ARP-Historie"),
        (ch.librenms(state, ctx, read_config), "librenms", ch.Q_LIBRENMS, "LibreNMS"),
        (ch.zabbix(state, ctx, read_config), "zabbix", ch.Q_ZABBIX, "Zabbix"),
        (wch.ad(state, ctx, read_config), "ad", wch.Q_AD, "Graylog"),
        (wch.ifix(state, ctx, read_config), "ifix", wch.Q_IFIX, "Graylog"),
        (ch.webdrive(state, ctx, read_config), "webdrive", ch.Q_WEBDRIVE, "Webdrive"),
    ]
    done = await asyncio.gather(*(_guarded(*j) for j in jobs))
    by_id = {c["id"]: c for c in done}
    attention = cross_checks(by_id, ctx)
    for c in done:
        attention += c.get("attention") or []
    attention.sort(key=lambda a: {"high": 0, "medium": 1}.get(a.get("level"), 2))
    chapters = [ch.strip_private(c) for c in done]
    summary = summarize(chapters, prev)
    summary["attention"] = len(attention)
    return {
        "version": VERSION, "title": TITLE,
        "period": {"start": start.isoformat(), "end": end.isoformat(),
                   **period.label(start, end, cfg)},
        "days": ctx.days,
        "sources": [{"id": c["id"], "question": c["question"], "source": c["source"],
                     "status": c["status"], "note": c.get("note")} for c in chapters],
        "summary": summary,
        "heatmap": [{"id": c["id"], "label": HEAT_LABEL.get(c["id"], c["id"]),
                     "values": c["daily"]} for c in chapters if c.get("daily")],
        "attention": attention[:60],
        "chapters": chapters,
    }


async def run(state, read_config, start: datetime, end: datetime, *, trigger: str,
              user: str | None = None) -> dict:
    """Bericht erzeugen und speichern. Liefert {id, status}."""
    cfg = await read_config("report")
    store = state.report_store
    prev = await store.previous(start)
    data = await build(state, read_config, start, end, cfg, prev)
    status = data["summary"]["status"]
    rid = await store.save(start, end, trigger, status, data, user)
    log.info("Wochenreport %s (%s – %s): %s", data["period"]["kw"], start, end, status)
    return {"id": rid, "status": status}
