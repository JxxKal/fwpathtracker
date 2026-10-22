"""Die Kapitel des Wochenreports — je Quelle eine Frage.

Jedes Kapitel ist ein dict mit festem Aufbau, das die Ansicht (und später das
PDF) ohne Sonderfälle darstellt:

    id, question, source, status (ok | partial | error | off), note,
    answer (ein Satz), kpis, daily (Zählung je Tag), charts, tables, attention

Je Quelle gibt es eine reine Auswertung (Daten rein, Kapitel raus — testbar
ohne Quelle) und einen Abholer, der die Daten besorgt. Ein Fehler beim Abholen
kostet nur das eigene Kapitel, nie den Bericht.
"""
from __future__ import annotations

import logging
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from report import period

log = logging.getLogger("report.chapters")

TABLE_MAX = 200
TOP = 10

SEVERITY = {0: "nicht klassifiziert", 1: "Information", 2: "Warnung", 3: "Durchschnitt",
            4: "Hoch", 5: "Katastrophe"}
SEVERITY_COLOR = {0: "#97AAB3", 1: "#7499FF", 2: "#FFC859", 3: "#FFA059", 4: "#E97659",
                  5: "#E45959"}


@dataclass
class Ctx:
    """Zeitraum und Konfiguration eines Laufs."""
    frm: datetime
    to: datetime
    cfg: dict
    days: list[dict] = field(default_factory=list)

    def __post_init__(self) -> None:
        if not self.days:
            self.days = period.days(self.frm, self.to, self.cfg)

    def day(self, ts: datetime | None) -> int | None:
        return None if ts is None else period.day_index(ts, self.frm, self.cfg, len(self.days))

    def daily(self, stamps) -> list[int]:
        out = [0] * len(self.days)
        for ts in stamps:
            i = self.day(ts)
            if i is not None:
                out[i] += 1
        return out

    def local(self, ts: datetime | None) -> str:
        if ts is None:
            return "—"
        return ts.astimezone(period.tz_of(self.cfg)).strftime("%a %d.%m. %H:%M")


def empty(cid: str, question: str, source: str, status: str, note: str) -> dict:
    """Kapitel ohne Daten: Quelle aus oder nicht erreichbar. Ehrlich ausweisen,
    nie „keine Änderungen" behaupten."""
    return {"id": cid, "question": question, "source": source, "status": status,
            "note": note, "answer": note, "kpis": [], "daily": [], "charts": [],
            "tables": [], "attention": []}


def _n(n: int, one: str, many: str) -> str:
    return f"{n} {one if n == 1 else many}"


def _dur(seconds: float | None) -> str:
    if seconds is None:
        return "—"
    m = int(seconds // 60)
    if m < 60:
        return f"{m} min"
    h, m = divmod(m, 60)
    if h < 48:
        return f"{h} h {m:02d} min"
    return f"{h // 24} d {h % 24} h"


def _top(counter: Counter, n: int = TOP) -> list[dict]:
    return [{"label": str(k), "value": v} for k, v in counter.most_common(n)]


# ── 2. Firewall-Änderungen (FAZ-Ereignislogs) ────────────────────────────────

Q_FIREWALL = "Was wurde an den Firewalls geändert?"


def is_config_change(rec: dict) -> bool:
    """Konfigurationsänderung einer FortiGate: Ereignis mit Konfigurationspfad."""
    if rec.get("cfgpath"):
        return True
    desc = str(rec.get("logdesc") or "").lower()
    return "configured" in desc or "config" in desc and "change" in desc


def firewall_chapter(logs: list[dict], ctx: Ctx, *, complete: bool = True,
                     total: int | None = None, log_time=None) -> dict:
    from faz import logs as faz_logs
    tz = period.tz_of(ctx.cfg)
    log_time = log_time or (lambda r: faz_logs.log_time(r, tz))
    changes = []
    for r in logs:
        if not is_config_change(r):
            continue
        ts = log_time(r)
        if ts is None or not (ctx.frm <= ts < ctx.to):
            continue
        changes.append((ts, r))
    changes.sort(key=lambda c: c[0])
    admins = Counter(str(r.get("user") or "?") for _, r in changes)
    devices = Counter(str(r.get("devname") or "?") for _, r in changes)
    actions = Counter(str(r.get("action") or "?").capitalize() for _, r in changes)
    off = [(ts, r, why) for ts, r in changes if (why := period.off_hours(ts, ctx.cfg))]

    def row(ts, r):
        return [ctx.local(ts), str(r.get("devname") or ""), str(r.get("vd") or ""),
                str(r.get("user") or ""), str(r.get("ui") or ""),
                str(r.get("action") or ""), str(r.get("cfgpath") or ""),
                str(r.get("cfgobj") or r.get("msg") or "")]

    cols = ["Zeit", "Firewall", "VDOM", "Admin", "Zugang", "Aktion", "Pfad", "Objekt"]
    n = len(changes)
    if n:
        answer = (f"{_n(n, 'Konfigurationsänderung', 'Konfigurationsänderungen')} auf "
                  f"{_n(len(devices), 'Firewall', 'Firewalls')} durch "
                  f"{_n(len(admins), 'Admin', 'Admins')}"
                  + (f", davon {len(off)} außerhalb der Arbeitszeit." if off else "."))
    else:
        answer = "Keine Konfigurationsänderungen in den FortiGate-Ereignislogs."
    status, note = "ok", None
    if not complete or (total is not None and total > len(logs)):
        status = "partial"
        note = (f"Der FortiAnalyzer lieferte {len(logs)} von {total or '?'} Ereignissen — "
                "die Zählung ist eine Untergrenze. Filter in den Report-Einstellungen enger fassen.")
    return {
        "id": "firewall", "question": Q_FIREWALL, "source": "FortiAnalyzer",
        "status": status, "note": note, "answer": answer,
        "kpis": [{"key": "fw_changes", "label": "Firewall-Änderungen", "value": n},
                 {"key": "fw_off_hours", "label": "davon außerhalb der Arbeitszeit",
                  "value": len(off)}],
        "daily": ctx.daily(ts for ts, _ in changes),
        "charts": [
            {"type": "daily", "title": "Änderungen je Tag",
             "series": [{"label": "Änderungen", "color": "#3d6ea8",
                         "values": ctx.daily(ts for ts, _ in changes)}]},
            {"type": "top", "title": "Nach Admin", "items": _top(admins)},
            {"type": "top", "title": "Nach Firewall", "items": _top(devices)},
            {"type": "top", "title": "Nach Aktion", "items": _top(actions)},
        ] if n else [],
        "tables": [{"title": "Änderungen", "columns": cols,
                    "rows": [row(ts, r) for ts, r in changes[-TABLE_MAX:]], "total": n}]
        if n else [],
        "attention": [{
            "title": f"Firewall-Änderung {why}: {r.get('devname') or '?'} durch "
                     f"{r.get('user') or '?'}",
            "why": f"{ctx.local(ts)} · {r.get('action') or ''} {r.get('cfgpath') or ''} "
                   f"{r.get('cfgobj') or ''}".strip(),
            "source": "FortiAnalyzer", "level": "medium"} for ts, r, why in off[:20]],
        "_changes": [{"ts": ts.isoformat(), "device": r.get("devname")} for ts, r in changes],
    }


async def firewall(state, ctx: Ctx, read_config) -> dict:
    from faz.client import FazNotConfigured, FazSource
    cfg = await read_config("faz")
    if not FazSource.configured(cfg):
        return empty("firewall", Q_FIREWALL, "FortiAnalyzer", "off",
                     "FortiAnalyzer ist nicht eingerichtet.")
    from faz import logs as faz_logs
    tz = faz_logs.tz_of(cfg)
    fmt = "%Y-%m-%d %H:%M:%S"
    try:
        res = await state.faz.logsearch(
            cfg, logtype="event", filter=str(ctx.cfg.get("faz_change_filter") or "subtype==system"),
            start=ctx.frm.astimezone(tz).strftime(fmt), end=ctx.to.astimezone(tz).strftime(fmt))
    except FazNotConfigured:
        return empty("firewall", Q_FIREWALL, "FortiAnalyzer", "off",
                     "FortiAnalyzer ist nicht eingerichtet.")
    except Exception as exc:
        return empty("firewall", Q_FIREWALL, "FortiAnalyzer", "error",
                     f"FortiAnalyzer nicht abrufbar: {exc}")
    return firewall_chapter(res["logs"], ctx, complete=res["complete"], total=res["total"],
                            log_time=lambda r: faz_logs.log_time(r, tz))


# ── 3. Neu im Netz (ARP-Historie, DNS, iTop, Zabbix) ─────────────────────────

Q_HOSTS = "Was ist neu im Netz, was ist verschwunden?"


def hosts_chapter(arp: dict, names: list[dict], ctx: Ctx, *, itop_ips: set[str] | None,
                  zabbix_ips: set[str] | None) -> dict:
    name_of = {r["ip"]: r["name"] for r in names}
    new, gone = arp["new"], arp["gone"]
    unmanaged = []
    for h in new:
        in_itop = None if itop_ips is None else h["ip"] in itop_ips
        in_zbx = None if zabbix_ips is None else h["ip"] in zabbix_ips
        h["in_itop"], h["in_zabbix"] = in_itop, in_zbx
        if in_itop is False and in_zbx is not True:
            unmanaged.append(h)

    def yn(v):
        return "—" if v is None else ("ja" if v else "nein")

    status, note = "ok", None
    start = arp.get("history_start")
    if start is None:
        status, note = "partial", "Die IP↔MAC-Historie ist leer — der ARP-Sweep läuft noch nicht."
    elif start >= ctx.frm:
        status = "partial"
        note = (f"Die IP↔MAC-Historie beginnt erst am {ctx.local(start)} — in diesem Zeitraum "
                "ist deshalb fast alles „neu“.")
    hints = ["Der DNS-Cache kennt nur Namen, nach denen A38 gefragt hat: „neu“ heißt "
             "„zum ersten Mal gesehen“."]
    answer = (f"{_n(len(new), 'neue MAC-Adresse', 'neue MAC-Adressen')}, "
              f"{_n(len(gone), 'verschwundene', 'verschwundene')} gegenüber der Vorwoche, "
              f"{_n(len(names), 'neuer DNS-Name', 'neue DNS-Namen')}"
              + (f"; {len(unmanaged)} neue Hosts weder im iTop noch in Zabbix." if unmanaged
                 else "."))
    cols = ["Erstmals", "IP", "Name", "MAC", "gesehen von", "iTop", "Zabbix"]
    return {
        "id": "hosts", "question": Q_HOSTS, "source": "ARP-Historie, DNS, iTop, Zabbix",
        "status": status, "note": note, "hints": hints, "answer": answer,
        "kpis": [{"key": "hosts_new", "label": "Neue MACs", "value": len(new)},
                 {"key": "hosts_gone", "label": "Verschwundene MACs", "value": len(gone)},
                 {"key": "hosts_unmanaged", "label": "Neu, ohne iTop/Zabbix",
                  "value": len(unmanaged)}],
        "daily": ctx.daily(h["first_seen"] for h in new),
        "charts": [{"type": "daily", "title": "Neue MACs je Tag",
                    "series": [{"label": "neu", "color": "#1ba34a",
                                "values": ctx.daily(h["first_seen"] for h in new)}]}]
        if new else [],
        "tables": [t for t in (
            {"title": "Neue Hosts", "columns": cols, "total": len(new),
             "rows": [[ctx.local(h["first_seen"]), h["ip"], name_of.get(h["ip"]) or "",
                       h["mac"], " ".join(p for p in (h.get("device"), h.get("interface")) if p),
                       yn(h["in_itop"]), yn(h["in_zabbix"])] for h in new[:TABLE_MAX]]}
            if new else None,
            {"title": "Verschwunden (in der Vorwoche gesehen, seitdem nicht mehr)",
             "columns": ["Zuletzt", "IP", "MAC", "gesehen von"], "total": len(gone),
             "rows": [[ctx.local(h["last_seen"]), h["ip"], h["mac"], h.get("device") or ""]
                      for h in gone[:TABLE_MAX]]} if gone else None,
            {"title": "Neue DNS-Namen", "columns": ["Erstmals", "IP", "Name"],
             "total": len(names),
             "rows": [[ctx.local(r["first_seen"]), r["ip"], r["name"]]
                      for r in names[:TABLE_MAX]]} if names else None,
        ) if t],
        "attention": [{
            "title": f"Neuer Host ohne Pflege: {h['ip']}"
                     + (f" ({name_of[h['ip']]})" if name_of.get(h["ip"]) else ""),
            "why": f"erstmals {ctx.local(h['first_seen'])}, MAC {h['mac']} — weder im iTop "
                   "noch in Zabbix", "source": "ARP-Historie", "level": "medium"}
            for h in unmanaged[:15]] if status == "ok" else [],
    }


async def hosts(state, ctx: Ctx, read_config, zabbix_index=None) -> dict:
    try:
        arp = await state.arp_store.week(ctx.frm, ctx.to)
        names = await state.dns_cache.new_names(ctx.frm, ctx.to)
    except Exception as exc:
        return empty("hosts", Q_HOSTS, "ARP-Historie", "error", f"Historie nicht lesbar: {exc}")
    itop_ips = None
    itop_cfg = await read_config("itop")
    if itop_cfg.get("base_url"):
        try:
            itop_ips = {h["ip"] for h in await state.resolver.itop.hosts(itop_cfg) if h.get("ip")}
        except Exception as exc:
            log.warning("Report: iTop nicht abrufbar: %s", exc)
    zabbix_ips = set(zabbix_index["by_ip"]) if zabbix_index else None
    return hosts_chapter(arp, names, ctx, itop_ips=itop_ips, zabbix_ips=zabbix_ips)


# ── 6. Betrieb (Zabbix) ──────────────────────────────────────────────────────

Q_ZABBIX = "Wie stabil lief der Betrieb?"


def zabbix_chapter(events: list[dict], ctx: Ctx) -> dict:
    now_end = ctx.to.timestamp()
    probs = []
    for e in events:
        start = datetime.fromtimestamp(int(e["clock"]), tz=timezone.utc)
        end = e.get("r_clock")
        sev = int(e.get("severity") or 0)
        host = ", ".join(h.get("name") or "?" for h in e.get("hosts") or []) or "?"
        probs.append({"ts": start, "sev": sev, "host": host, "name": e.get("name") or "?",
                      "open": end is None,
                      "dur": (min(end, now_end) if end else now_end) - start.timestamp(),
                      "ack": str(e.get("acknowledged") or "0") == "1"})
    high = [p for p in probs if p["sev"] >= 4]
    open_ = [p for p in probs if p["open"]]
    series = []
    for sev in (5, 4, 3, 2, 1, 0):
        vals = ctx.daily(p["ts"] for p in probs if p["sev"] == sev)
        if any(vals):
            series.append({"label": SEVERITY[sev], "color": SEVERITY_COLOR[sev], "values": vals})
    longest = sorted(probs, key=lambda p: -p["dur"])[:15]
    answer = (f"{_n(len(probs), 'Problem', 'Probleme')} begannen im Zeitraum, "
              f"{len(high)} davon „Hoch“ oder schwerer; {len(open_)} sind noch offen."
              if probs else "Keine Zabbix-Probleme im Zeitraum.")
    return {
        "id": "zabbix", "question": Q_ZABBIX, "source": "Zabbix", "status": "ok", "note": None,
        "answer": answer,
        "kpis": [{"key": "zbx_problems", "label": "Zabbix-Probleme", "value": len(probs)},
                 {"key": "zbx_high", "label": "davon Hoch und schwerer", "value": len(high)},
                 {"key": "zbx_open", "label": "noch offen", "value": len(open_)}],
        "daily": ctx.daily(p["ts"] for p in probs),
        "charts": [c for c in (
            {"type": "daily", "title": "Probleme je Tag nach Schwere", "stacked": True,
             "series": series} if series else None,
            {"type": "top", "title": "Hosts mit den meisten Problemen",
             "items": _top(Counter(p["host"] for p in probs))} if probs else None,
        ) if c],
        "tables": [{"title": "Längste Probleme", "total": len(probs),
                    "columns": ["Beginn", "Host", "Problem", "Schwere", "Dauer", "Status"],
                    "rows": [[ctx.local(p["ts"]), p["host"], p["name"], SEVERITY[p["sev"]],
                              _dur(p["dur"]), "offen" if p["open"] else
                              ("behoben" + (", quittiert" if p["ack"] else ""))]
                             for p in longest]}] if probs else [],
        "attention": [{
            "title": f"Offenes Problem ({SEVERITY[p['sev']]}): {p['host']}",
            "why": f"{p['name']} — seit {ctx.local(p['ts'])}, {_dur(p['dur'])}"
                   + ("" if p["ack"] else ", nicht quittiert"),
            "source": "Zabbix", "level": "high" if p["sev"] >= 4 else "medium"}
            for p in sorted(open_, key=lambda p: (-p["sev"], -p["dur"])) if p["sev"] >= 4][:15],
        "_high": [{"ts": p["ts"].isoformat(), "host": p["host"], "name": p["name"]}
                  for p in high],
    }


async def zabbix(state, ctx: Ctx, read_config) -> dict:
    cfg = await read_config("zabbix")
    if not cfg.get("base_url"):
        return empty("zabbix", Q_ZABBIX, "Zabbix", "off", "Zabbix ist nicht eingerichtet.")
    try:
        events = await state.zabbix.events(cfg, ctx.frm.timestamp(), ctx.to.timestamp())
    except Exception as exc:
        hint = " — `event.get` in der Allow-Liste des API-Users?" if "permission" in str(
            exc).lower() or "not authorized" in str(exc).lower() else ""
        return empty("zabbix", Q_ZABBIX, "Zabbix", "error",
                     f"Zabbix-Ereignisse nicht abrufbar: {exc}{hint}")
    return zabbix_chapter(events, ctx)


# ── 4. Verkabelung und Geräte (LibreNMS-Eventlog) ────────────────────────────

Q_LIBRENMS = "Was hat sich an Switches und Ports getan?"


def _librenms_kind(row: dict) -> str:
    msg = str(row.get("message") or "").lower()
    typ = str(row.get("type") or "").lower()
    if "reboot" in msg:
        return "Neustart"
    if "device added" in msg or ("added" in msg and typ == "system"):
        return "Gerät neu"
    if ("deleted" in msg or "removed" in msg) and typ == "system":
        return "Gerät entfernt"
    if typ == "interface":
        # „ifOperStatus: up -> down": maßgeblich ist der Zustand NACH dem Pfeil.
        after = msg.rsplit("->", 1)[-1] if "->" in msg else msg
        if "down" in after:
            return "Port down"
        if "up" in after:
            return "Port up"
    if "status" in msg and "down" in msg:
        return "Gerät down"
    if "status" in msg and "up" in msg:
        return "Gerät up"
    return "sonstiges"


def librenms_chapter(rows: list[dict], ctx: Ctx, *, complete: bool = True,
                     total: int | None = None) -> dict:
    tz = period.tz_of(ctx.cfg)
    items = []
    for r in rows:
        try:
            ts = datetime.fromisoformat(str(r.get("datetime"))).replace(tzinfo=tz)
        except ValueError:
            continue
        items.append({"ts": ts, "kind": _librenms_kind(r),
                      "device": r.get("hostname") or r.get("sysName") or "?",
                      "msg": str(r.get("message") or "")})
    kinds = Counter(i["kind"] for i in items)
    downs = Counter(i["device"] for i in items if i["kind"] == "Port down")
    notable = [i for i in items if i["kind"] in ("Neustart", "Gerät neu", "Gerät entfernt",
                                                    "Gerät down")]
    answer = (f"{kinds['Port down']} Port-Ausfälle, {kinds['Neustart']} Neustarts, "
              f"{kinds['Gerät neu']} neue Geräte in LibreNMS." if items
              else "Keine Ereignisse im LibreNMS-Eventlog.")
    order = ["Port down", "Port up", "Neustart", "Gerät down", "Gerät up", "Gerät neu",
             "Gerät entfernt"]
    colors = {"Port down": "#E97659", "Port up": "#59DB8F", "Neustart": "#FFA059",
              "Gerät down": "#B71C1C", "Gerät up": "#1ba34a", "Gerät neu": "#3d6ea8",
              "Gerät entfernt": "#777777"}
    status = "ok" if complete else "partial"
    return {
        "id": "librenms", "question": Q_LIBRENMS, "source": "LibreNMS", "status": status,
        "note": None if complete else f"Nur {len(rows)} von {total} Einträgen geholt.",
        "answer": answer,
        "kpis": [{"key": "lnms_port_down", "label": "Port-Ausfälle", "value": kinds["Port down"]},
                 {"key": "lnms_reboots", "label": "Neustarts", "value": kinds["Neustart"]}],
        "daily": ctx.daily(i["ts"] for i in items if i["kind"] != "sonstiges"),
        "charts": [c for c in (
            {"type": "daily", "title": "Ereignisse je Tag", "stacked": True,
             "series": [{"label": k, "color": colors[k],
                         "values": ctx.daily(i["ts"] for i in items if i["kind"] == k)}
                        for k in order if kinds[k]]} if items else None,
            {"type": "top", "title": "Switches mit den meisten Port-Ausfällen",
             "items": _top(downs)} if downs else None,
        ) if c],
        "tables": [{"title": "Neustarts, neue und ausgefallene Geräte", "total": len(notable),
                    "columns": ["Zeit", "Gerät", "Ereignis", "Meldung"],
                    "rows": [[ctx.local(i["ts"]), i["device"], i["kind"], i["msg"]]
                             for i in notable[:TABLE_MAX]]}] if notable else [],
        "attention": [{"title": f"{i['kind']}: {i['device']}", "why": f"{ctx.local(i['ts'])} · "
                       f"{i['msg']}", "source": "LibreNMS", "level": "medium"}
                      for i in notable if i["kind"] in ("Neustart", "Gerät down")][:10],
    }


async def librenms(state, ctx: Ctx, read_config) -> dict:
    cfg = await read_config("librenms")
    if not cfg.get("base_url"):
        return empty("librenms", Q_LIBRENMS, "LibreNMS", "off", "LibreNMS ist nicht eingerichtet.")
    tz = period.tz_of(ctx.cfg)
    fmt = "%Y-%m-%d %H:%M:%S"
    try:
        res = await state.locate.librenms.eventlog(
            cfg, ctx.frm.astimezone(tz).strftime(fmt), ctx.to.astimezone(tz).strftime(fmt))
    except Exception as exc:
        return empty("librenms", Q_LIBRENMS, "LibreNMS", "error",
                     f"LibreNMS-Eventlog nicht abrufbar: {exc}")
    return librenms_chapter(res["logs"], ctx, complete=res["complete"], total=res["total"])


# ── 10. Webdrive ─────────────────────────────────────────────────────────────

Q_WEBDRIVE = "Wie lief Webdrive?"

WEBDRIVE_KINDS = {
    "portal_login_ok": "Anmeldungen", "portal_login_failed": "Fehlanmeldungen",
    "user_locked": "Sperrungen", "upload_finished": "Uploads", "upload_failed": "Upload-Fehler",
    "file_error": "Dateifehler", "sync_failed": "Sync-Fehler", "provision_failed":
        "Bereitstellungsfehler", "user_added": "neue Nutzer",
}


def webdrive_chapter(events: list, ctx: Ctx) -> dict:
    evs = [e for e in events if ctx.frm <= e.ts < ctx.to]
    kinds = Counter(e.kind for e in evs)
    users = {e.username for e in evs if e.kind == "portal_login_ok" and e.username}
    errors = sum(kinds[k] for k in ("portal_login_failed", "upload_failed", "file_error",
                                    "sync_failed", "provision_failed"))
    answer = (f"{_n(len(users), 'Nutzer', 'Nutzer')} angemeldet, {kinds['upload_finished']} "
              f"Uploads, {errors} Fehler." if evs else "Keine Webdrive-Ereignisse im Zeitraum.")
    return {
        "id": "webdrive", "question": Q_WEBDRIVE, "source": "Webdrive (Graylog)",
        "status": "ok", "note": None, "answer": answer,
        "kpis": [{"key": "wd_users", "label": "Webdrive-Nutzer", "value": len(users)},
                 {"key": "wd_errors", "label": "Webdrive-Fehler", "value": errors}],
        "daily": ctx.daily(e.ts for e in evs if e.kind in WEBDRIVE_KINDS),
        "charts": [{"type": "daily", "title": "Anmeldungen und Fehler je Tag", "series": [
            {"label": "Anmeldungen", "color": "#1ba34a",
             "values": ctx.daily(e.ts for e in evs if e.kind == "portal_login_ok")},
            {"label": "Fehler", "color": "#E97659",
             "values": ctx.daily(e.ts for e in evs if e.kind in (
                 "portal_login_failed", "upload_failed", "file_error", "sync_failed",
                 "provision_failed"))}]}] if evs else [],
        "tables": [{"title": "Ereignisse", "columns": ["Art", "Anzahl"], "total": None,
                    "rows": [[label, kinds[k]] for k, label in WEBDRIVE_KINDS.items()
                             if kinds[k]]}] if evs else [],
        "attention": [],
    }


async def webdrive(state, ctx: Ctx, read_config) -> dict:
    cfg = await read_config("webdrive")
    if not cfg.get("stream_id") and not cfg.get("fac_query") and not cfg.get("oc_query"):
        return empty("webdrive", Q_WEBDRIVE, "Webdrive", "off", "Webdrive ist nicht eingerichtet.")
    try:
        events = await state.webdrive_store.load_events(ctx.frm)
    except Exception as exc:
        return empty("webdrive", Q_WEBDRIVE, "Webdrive", "error", f"Nicht lesbar: {exc}")
    ch = webdrive_chapter(events, ctx)
    keep = int(cfg.get("retention_days", 7))
    if (ctx.to - ctx.frm).days >= keep:
        ch["status"] = "partial"
        ch["note"] = (f"Webdrive bewahrt nur {keep} Tage auf — der Anfang des Zeitraums "
                      "kann fehlen.")
    return ch


def strip_private(ch: dict) -> dict:
    """Interne Hilfsfelder (Präfix _) nicht speichern."""
    return {k: v for k, v in ch.items() if not k.startswith("_")}


def any_of(*vals: Any) -> Any:
    return next((v for v in vals if v), None)
