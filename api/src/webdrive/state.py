"""Ereignisse → Dashboard-Modell. Reine Funktion: keine DB, keine Uhr.

Das Dashboard zeigt Zustände, keine Logzeilen: wer hat ein Problem und warum,
was war ein Problem und ist behoben, wer ist aktiv. Die Texte der Gründe
entstehen hier, damit Frontend und Graylog-Link nichts über Logformate
wissen müssen.
"""
from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime, timedelta

from webdrive.correlate import Failure, pair_failures
from webdrive.parse import Event, normalize_user

PORTAL_REASONS = {
    "invalid password": "Falsches Passwort",
    "user password change required": "Passwort muss im AD geändert werden",
    "invalid user": "User im AD unbekannt",
    "nas cannot find user realm": "Mit E-Mail statt Username angemeldet",
    "user not filtered by groups": "Nicht in der Webdrive-Gruppe",
    "not imported": "Noch nicht im FAC – Sync abwarten",
    "invalid token": "Falscher FortiToken-Code",
    "locked": "Im FAC gesperrt (zu viele Fehlversuche)",
}
PROVISION_REASONS = {
    "displayname": "Name fehlt im AD – Vor- oder Nachname leer",
    "mail": "E-Mail fehlt im AD",
    "sam": "sAMAccountName fehlt im AD",
    "unknown": "OpenCloud konnte den User nicht anlegen",
}
UPLOAD_REASONS = {
    "too_large": "Datei zu groß",
    "quota": "Speicherplatz voll",
    "locked": "Datei gesperrt",
    "name": "Unzulässiger Dateiname",
}
AV_OUTCOMES = {"delete": "gelöscht", "abort": "abgebrochen", "continue": "durchgelassen"}
REALM_REASON = "nas cannot find user realm"
UPLOAD_STALE = timedelta(minutes=30)
UNKNOWN_USER = "unbekannter User"


def portal_reason(raw: str) -> str:
    low = raw.lower()
    for key, text in PORTAL_REASONS.items():
        if low.startswith(key):
            return text
    return f"Anmeldung fehlgeschlagen ({raw})" if raw else "Anmeldung fehlgeschlagen (Grund unbekannt)"


def _iso(ts: datetime | None) -> str | None:
    return ts.isoformat() if ts else None


def _attempts(n: int) -> str:
    return "1 Fehlversuch" if n == 1 else f"{n} Fehlversuche"


# ── Sync ──────────────────────────────────────────────────────────────────────

def _sync_runs(events: list[Event]) -> list[dict]:
    """Läufe der Sync-Regel. Die vier Zeilen eines Laufs tragen dieselbe Sekunde,
    Graylog liefert sie aber nicht zwingend in Reihenfolge — deshalb Zuordnung
    über die Zeit statt über die Position."""
    runs = [{"ts": e.ts, "users": None, "modified": None, "ok": False, "error": None}
            for e in events if e.kind == "sync_start"]
    runs.sort(key=lambda r: r["ts"])
    for e in events:
        if not e.kind.startswith("sync_") or e.kind == "sync_start":
            continue
        owners = [r for r in runs if r["ts"] <= e.ts + timedelta(seconds=2)]
        if not owners:
            continue
        r = owners[-1]
        if e.kind == "sync_retrieved":
            r["users"] = e.data["users"]
        elif e.kind == "sync_modified":
            r["modified"] = e.data["modified"]
        elif e.kind == "sync_ok":
            r["ok"] = True
        elif e.kind == "sync_failed":
            r["error"] = e.data.get("msg")
    return runs


def sync_summary(events: list[Event]) -> dict | None:
    runs = _sync_runs(events)
    if not runs:
        return None
    # Ein Lauf außerhalb des üblichen Takts (häufigste Minute) war manuell.
    usual = Counter(r["ts"].minute for r in runs[-24:]).most_common(1)[0][0] if len(runs) >= 3 else None

    def manual(ts: datetime) -> bool:
        if usual is None:
            return False
        d = abs(ts.minute - usual)
        return min(d, 60 - d) > 1

    last = runs[-1]
    out = {"last_run": _iso(last["ts"]), "users": last["users"], "modified": last["modified"],
           "ok": last["ok"], "error": last["error"], "manual": manual(last["ts"]), "last_change": None}
    changes = [e for e in events if e.kind in ("attr_changed", "user_added") and e.username]
    if changes:
        c = changes[-1]
        text = "neu angelegt" if c.kind == "user_added" else ", ".join(c.data.get("fields", []))
        run = [r for r in runs if r["ts"] <= c.ts + timedelta(seconds=2)]
        out["last_change"] = {"ts": _iso(c.ts), "username": c.username, "text": text,
                              "manual": manual(run[-1]["ts"]) if run else False}
    return out


# ── Gesamtmodell ──────────────────────────────────────────────────────────────

def build(events: list[Event], identities: dict[str, tuple[str, datetime]],
          now: datetime, since: datetime, active_window_min: int = 15) -> dict:
    """events darf vor `since` beginnen (für den Sync-Kopf); User-Zustände
    berücksichtigen nur Ereignisse ab `since`."""
    events = sorted(events, key=lambda e: e.ts)
    in_range = [e for e in events if e.ts >= since]
    user_of = {o: u for o, (u, _) in identities.items()}
    first_seen_of = {u: fs for _, (u, fs) in identities.items()}

    activity: dict[str, list[datetime]] = defaultdict(list)
    uploads: Counter = Counter()
    unknown: set[str] = set()
    for e in in_range:
        if e.kind == "session_seen":
            if e.opaque_id in user_of:
                activity[user_of[e.opaque_id]].append(e.ts)
            else:
                unknown.add(e.opaque_id)
        elif e.kind == "file_scanned" and e.opaque_id in user_of:
            uploads[user_of[e.opaque_id]] += 1

    problems: list[dict] = []
    hints: list[dict] = []

    # Anmeldung am Portal: Fehlversuche bis zum nächsten erfolgreichen Login
    logins_ok = [e for e in in_range if e.kind == "portal_login_ok"]
    failures = pair_failures(in_range)
    failures += [Failure(e.username, e.ts, "locked", "", e.username)
                 for e in in_range if e.kind == "user_locked" and e.username]

    def resolved_by(f: Failure) -> Event | None:
        for l in logins_ok:
            if l.ts <= f.ts:
                continue
            if l.username == f.username:
                return l
            # E-Mail statt Username ist kein Konto — gelöst ist es, sobald vom
            # selben Rechner aus ein richtiger Login klappt.
            if f.reason.lower().startswith(REALM_REASON) and f.client_ip \
                    and l.data.get("client_ip") == f.client_ip:
                return l
        return None

    groups: dict[tuple, list[Failure]] = defaultdict(list)
    for f in sorted(failures, key=lambda f: f.ts):
        ok = resolved_by(f)
        groups[(f.username, ok.ts if ok else None)].append(f)
    retried: dict[str, list] = {}       # je User ein Hinweis, auch bei mehreren Anläufen
    for (user, ok_ts), grp in groups.items():
        last = grp[-1]
        name = last.entered if last.reason.lower().startswith(REALM_REASON) else user
        if ok_ts is None:
            problems.append({"username": name, "category": "login", "reason": portal_reason(last.reason),
                             "count": len(grp), "first": _iso(grp[0].ts), "last": _iso(last.ts)})
            continue
        n, prev_ok, prev_last = retried.get(name, (0, None, None))
        newer = prev_ok is None or ok_ts > prev_ok
        retried[name] = (n + len(grp), ok_ts if newer else prev_ok, last if newer else prev_last)
    for name, (n, ok_ts, last) in retried.items():
        hints.append({"username": name, "kind": "retry_ok",
                      "text": f"{_attempts(n)} ({portal_reason(last.reason)}), danach erfolgreich",
                      "ts": _iso(ok_ts)})

    # Erstanmeldung von OpenCloud abgelehnt: gelöst durch eine spätere Sitzung
    prov: dict[str, list[Event]] = defaultdict(list)
    for e in in_range:
        if e.kind == "provision_failed" and e.username:
            prov[e.username].append(e)
    for user, grp in prov.items():
        last = grp[-1]
        reason = PROVISION_REASONS.get(last.data.get("reason"), PROVISION_REASONS["unknown"])
        after = [t for t in activity.get(user, []) if t > last.ts]
        if after:
            hints.append({"username": user, "kind": "resolved",
                          "text": f"Erstanmeldung scheiterte ({reason}), behoben", "ts": _iso(min(after))})
        else:
            problems.append({"username": user, "category": "login", "reason": reason, "count": len(grp),
                             "first": _iso(grp[0].ts), "last": _iso(last.ts)})

    # Dateien
    unattributed: list[dict] = []
    started: dict[str, datetime] = {}
    finished: set[str] = set()
    for e in in_range:
        if e.kind == "file_scanned" and e.data.get("infected"):
            outcome = AV_OUTCOMES.get(e.data.get("outcome"), e.data.get("outcome") or "")
            virus = e.data.get("virus") or "unbekannt"
            problems.append({"username": user_of.get(e.opaque_id, UNKNOWN_USER), "category": "file",
                             "reason": f"Virus gefunden: {e.data.get('filename')} ({virus}), {outcome}",
                             "count": 1, "first": _iso(e.ts), "last": _iso(e.ts)})
        elif e.kind == "scan_skipped":
            hints.append({"username": user_of.get(e.opaque_id, UNKNOWN_USER), "kind": "scan_skipped",
                          "text": f"Nicht auf Viren geprüft (zu groß): {e.data.get('filename')}",
                          "ts": _iso(e.ts)})
        elif e.kind == "upload_failed":
            unattributed.append({"reason": UPLOAD_REASONS.get(e.data.get("reason"), "Upload fehlgeschlagen"),
                                 "detail": e.data.get("path", ""), "ts": _iso(e.ts)})
        elif e.kind == "file_error":
            unattributed.append({"reason": "Datei-Problem (unbekannt)",
                                 "detail": f"{e.data.get('service')}: {e.data.get('detail')}", "ts": _iso(e.ts)})
        elif e.kind == "upload_started":
            started.setdefault(e.data["upload_id"], e.ts)
        elif e.kind == "upload_finished":
            finished.add(e.data["upload_id"])
    for uid, ts in started.items():
        if uid not in finished and now - ts > UPLOAD_STALE:
            unattributed.append({"reason": "Upload abgebrochen", "detail": uid, "ts": _iso(ts)})

    # AD-Attribut geändert, nachdem OpenCloud den User schon angelegt hat.
    # Der FAC schreibt dieselbe Änderung teils doppelt (10002 + 10051).
    changes: dict[tuple, Event] = {}
    for e in in_range:
        if e.kind == "attr_changed" and e.username and e.username in first_seen_of \
                and first_seen_of[e.username] < e.ts:
            key = (e.username, e.ts.replace(microsecond=0))
            if key not in changes or e.data.get("new"):
                changes[key] = e
    for e in changes.values():
        detail = f": {e.data['old']} → {e.data['new']}" if e.data.get("new") else ""
        hints.append({"username": e.username, "kind": "attr_changed",
                      "text": f"AD-Attribut nach Erstanmeldung geändert ({', '.join(e.data.get('fields', []))}){detail}",
                      "ts": _iso(e.ts)})

    window = timedelta(minutes=active_window_min)
    active, inactive = [], []
    for user, times in activity.items():
        row = {"username": user, "first": _iso(min(times)), "last": _iso(max(times)),
               "uploads": uploads.get(user, 0)}
        (active if now - max(times) <= window else inactive).append(row)
    active.sort(key=lambda r: r["first"])
    inactive.sort(key=lambda r: r["last"], reverse=True)

    return {
        "sync": sync_summary(events),
        "problems": sorted(problems, key=lambda p: p["last"], reverse=True),
        "hints": sorted(hints, key=lambda h: h["ts"], reverse=True),
        "active": active,
        "inactive": inactive,
        "unknown_sessions": len(unknown),
        "unattributed": sorted(unattributed, key=lambda u: u["ts"], reverse=True),
    }


# ── Userliste aus dem FortiAuthenticator ──────────────────────────────────────

# Was OpenCloud für die Erstanmeldung braucht: E-Mail und einen Anzeigenamen
# (aus Vor- und Nachname). sAMAccountName ist der Username selbst.
FAC_ATTRS = (("email", "E-Mail"), ("first_name", "Vorname"), ("last_name", "Nachname"))


def user_list(fac_users: list[dict], identities: dict[str, tuple[str, datetime]],
              model: dict, dn_filter: str = "") -> list[dict]:
    """FAC-User mit fehlenden Attributen und Webdrive-Zustand.
    status: problem | active | inactive | known (schon einmal in OpenCloud) | never"""
    known = {u for u, _ in identities.values()}
    active = {r["username"]: r for r in model.get("active", [])}
    inactive = {r["username"]: r for r in model.get("inactive", [])}
    problems = {p["username"] for p in model.get("problems", [])}
    needle = dn_filter.strip().lower()
    rows = []
    for u in fac_users:
        name = normalize_user(u.get("username"))
        if not name or (needle and needle not in str(u.get("dn") or "").lower()):
            continue
        missing = [label for key, label in FAC_ATTRS if not str(u.get(key) or "").strip()]
        seen = active.get(name) or inactive.get(name)
        status = ("problem" if name in problems else "active" if name in active
                  else "inactive" if name in inactive else "known" if name in known else "never")
        rows.append({
            "username": name,
            "name": " ".join(x for x in (u.get("first_name"), u.get("last_name")) if x),
            "email": u.get("email") or "",
            "enabled": bool(u.get("active", True)),
            "missing": missing,
            "status": status,
            "last": seen["last"] if seen else None,
        })
    rank = {"problem": 0, "active": 2, "inactive": 3, "known": 4, "never": 5}
    rows.sort(key=lambda r: (0 if r["missing"] else 1, rank[r["status"]], r["username"]))
    return rows
