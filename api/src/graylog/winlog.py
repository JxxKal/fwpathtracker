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
IFIX_FILTER = (
    '({p}event_code:1 OR {p}event_code:2) AND NOT {p}event_provider:Microsoft\\-Windows\\-Sysmon '
    'AND NOT {p}winlog_provider_name:"Veeam Backup" AND message:("*File service Message time out*" '
    'OR "*Snap shot failed*" OR "*SCADA Sync*" OR "*STANDBY*" OR "*ACTIVE*" OR "*SAC*" '
    'OR "*Network*" OR "*NODE*" OR "*down*" OR "*Kopplung*")')

# AD-Ereignisse für den Wochenreport: EventID → (Bedeutung, Behandlung).
#   alert  immer unter „Was sollte sich jemand ansehen?", namentlich
#   named  einzeln mit Konto, Gruppe und Bearbeiter
#   count  nur gezählt (mit den häufigsten Konten, wo sinnvoll)
AD_EVENTS = {
    1102: ("Sicherheitsprotokoll gelöscht", "alert"),
    4719: ("Überwachungsrichtlinie geändert", "alert"),
    4739: ("Domänenrichtlinie geändert", "alert"),
    4794: ("DSRM-Administratorkennwort gesetzt", "alert"),
    4765: ("SID-History zu Konto hinzugefügt", "alert"),
    4766: ("SID-History hinzufügen fehlgeschlagen", "alert"),
    4706: ("Vertrauensstellung angelegt", "alert"),
    4707: ("Vertrauensstellung entfernt", "alert"),
    4716: ("Vertrauensstellung geändert", "alert"),
    4720: ("Konto angelegt", "named"), 4726: ("Konto gelöscht", "named"),
    4722: ("Konto aktiviert", "named"), 4725: ("Konto deaktiviert", "named"),
    4781: ("Kontoname geändert", "named"), 4767: ("Konto entsperrt", "named"),
    4741: ("Computerkonto angelegt", "named"), 4743: ("Computerkonto gelöscht", "named"),
    4727: ("Globale Sicherheitsgruppe angelegt", "named"),
    4730: ("Globale Sicherheitsgruppe gelöscht", "named"),
    4731: ("Lokale Sicherheitsgruppe angelegt", "named"),
    4734: ("Lokale Sicherheitsgruppe gelöscht", "named"),
    4754: ("Universelle Sicherheitsgruppe angelegt", "named"),
    4758: ("Universelle Sicherheitsgruppe gelöscht", "named"),
    4735: ("Lokale Gruppe geändert", "named"), 4737: ("Globale Gruppe geändert", "named"),
    4755: ("Universelle Gruppe geändert", "named"),
    4728: ("Mitglied zu globaler Gruppe hinzugefügt", "named"),
    4729: ("Mitglied aus globaler Gruppe entfernt", "named"),
    4732: ("Mitglied zu lokaler Gruppe hinzugefügt", "named"),
    4733: ("Mitglied aus lokaler Gruppe entfernt", "named"),
    4756: ("Mitglied zu universeller Gruppe hinzugefügt", "named"),
    4757: ("Mitglied aus universeller Gruppe entfernt", "named"),
    4723: ("Kennwort selbst geändert", "count"),
    4724: ("Kennwort durch Admin zurückgesetzt", "count"),
    4738: ("Konto geändert", "count"), 4742: ("Computerkonto geändert", "count"),
    4740: ("Konto gesperrt", "count"), 4625: ("Fehlanmeldung", "count"),
    4771: ("Kerberos-Vorauthentifizierung fehlgeschlagen", "count"),
    4776: ("NTLM-Anmeldeprüfung fehlgeschlagen", "count"),
}
GROUP_MEMBER_EVENTS = {4728, 4729, 4732, 4733, 4756, 4757}
PRIVILEGED_GROUPS = ["Domain Admins", "Enterprise Admins", "Schema Admins", "Administrators",
                     "Account Operators", "Backup Operators", "Server Operators",
                     "Print Operators", "Group Policy Creator Owners", "DnsAdmins",
                     "Domänen-Admins", "Organisations-Admins", "Schema-Admins",
                     "Administratoren", "Konten-Operatoren", "Sicherungs-Operatoren",
                     "Server-Operatoren"]
# Zustand der iFIX-Knoten aus dem Windows-Ereignisprotokoll.
NODE_EVENTS = {
    6008: ("Unerwarteter Neustart", "alert"), 41: ("Kernel-Power: Neustart ohne Herunterfahren", "alert"),
    7031: ("Dienst unerwartet beendet", "named"), 7034: ("Dienst unerwartet beendet", "named"),
    1000: ("Anwendung abgestürzt", "named"), 1002: ("Anwendung hängt", "named"),
    6005: ("Ereignisprotokoll gestartet (Systemstart)", "count"),
    6006: ("Ereignisprotokoll beendet (Herunterfahren)", "count"),
}
IFIX_KEYWORDS = ["File service Message time out", "Snap shot failed", "SCADA Sync", "STANDBY",
                 "ACTIVE", "SAC", "Network", "NODE", "down", "Kopplung"]
ROLES = {
    "ad": {"label": "Active Directory", "filter": "{p}winlog_channel:Security"},
    # iFIX-Meldungen: Fehler/Warnungen (event.code 1/2) mit den Stichworten, die
    # im Betrieb zählen — ohne Sysmon und Veeam. Vorgabe aus dem Betrieb.
    "ifix": {"label": "iFIX (SCADA)", "filter": IFIX_FILTER},
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


# Der Absender eines Windows-Ereignisses: der Rechner, auf dem Winlogbeat
# läuft (`host.name`, z. B. STAFFS2.op-tech.com). NICHT `source` — dort steht
# der Graylog-Eingang bzw. Sammler. Keyword-Feld: Groß-/Kleinschreibung zählt.
HOST_FIELD = "{p}host_name"
LUCENE_SPECIAL = set('+-=&|><!(){}[]^"~*?:\\/ ')


def host_field(cfg: dict, prefix: str) -> str:
    return str(cfg.get("host_field") or HOST_FIELD).replace("{p}", prefix)


def _esc(term: str) -> str:
    return "".join("\\" + c if c in LUCENE_SPECIAL else c for c in term)


def host_terms(name: str) -> list[str]:
    """`svo3005-ot` findet auch `SVO3005-OT` und `SVO3005-OT.op-tech.com`."""
    out = []
    for v in dict.fromkeys((name, name.lower(), name.upper())):
        out.append(_esc(v))
        if "." not in v:
            out.append(_esc(v) + ".*")
    return out


def role_hosts(cfg: dict, role: str) -> list[str]:
    """Rechner einer Rolle (Domain Controller, iFIX-Knoten)."""
    hosts = ((cfg.get("roles") or {}).get(role) or {}).get("hosts") or []
    return list(dict.fromkeys(str(h).strip() for h in hosts if str(h).strip()))


def hosts_query(cfg: dict, role: str, prefix: str) -> str:
    """Nur die Rechner einer Rolle, ohne Filter — für den Knotenzustand."""
    hosts = role_hosts(cfg, role)
    if not hosts:
        return ""
    return f"{host_field(cfg, prefix)}:(" + " OR ".join(
        t for h in hosts for t in host_terms(h)) + ")"


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
        terms = [t for h in hosts for t in host_terms(h)]
        parts.append(f"{host_field(cfg, prefix)}:(" + " OR ".join(terms) + ")")
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
                 "hosts": [], "host_field": None, "collectors": [], "providers": [],
                 "aggregation": {"ok": False, "error": None}}
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
                    c = m.get(host_field(cfg, p)) or m.get("source")
                    if c:
                        names[str(c)] = names.get(str(c), 0) + 1
                r["computers"] = sorted(names, key=lambda n: -names[n])[:10]
            except Exception as exc:
                r["error"] = str(exc)
        out["roles"][role] = r
    # Vorschläge: alle Absender (host.name), dazu die Sammler (`source`),
    # damit sichtbar wird, warum `source` nicht der DC ist.
    beats = f"_exists_:{field('winlog.event_id', p)}"
    hf = host_field(cfg, p)
    out["host_field"] = hf
    for key, fld in (("hosts", hf), ("collectors", "source")):
        try:
            out[key] = [{"name": n, "hits": c} for n, c in await client.aggregate(
                cfg, beats, frm, now, fld, HOSTS_SHOWN if key == "hosts" else 20)]
        except Exception:
            try:
                seen_h: dict[str, int] = {}
                for m in await client.sample(cfg, beats, frm, now, SAMPLE):
                    if m.get(fld):
                        seen_h[str(m[fld])] = seen_h.get(str(m[fld]), 0) + 1
                out[key] = [{"name": n, "hits": c, "sampled": True}
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
