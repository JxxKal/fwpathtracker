"""Graylog-Nachricht → normiertes Webdrive-Ereignis.

Gespeichert wird nur, was das Dashboard braucht, keine Rohzeilen. Jede
Nachricht wird zu höchstens einem Ereignis oder verworfen (None) — das ist die
einzige Stelle, die die Logformate von FAC und OpenCloud kennt.

Der FAC schreibt `key="value"`-Zeilen, OpenCloud JSON-Zeilen. Graylog legt die
Rohzeile im Feld `message` ab; hat eine Extraktion die Felder schon zerlegt,
werden diese ergänzend genutzt.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class Event:
    gl_id: str
    ts: datetime
    source: str                 # 'fac' | 'oc'
    kind: str
    username: str | None = None
    token: str | None = None    # FAC-Token-Maske, z. B. 'rzrA***************UdUR'
    opaque_id: str | None = None
    data: dict = field(default_factory=dict)


def normalize_user(raw: str | None) -> str | None:
    """Vergleichsform: klein, ohne Domänen-/Realm-Präfix (`op-tech\\`, `ldaps/`)."""
    if not raw:
        return None
    u = raw.strip().lower()
    for sep in ("\\", "/"):
        if sep in u:
            u = u.rsplit(sep, 1)[1]
    return u or None


# Der FAC kennt zwei Formate:
#  Log-Export:  … logid=20000 cat="Event" subcat="…" nas="…" action="" status="" msg="…" user="…" requestid=
#  Syslog:      svo3038-ot db[18260]: category="Event" subcategory="…" typeid=20000 level="…" user="" nas="…"
#               userip="…" action="" status="" Successfully returned user info (…)
# msg="…" kann selbst Anführungszeichen enthalten ("… server "dc01" …"); die
# Felder danach sind immer user="…" requestid=…, also bis dorthin gierig lesen.
# Im Syslog-Format steht der Text ohne Schlüssel hinter status="…".
_MSG = re.compile(r'\bmsg="(?P<msg>.*)"\s+user="(?P<user>[^"]*)"')
_TAIL = re.compile(r'\bstatus="[^"]*"[ \t]*(?P<msg>.*)$')
_KV = re.compile(r'(\w+)="([^"]*)"|(\w+)=(\S+)')
_ALIASES = {"typeid": "logid", "category": "cat", "subcategory": "subcat"}


def parse_kv(text: str) -> dict[str, str]:
    out: dict[str, str] = {}
    text = text.strip()
    m = _MSG.search(text)
    tail = None if m else _TAIL.search(text)
    head = text[: m.start()] if m else text[: tail.start("msg")] if tail else text
    for k1, v1, k2, v2 in _KV.findall(head):
        k, v = (k1, v1) if k1 else (k2, v2)
        out[_ALIASES.get(k, k)] = v
    if m:
        out["msg"] = m.group("msg")
        out["user"] = m.group("user")
    elif tail and tail.group("msg"):
        out["msg"] = tail.group("msg")
    return out


# ── FAC ───────────────────────────────────────────────────────────────────────

_PORTAL_OK = re.compile(r"^\[(?P<u>[^\]]+)\] has successfully logged in OAuth portal")
_PORTAL_FAIL = re.compile(r"^\[(?P<u>[^\]]+)\] has failed to log in OAuth portal")
_FAIL_REASON = re.compile(r"failed: (?P<r>.+?)\.?$")
_TOKEN = re.compile(r"^Successful OAuth token login \((?P<t>[^)]+)\)")
_USERINFO = re.compile(r"^Successfully returned user info \((?P<t>[^)]+)\)")
_RETRIEVED = re.compile(r"Retrieved (?P<n>\d+) user")
_MODIFIED = re.compile(r"Found (?P<n>\d+) modified")
_ADDED = re.compile(r"^Added Remote LDAP User: (?P<u>\S+)")
_EDITED = re.compile(r"^Edited Remote LDAP User: (?P<u>\S+) \(changed fields: (?P<f>[^)]+)\)")
_SYNC_SET = re.compile(r"^(?:Set|Changed) (?P<u>\S+) (?P<attr>[\w ]+?) "
                       r"(?:from (?P<old>\S+) )?to (?P<new>\S+) from LDAP sync rule")
# Gründe, die der FAC eine Sekunde vor dem fehlgeschlagenen Portal-Login schreibt
_REASON_LOGIDS = {"20102", "20103", "20104", "20324", "20355"}


def parse_fac(gl_id: str, ts: datetime, kv: dict[str, str],
              oc_ip: str, sync_rule: str) -> Event | None:
    logid = kv.get("logid", "")
    msg = kv.get("msg", "")
    nas = kv.get("nas", "")
    user = kv.get("user", "")

    def ev(kind: str, **kw) -> Event:
        return Event(gl_id, ts, "fac", kind, **kw)

    if logid == "20701" and (m := _PORTAL_OK.match(msg)):
        return ev("portal_login_ok", username=normalize_user(m["u"]),
                  data={"client_ip": nas})
    if logid == "20702" and (m := _PORTAL_FAIL.match(msg)):
        return ev("portal_login_failed", username=normalize_user(m["u"]),
                  data={"client_ip": nas, "entered": m["u"]})
    if logid == "20100" and "has not been imported" in msg:
        return ev("auth_failed_reason", username=normalize_user(user),
                  data={"reason": "not imported"})
    # Nur Logins über das Portal (FAC_GUI); REST-API-Logins anderer Apps nicht.
    if logid in _REASON_LOGIDS and nas.startswith("FAC_GUI") and (m := _FAIL_REASON.search(msg)):
        return ev("auth_failed_reason", username=normalize_user(user),
                  data={"reason": m["r"]})
    if logid == "20000":
        if m := _TOKEN.match(msg):
            return ev("token_issued", token=m["t"], data={"client_ip": nas})
        if (m := _USERINFO.match(msg)) and nas == oc_ip:
            return ev("userinfo_ok", token=m["t"])
        return None
    if logid == "30303" and f"rule: {sync_rule})" in msg:
        if msg.startswith("Performing remote LDAP user sync"):
            return ev("sync_start")
        if m := _RETRIEVED.search(msg):
            return ev("sync_retrieved", data={"users": int(m["n"])})
        if m := _MODIFIED.search(msg):
            return ev("sync_modified", data={"modified": int(m["n"])})
        if msg.startswith("Successfully synced"):
            return ev("sync_ok")
        if "fail" in msg.lower() or "error" in msg.lower():
            return ev("sync_failed", data={"msg": msg})
        return None
    if logid == "10001" and (m := _ADDED.match(msg)):
        return ev("user_added", username=normalize_user(m["u"]))
    if logid == "10002" and (m := _EDITED.match(msg)):
        fields = [f for f in re.split(r",\s*|\s+and\s+", m["f"]) if f]
        return ev("attr_changed", username=normalize_user(m["u"]), data={"fields": fields})
    if logid in ("10050", "10051") and nas == sync_rule and (m := _SYNC_SET.match(msg)):
        return ev("attr_changed", username=normalize_user(m["u"]),
                  data={"fields": [m["attr"]], "old": m["old"], "new": m["new"]})
    if "locked out" in msg.lower() and user:
        return ev("user_locked", username=normalize_user(user))
    return None


# ── OpenCloud ─────────────────────────────────────────────────────────────────

_OPAQUE = re.compile(r'opaque_id:"(?P<id>[^"]+)"')
_UPLOAD_PATHS = ("/dav/", "/data/", "/remote.php/")
_UPLOAD_STATUS = {400: "name", 413: "too_large", 423: "locked", 507: "quota"}
# Reihenfolge = Priorität: was OpenCloud als erstes leer vorfindet
_PROVISION_FIELDS = (("displayName", "displayname"), ("mail", "mail"),
                     ("onPremisesSamAccountName", "sam"))


def parse_oc(gl_id: str, ts: datetime, p: dict) -> Event | None:
    svc = p.get("service")
    msg = str(p.get("message") or "")

    def ev(kind: str, **kw) -> Event:
        return Event(gl_id, ts, "oc", kind, **kw)

    if svc == "graph" and msg.startswith("could not create user"):
        u = p.get("user") if isinstance(p.get("user"), dict) else {}
        reason = next((code for key, code in _PROVISION_FIELDS if not u.get(key)), "unknown")
        name = normalize_user(u.get("onPremisesSamAccountName") or u.get("mail"))
        return ev("provision_failed", username=name, data={"reason": reason, "detail": msg})
    if svc == "auth-machine" and "USER_TYPE_PRIMARY authenticated" in msg:
        m = _OPAQUE.search(msg)
        return ev("session_seen", opaque_id=m["id"]) if m else None
    if svc == "antivirus":
        if msg == "File scanned":
            return ev("file_scanned", opaque_id=p.get("user") or None, data={
                "filename": p.get("filename") or "", "infected": bool(p.get("infected")),
                "virus": p.get("virus") or "", "outcome": p.get("outcome") or "",
            })
        if "max scan size" in msg.lower() or "skip" in msg.lower():
            return ev("scan_skipped", opaque_id=p.get("user") or None,
                      data={"filename": p.get("filename") or ""})
        if p.get("level") == "error":
            return ev("file_error", data={"service": svc, "detail": msg})
        return None
    if svc == "postprocessing" and p.get("level") == "error":
        return ev("file_error", data={"service": svc, "detail": msg})
    if svc == "proxy" and msg == "access-log" and p.get("method") in ("PUT", "POST", "PATCH"):
        status = int(p.get("status") or 0)
        path = str(p.get("path") or "")
        if status in _UPLOAD_STATUS and path.startswith(_UPLOAD_PATHS):
            return ev("upload_failed", data={"status": status,
                                             "reason": _UPLOAD_STATUS[status], "path": path})
        return None
    if svc == "storage-users" and p.get("datatx") == "tus" and p.get("id"):
        if msg == "ChunkWriteStart":
            return ev("upload_started", data={"upload_id": p["id"]})
        if msg == "UploadFinished":
            return ev("upload_finished", data={"upload_id": p["id"]})
    return None


# ── Einstieg ──────────────────────────────────────────────────────────────────

def parse_ts(raw) -> datetime | None:
    if not raw:
        return None
    try:
        return datetime.fromisoformat(str(raw).replace("Z", "+00:00"))
    except ValueError:
        return None


def detect_source(m: dict) -> str:
    """OpenCloud schreibt JSON-Zeilen (oder Graylog hat daraus Felder wie
    `service` gemacht), alles andere ist FAC. So reicht ein gemeinsamer Stream."""
    text = str(m.get("message") or "").lstrip()
    return "oc" if text.startswith("{") or "service" in m else "fac"


def parse_message(source: str, m: dict, cfg: dict) -> Event | None:
    """Graylog-Nachricht (das Objekt unter messages[].message) → Ereignis.
    source: 'fac', 'oc' oder 'auto' (am Inhalt erkennen)."""
    gl_id = str(m.get("_id") or "")
    ts = parse_ts(m.get("timestamp"))
    if not gl_id or ts is None:
        return None
    if source == "auto":
        source = detect_source(m)
    text = str(m.get("message") or "")
    fields = {k: v for k, v in m.items() if not k.startswith("_")}
    if source == "fac":
        kv = {k: str(v) for k, v in fields.items()}
        kv.update(parse_kv(text))
        return parse_fac(gl_id, ts, kv, str(cfg.get("oc_ip") or ""),
                         str(cfg.get("sync_rule") or "Webdrive-User"))
    if source == "oc":
        payload = None
        if text.lstrip().startswith("{"):
            try:
                payload = json.loads(text)
            except ValueError:
                payload = None
        if not isinstance(payload, dict):
            payload = fields
        return parse_oc(gl_id, ts, payload)
    return None
