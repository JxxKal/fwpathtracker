"""Testdaten fürs Webdrive-Dashboard: der Morgen des 07.10.2026 nachgebaut,
anonymisiert (User, IPs, Token-Masken, opaque_ids).

Die Zeilen haben das Format der echten Logs: FAC als `key="value"`-Zeile,
OpenCloud als JSON-Zeile, beide so verpackt, wie Graylog sie über
/api/search/universal/absolute liefert (messages[].message).
"""
from __future__ import annotations

import itertools
import json
from datetime import datetime

CFG = {"oc_ip": "10.0.18.69", "sync_rule": "Webdrive-User"}
DAY = "2026-10-07"
_seq = itertools.count(1)

OA = "0a0a0a0a-0000-4000-8000-00000000000a"
OD = "0d0d0d0d-0000-4000-8000-00000000000d"
OE = "0e0e0e0e-0000-4000-8000-00000000000e"
OX = "0f0f0f0f-0000-4000-8000-00000000000f"


def at(hms: str) -> datetime:
    return datetime.fromisoformat(f"{DAY}T{hms}+00:00")


def fac(hms: str, logid: str, msg: str, *, nas: str = "", user: str = "",
        subcat: str = "Authentication") -> tuple[str, dict]:
    text = (f'date={DAY} time={hms}+0000 oid=1 logid={logid} cat="Event" subcat="{subcat}" '
            f'level="information" nas="{nas}" action="" status="" msg="{msg}" user="{user}" requestid=')
    return ("fac", {"_id": f"m{next(_seq)}", "timestamp": f"{DAY}T{hms}.000Z",
                    "message": text, "source": "fac01"})


def oc(hms: str, **payload) -> tuple[str, dict]:
    body = {"level": "info", **payload, "time": f"{DAY}T{hms}Z"}
    return ("oc", {"_id": f"m{next(_seq)}", "timestamp": f"{DAY}T{hms}.000Z",
                   "message": json.dumps(body), "source": "opencloud"})


def portal_ok(hms: str, user: str, ip: str):
    return fac(hms, "20701", f"[{user}] has successfully logged in OAuth portal[OAuth Authentication]",
               nas=ip, user=user)


def portal_fail(hms: str, entered: str, ip: str):
    return fac(hms, "20702", f"[{entered}] has failed to log in OAuth portal[OAuth Authentication]. "
               "Please check the Radius Authentication log for more details", nas=ip, user=entered)


def reason(hms: str, user: str, ip: str, why: str, logid: str = "20102"):
    return fac(hms, logid, f"Remote LDAP user authentication from {ip}  with no token failed: {why}.",
               nas="FAC_GUI:13", user=user)


def token(hms: str, mask: str, ip: str):
    return fac(hms, "20000", f"Successful OAuth token login ({mask})", nas=ip)


def userinfo(hms: str, mask: str):
    return fac(hms, "20000", f"Successfully returned user info ({mask})", nas=CFG["oc_ip"])


def session(hms: str, opaque: str):
    return oc(hms, service="auth-machine",
              message=f'user idp:"https://fac.example/api/v1/oauth" opaque_id:"{opaque}" '
                      'type:USER_TYPE_PRIMARY authenticated')


def active(times: list[str], mask: str, opaque: str) -> list:
    """Laufende Sitzung: jeder Userinfo-Abruf im FAC fällt auf eine OpenCloud-Sitzung."""
    return [x for h in times for x in (userinfo(h, mask), session(h, opaque))]


def sync_run(hms: str, users: int) -> list:
    rule = CFG["sync_rule"]
    return [
        fac(hms, "30303", f"Performing remote LDAP user sync (rule: {rule}) with dc01.example (10.0.17.37).",
            subcat="System"),
        fac(hms, "30303", f'Retrieved {users} user(s) from the remote LDAP server "dc01.example (10.0.17.37)". '
            f"(sync rule: {rule})", subcat="System"),
        fac(hms, "30303", f"Found 0 modified FTC users for sync (rule: {rule}) with dc01.example (10.0.17.37)",
            subcat="System"),
        fac(hms, "30303", f"Successfully synced (rule: {rule}) with dc01.example on Wed Oct  7 2026.",
            subcat="System"),
    ]


def reference_day() -> list[tuple[str, dict]]:
    a, b, d, e = "user-a.ra", "user-b.ra", "user-d.ra", "user-e.ra"
    msgs: list = []
    for h in ("06:04:44", "07:04:44", "08:04:44", "09:04:44", "10:04:44"):
        msgs += sync_run(h, 25)
    msgs += sync_run("10:41:52", 25)          # manuell angestoßen
    msgs += [
        # Rauschen: andere Sync-Regel, REST-API-Login einer anderen App, toter Browser-Tab
        fac("06:04:44", "30303", "Performing remote LDAP user sync (rule: OT-Users) with dc01.example.",
            subcat="System"),
        fac("05:10:10", "20103", "Remote LDAP user authentication from (null)  with FortiToken failed: "
            "invalid token.", nas="REST API", user=f"ldaps/{a}"),
        fac("05:20:00", "20100", "Failed to send user info due to invalid_token. Reason: The access token "
            "provided is expired, revoked, malformed, or invalid for other reasons.", nas=CFG["oc_ip"]),

        # user-a: erst E-Mail statt Username, dann Erstanmeldung ohne Nachnamen im AD
        reason("05:15:57", "user.a@partner.example", "10.0.8.5", "NAS cannot find user realm", logid="20355"),
        portal_fail("05:15:58", "user.a@partner.example", "10.0.8.5"),
        portal_ok("07:26:32", a, "10.0.8.5"),
        token("07:26:33", "aaa1***************aaa1", "10.0.8.5"),
        userinfo("07:26:33", "aaa1***************aaa1"),
        oc("07:26:33", service="graph", message="could not create user: empty displayname",
           user={"displayName": "", "mail": "user-a.ra@example.com", "onPremisesSamAccountName": a}),
        fac("10:41:53", "10002", f"Edited Remote LDAP User: {a} (changed fields: first name and last name)",
            user=d, subcat="Admin Configuration"),
        portal_ok("10:43:50", a, "10.0.8.4"),
        token("10:43:51", "aaa2***************aaa2", "10.0.8.5"),   # Token über den anderen Knoten
        *active(["10:43:51", "10:44:30", "10:45:10"], "aaa2***************aaa2", OA),

        # user-b: zweimal falsches Passwort, kein Erfolg
        reason("08:22:10", b, "10.0.8.5", "invalid password"),
        portal_fail("08:22:11", b, "10.0.8.5"),
        reason("08:22:30", b, "10.0.8.5", "invalid password"),
        portal_fail("08:22:31", b, "10.0.8.5"),

        # user-d: vertippt, 10 s später drin
        reason("07:23:17", d, "10.0.8.4", "invalid password"),
        portal_fail("07:23:18", d, "10.0.8.4"),
        portal_ok("07:23:28", d, "10.0.8.4"),
        token("07:23:29", "ddd1***************ddd1", "10.0.8.4"),
        *active(["07:23:29", "07:24:10", "07:25:00"], "ddd1***************ddd1", OD),

        # user-e: normaler Login
        portal_ok("10:12:59", e, "10.0.21.66"),
        token("10:12:59", "eee1***************eee1", "10.0.21.66"),
        *active(["10:12:59", "10:13:40"], "eee1***************eee1", OE),

        # Sitzung ohne Portal-Login (Desktop-Client, Token-Refresh)
        session("10:48:07", OX),
    ]
    return msgs


def events_of(messages: list[tuple[str, dict]]) -> list:
    from webdrive.parse import parse_message
    evs = [parse_message(src, m, CFG) for src, m in messages]
    return sorted([e for e in evs if e], key=lambda e: e.ts)


def reference_events() -> list:
    return events_of(reference_day())


NOW = at("10:50:00")
SINCE = at("00:00:00")
IDENTITIES = {
    OA: ("user-a.ra", at("10:43:51")),
    OD: ("user-d.ra", at("07:23:29")),
    OE: ("user-e.ra", at("10:12:59")),
}
