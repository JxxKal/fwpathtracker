"""Parser: echte (anonymisierte) Logzeilen → normierte Ereignisse."""
from __future__ import annotations

from secrets_mask import SENTINEL, mask_secrets, merge_secrets
from webdrive.parse import normalize_user, parse_kv, parse_message
from webdrive_fixtures import (CFG, OA, events_of, fac, oc, portal_fail, portal_ok,
                               reason, reference_events, session, sync_run, token, userinfo)


def one(msg):
    evs = events_of([msg])
    assert len(evs) <= 1
    return evs[0] if evs else None


def test_config_key_token_masked():
    assert mask_secrets("webdrive", {"token": "abc", "base_url": "x"}) == {"token": SENTINEL, "base_url": "x"}
    assert merge_secrets("webdrive", {"token": SENTINEL}, {"token": "abc"})["token"] == "abc"


def test_normalize_user():
    assert normalize_user("OP-TECH\\User-A.RA") == "user-a.ra"
    assert normalize_user("ldaps/user-a.ra") == "user-a.ra"
    assert normalize_user("User.A@Partner.example") == "user.a@partner.example"
    assert normalize_user("") is None


def test_parse_kv_message_with_inner_quotes():
    kv = parse_kv('logid=30303 nas="" msg="Retrieved 25 user(s) from the remote LDAP server '
                  '"dc01 (10.0.17.37)". (sync rule: Webdrive-User)" user="" requestid=')
    assert kv["logid"] == "30303"
    assert kv["msg"].endswith("(sync rule: Webdrive-User)")
    assert kv["user"] == ""


def test_portal_login_ok_and_failed():
    ok = one(portal_ok("07:23:28", "User-D.ra", "10.0.8.4"))
    assert (ok.kind, ok.username, ok.data["client_ip"]) == ("portal_login_ok", "user-d.ra", "10.0.8.4")
    bad = one(portal_fail("05:16:17", "op-tech\\user-a.ra", "10.0.8.5"))
    assert (bad.kind, bad.username, bad.data["entered"]) == ("portal_login_failed", "user-a.ra",
                                                              "op-tech\\user-a.ra")


def test_failure_reasons():
    ev = one(reason("07:23:17", "user-d.ra", "10.0.8.4", "invalid password"))
    assert (ev.kind, ev.username, ev.data["reason"]) == ("auth_failed_reason", "user-d.ra", "invalid password")
    ev = one(reason("05:16:16", "op-tech\\user-a.ra", "10.0.8.5", "user not filtered by groups", logid="20324"))
    assert ev.data["reason"] == "user not filtered by groups"
    ev = one(fac("13:22:05", "20100", "OAuth authentication failed for for a remote user (user-x.ot) "
                 "who has not been imported", user="user-x.ot"))
    assert (ev.kind, ev.data["reason"]) == ("auth_failed_reason", "not imported")


def test_rest_api_logins_of_other_apps_are_dropped():
    assert one(fac("05:10:10", "20103", "Remote LDAP user authentication from (null)  with FortiToken "
                   "failed: invalid token.", nas="REST API", user="ldaps/user-a.ra")) is None


def test_token_and_userinfo():
    ev = one(token("10:43:51", "aaa2***************aaa2", "10.0.8.5"))
    assert (ev.kind, ev.token) == ("token_issued", "aaa2***************aaa2")
    ev = one(userinfo("10:43:51", "aaa2***************aaa2"))
    assert (ev.kind, ev.token) == ("userinfo_ok", "aaa2***************aaa2")
    # Userinfo für einen anderen Client als OpenCloud zählt nicht
    assert one(fac("10:43:51", "20000", "Successfully returned user info (x)", nas="10.9.9.9")) is None


def test_invalid_token_noise_is_dropped():
    assert one(fac("05:20:00", "20100", "Failed to send user info due to invalid_token. Reason: x",
                   nas=CFG["oc_ip"])) is None


def test_sync_run_only_for_configured_rule():
    kinds = [e.kind for e in events_of(sync_run("10:04:44", 25))]
    assert kinds == ["sync_start", "sync_retrieved", "sync_modified", "sync_ok"]
    assert one(fac("06:04:44", "30303", "Performing remote LDAP user sync (rule: OT-Users) with dc01.",
                   subcat="System")) is None


def test_attribute_changes():
    ev = one(fac("10:41:53", "10002", "Edited Remote LDAP User: user-a.ra (changed fields: first name "
                 "and last name)", user="user-d.ra"))
    assert (ev.kind, ev.username, ev.data["fields"]) == ("attr_changed", "user-a.ra", ["first name", "last name"])
    ev = one(fac("07:04:45", "10051", "Changed user-a.ra email from a@old.example to user-a.ra@example.com "
                 "from LDAP sync rule", nas="Webdrive-User", user="admin"))
    assert (ev.username, ev.data["fields"], ev.data["old"], ev.data["new"]) == (
        "user-a.ra", ["email"], "a@old.example", "user-a.ra@example.com")
    ev = one(fac("07:04:45", "10001", "Added Remote LDAP User: user-z.ot"))
    assert (ev.kind, ev.username) == ("user_added", "user-z.ot")


def test_provision_failed_reason_from_empty_field():
    def prov(**user):
        return one(oc("07:26:33", service="graph", message="could not create user: empty displayname",
                      user={"displayName": "A B", "mail": "a@example.com",
                            "onPremisesSamAccountName": "user-a.ra", **user}))
    assert prov(displayName="").data["reason"] == "displayname"
    assert prov(mail="").data["reason"] == "mail"
    ev = prov(onPremisesSamAccountName="")
    assert (ev.data["reason"], ev.username) == ("sam", "a@example.com")
    assert prov(displayName="").username == "user-a.ra"


def test_session_seen():
    ev = one(session("10:43:51", OA))
    assert (ev.kind, ev.opaque_id) == ("session_seen", OA)
    # Service-Accounts sind keine User-Sitzungen
    assert one(oc("10:00:00", service="auth-machine",
                  message='user idp:"internal" opaque_id:"x" type:USER_TYPE_SERVICE authenticated')) is None


def test_file_events():
    ev = one(oc("05:28:59", service="antivirus", message="File scanned", user=OA,
                filename="report.pdf", infected=True, virus="Win.Test.EICAR_HDB-1", outcome="delete"))
    assert (ev.kind, ev.opaque_id, ev.data["infected"], ev.data["virus"]) == (
        "file_scanned", OA, True, "Win.Test.EICAR_HDB-1")
    ev = one(oc("09:00:00", service="proxy", message="access-log", method="PUT", status=413,
                path="/dav/spaces/abc/big.iso"))
    assert (ev.kind, ev.data["reason"]) == ("upload_failed", "too_large")
    assert one(oc("09:00:00", service="proxy", message="access-log", method="GET", status=404,
                  path="/dav/spaces/abc")) is None
    ev = one(oc("09:00:00", service="storage-users", message="ChunkWriteStart", datatx="tus", id="u1"))
    assert (ev.kind, ev.data["upload_id"]) == ("upload_started", "u1")
    ev = one(oc("09:00:00", service="postprocessing", level="error", message="step failed"))
    assert ev.kind == "file_error"


def test_storage_noise_is_not_a_file_problem():
    assert one(oc("09:00:00", service="storage-users", level="error",
                  message="failed to handle moved away item")) is None


def test_oc_fields_already_extracted_by_graylog():
    """Hat Graylog die JSON-Felder zerlegt, steht in `message` nur noch der Text."""
    m = {"_id": "x1", "timestamp": "2026-10-07T10:43:51.000Z", "message": "File scanned",
         "service": "antivirus", "user": OA, "filename": "a.txt", "infected": False}
    ev = parse_message("oc", m, CFG)
    assert (ev.kind, ev.opaque_id, ev.data["filename"]) == ("file_scanned", OA, "a.txt")


def test_fac_fields_already_extracted_by_graylog():
    m = {"_id": "x2", "timestamp": "2026-10-07T07:23:28.000Z",
         "message": "[user-d.ra] has successfully logged in OAuth portal[OAuth Authentication]",
         "logid": "20701", "msg": "[user-d.ra] has successfully logged in OAuth portal[OAuth Authentication]",
         "nas": "10.0.8.4"}
    ev = parse_message("fac", m, CFG)
    assert (ev.kind, ev.username) == ("portal_login_ok", "user-d.ra")


def test_message_without_id_or_timestamp_is_dropped():
    assert parse_message("fac", {"message": "x"}, CFG) is None


def test_reference_day_parses_without_noise():
    evs = reference_events()
    assert all(e.username != "ldaps/user-a.ra" for e in evs)
    assert sum(e.kind == "provision_failed" for e in evs) == 1
    assert sum(e.kind == "sync_start" for e in evs) == 6


# ── Syslog-Format, wie es in Graylog ankommt (OT-Prod-Offline, 07.10.2026) ────

def syslog(text: str, gl_id: str = "s1"):
    return parse_message("auto", {"_id": gl_id, "timestamp": "2026-10-07T15:05:14.583Z",
                                  "message": text, "source": "svo3038-ot"}, CFG)


def test_syslog_userinfo():
    ev = syslog('svo3038-ot db[18260]: category="Event" subcategory="Authentication" typeid=20000 '
                'level="information" user="" nas="10.0.18.69" userip="10.0.18.69" action="" status="" '
                'Successfully returned user info (CETa***************hCsn)')
    assert (ev.source, ev.kind, ev.token) == ("fac", "userinfo_ok", "CETa***************hCsn")


def test_syslog_portal_login():
    ev = syslog('svo3038-ot db[18260]: category="Event" subcategory="Authentication" typeid=20701 '
                'level="information" user="user-d.ra" nas="10.0.8.4" userip="10.0.8.4" action="Login" '
                'status="Success" [user-d.ra] has successfully logged in OAuth portal[OAuth Authentication]')
    assert (ev.kind, ev.username, ev.data["client_ip"]) == ("portal_login_ok", "user-d.ra", "10.0.8.4")


def test_syslog_failure_reason_and_sync():
    ev = syslog('svo3038-ot db[1]: category="Event" subcategory="Authentication" typeid=20102 '
                'level="information" user="user-d.ra" nas="FAC_GUI:13" userip="" action="Authentication" '
                'status="Failed" Remote LDAP user authentication from 10.0.8.4  with no token failed: invalid password.')
    assert (ev.kind, ev.data["reason"]) == ("auth_failed_reason", "invalid password")
    ev = syslog('svo3038-ot db[1]: category="Event" subcategory="System" typeid=30303 level="information" '
                'user="" nas="" userip="" action="" status="" Retrieved 25 user(s) from the remote LDAP server '
                '"dc01 (10.0.17.37)". (sync rule: Webdrive-User)')
    assert (ev.kind, ev.data["users"]) == ("sync_retrieved", 25)


def test_syslog_rest_debug_lines_are_dropped():
    assert syslog("svo3038-ot rest_api_dbg_log: 2026-10-07 15:05:14,582 debug 18260 140406809409216 "
                  "Userinfo access valid for <oauthlib.Request SANITIZED>.") is None


def test_auto_detects_opencloud_json():
    m = {"_id": "o1", "timestamp": "2026-10-07T15:05:14.537Z", "source": "svo3120-ot",
         "message": '{"level":"info","service":"auth-machine","message":"user idp:\\"https://fac/oauth\\" '
                    'opaque_id:\\"59aeb4b1\\" type:USER_TYPE_PRIMARY authenticated"}'}
    ev = parse_message("auto", m, CFG)
    assert (ev.source, ev.kind, ev.opaque_id) == ("oc", "session_seen", "59aeb4b1")
