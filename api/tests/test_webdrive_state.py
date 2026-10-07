"""Dashboard-Zustand: der Referenzmorgen und die Randfälle."""
from __future__ import annotations

import random

from webdrive.state import build
from webdrive_fixtures import (IDENTITIES, NOW, OA, OD, SINCE, at, events_of, fac, oc,
                               portal_fail, portal_ok, reason,
                               reference_events, sync_run)


def model(events=None, identities=IDENTITIES, now=NOW, since=SINCE):
    return build(reference_events() if events is None else events, identities, now, since)


def by_user(rows):
    return {r["username"]: r for r in rows}


def test_reference_day_problems():
    [p] = model()["problems"]
    assert (p["username"], p["reason"], p["count"]) == ("user-b.ra", "Falsches Passwort", 2)
    assert p["last"] == at("08:22:31").isoformat()


def test_reference_day_hints():
    hints = by_user(model()["hints"])
    assert hints["user-a.ra"]["kind"] == "resolved"
    assert hints["user-a.ra"]["text"] == "Erstanmeldung scheiterte (Name fehlt im AD – Vor- oder Nachname leer), behoben"
    assert hints["user-a.ra"]["ts"] == at("10:43:51").isoformat()
    assert hints["user-d.ra"]["text"] == "1 Fehlversuch (Falsches Passwort), danach erfolgreich"
    # E-Mail statt Username: gelöst durch den späteren Login vom selben Rechner
    assert hints["user.a@partner.example"]["text"] == \
        "1 Fehlversuch (Mit E-Mail statt Username angemeldet), danach erfolgreich"
    # Namens-Korrektur kam VOR der Erstanmeldung → keine Attribut-Warnung
    assert all(h["kind"] != "attr_changed" for h in model()["hints"])


def test_reference_day_sessions():
    m = model()
    assert [r["username"] for r in m["active"]] == ["user-a.ra"]
    assert [r["username"] for r in m["inactive"]] == ["user-e.ra", "user-d.ra"]
    assert m["unknown_sessions"] == 1


def test_reference_day_sync():
    s = model()["sync"]
    assert s["last_run"] == at("10:41:52").isoformat()
    assert (s["users"], s["ok"], s["manual"]) == (25, True, True)
    assert s["last_change"] == {"ts": at("10:41:53").isoformat(), "username": "user-a.ra",
                                "text": "first name, last name", "manual": True}


def test_sync_lines_in_any_order():
    msgs = [m for h in ("06:04:44", "07:04:44", "08:04:44") for m in sync_run(h, 25)]
    random.Random(7).shuffle(msgs)
    s = build(events_of(msgs), {}, NOW, SINCE)["sync"]
    assert (s["last_run"], s["users"], s["ok"], s["manual"]) == (at("08:04:44").isoformat(), 25, True, False)


def test_unresolved_first_login_stays_a_problem():
    evs = [e for e in reference_events() if not (e.kind == "session_seen" and e.opaque_id == OA)]
    probs = by_user(model(evs)["problems"])
    assert probs["user-a.ra"]["reason"] == "Name fehlt im AD – Vor- oder Nachname leer"


def test_active_window_boundary():
    assert [r["username"] for r in model(now=at("11:00:10"))["active"]] == ["user-a.ra"]
    assert model(now=at("11:00:11"))["active"] == []


def test_since_hides_older_trouble():
    m = model(since=at("09:00:00"))
    assert m["problems"] == []
    assert "user-d.ra" not in by_user(m["hints"])
    assert m["sync"]["last_run"] == at("10:41:52").isoformat()   # Sync-Kopf unabhängig vom Zeitraum


def test_virus_found():
    evs = reference_events() + events_of([oc("07:30:00", service="antivirus", message="File scanned", user=OD,
                                             filename="report.pdf", infected=True,
                                             virus="Win.Test.EICAR_HDB-1", outcome="delete")])
    probs = by_user(model(evs)["problems"])
    assert probs["user-d.ra"]["category"] == "file"
    assert probs["user-d.ra"]["reason"] == "Virus gefunden: report.pdf (Win.Test.EICAR_HDB-1), gelöscht"


def test_uploads_are_counted_per_user():
    evs = reference_events() + events_of([oc("10:44:00", service="antivirus", message="File scanned", user=OA,
                                             filename="a.txt", infected=False, outcome="continue")])
    assert by_user(model(evs)["active"])["user-a.ra"]["uploads"] == 1


def test_abandoned_upload_without_user():
    evs = reference_events() + events_of([
        oc("09:00:00", service="storage-users", message="ChunkWriteStart", datatx="tus", id="u-old"),
        oc("10:40:00", service="storage-users", message="ChunkWriteStart", datatx="tus", id="u-new"),
        oc("09:10:00", service="storage-users", message="ChunkWriteStart", datatx="tus", id="u-done"),
        oc("09:10:05", service="storage-users", message="UploadFinished", datatx="tus", id="u-done"),
    ])
    rows = model(evs)["unattributed"]
    assert [(r["reason"], r["detail"]) for r in rows] == [("Upload abgebrochen", "u-old")]


def test_attribute_change_after_first_login_warns_once():
    evs = reference_events() + events_of([
        fac("10:47:00", "10002", "Edited Remote LDAP User: user-e.ra (changed fields: email address)"),
        fac("10:47:00", "10051", "Changed user-e.ra email from e@old.example to e@new.example "
            "from LDAP sync rule", nas="Webdrive-User", user="admin"),
    ])
    hints = [h for h in model(evs)["hints"] if h["kind"] == "attr_changed"]
    assert len(hints) == 1
    assert hints[0]["username"] == "user-e.ra"
    assert hints[0]["text"].endswith("e@old.example → e@new.example")


def test_unknown_reason_is_shown_not_dropped():
    evs = events_of([fac("09:00:01", "20702", "[user-x.ra] has failed to log in OAuth portal[OAuth "
                         "Authentication]. Please check the Radius Authentication log", nas="10.0.8.4")])
    [p] = build(evs, {}, NOW, SINCE)["problems"]
    assert p["reason"] == "Anmeldung fehlgeschlagen (Grund unbekannt)"


def test_empty():
    m = build([], {}, NOW, SINCE)
    assert m["sync"] is None and m["problems"] == [] and m["active"] == []


def test_several_resolved_attempts_make_one_hint():
    evs = events_of([
        reason("05:15:57", "user.a@partner.example", "10.0.8.5", "NAS cannot find user realm", logid="20355"),
        portal_fail("05:15:58", "user.a@partner.example", "10.0.8.5"),
        portal_ok("05:20:00", "user-a.ra", "10.0.8.5"),
        reason("06:38:55", "user.a@partner.example", "10.0.8.5", "NAS cannot find user realm", logid="20355"),
        portal_fail("06:38:56", "user.a@partner.example", "10.0.8.5"),
        portal_ok("06:39:26", "user-a.ra", "10.0.8.5"),
    ])
    hints = [h for h in build(evs, {}, NOW, SINCE)["hints"] if h["username"] == "user.a@partner.example"]
    assert [(h["text"], h["ts"]) for h in hints] == [
        ("2 Fehlversuche (Mit E-Mail statt Username angemeldet), danach erfolgreich", at("06:39:26").isoformat())]
