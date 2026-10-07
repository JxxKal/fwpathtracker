"""Korrelation Username ↔ Token ↔ opaque_id."""
from __future__ import annotations

from webdrive.correlate import map_tokens, new_identities, pair_failures
from webdrive_fixtures import (IDENTITIES, OA, OD, OE, OX, active, events_of, portal_fail,
                               portal_ok, reason, reference_events, session, token)


def test_failures_get_their_reason():
    fs = {(f.username, f.reason) for f in pair_failures(reference_events())}
    assert ("user-d.ra", "invalid password") in fs
    assert ("user.a@partner.example", "NAS cannot find user realm") in fs


def test_failure_without_reason_line():
    [f] = pair_failures(events_of([portal_fail("09:00:00", "user-x.ra", "10.0.8.4")]))
    assert f.reason == ""


def test_reason_of_another_user_is_not_taken():
    evs = events_of([reason("09:00:00", "user-y.ra", "10.0.8.4", "invalid password"),
                     portal_fail("09:00:01", "user-x.ra", "10.0.8.4")])
    assert pair_failures(evs)[0].reason == ""


def test_token_mapping_tolerates_other_node():
    tokens = map_tokens(reference_events())
    assert tokens["aaa2***************aaa2"] == "user-a.ra"     # Login .4, Token .5
    assert tokens["eee1***************eee1"] == "user-e.ra"


def test_two_logins_in_the_same_second_are_not_guessed():
    evs = events_of([portal_ok("09:00:00", "user-x.ra", "10.0.8.4"),
                     portal_ok("09:00:00", "user-y.ra", "10.0.8.5"),
                     token("09:00:01", "tok1", "10.0.8.6")])
    assert "tok1" not in map_tokens(evs)


def test_identities_of_the_reference_day():
    assert new_identities(reference_events(), known=set()) == IDENTITIES


def test_known_identities_are_not_remapped():
    assert new_identities(reference_events(), known={OA, OD, OE}) == {}


def test_rejected_first_login_gets_no_identity():
    """1 Userinfo-Abruf (Erstanmeldung abgelehnt) + zufällig gleichzeitige Sitzung
    eines anderen Users darf keine Zuordnung erzeugen."""
    evs = events_of([portal_ok("09:00:00", "user-x.ra", "10.0.8.4"),
                     token("09:00:01", "tok1", "10.0.8.4"),
                     *active(["09:00:01"], "tok1", OX)])
    assert new_identities(evs, known=set()) == {}


def test_busy_other_user_does_not_steal_the_mapping():
    """Ein Dauernutzer mit Sitzungen im Sekundentakt trifft zufällig einmal
    einen Abruf — der echte Partner trifft alle."""
    noise = [session(f"09:00:{s:02d}", OX) for s in range(0, 60, 5)]
    evs = events_of([portal_ok("09:00:00", "user-x.ra", "10.0.8.4"),
                     token("09:00:01", "tok1", "10.0.8.4"),
                     *active(["09:00:05", "09:00:32", "09:00:48"], "tok1", OA),
                     *noise])
    assert new_identities(evs, known=set())[OA][0] == "user-x.ra"
    assert OX not in new_identities(evs, known=set())


def test_token_a_few_seconds_after_login():
    """Am 07.10.2026 kam ein Token 4 s nach dem Portal-Login."""
    evs = events_of([portal_ok("10:43:47", "user-a.ra", "10.0.8.4"),
                     token("10:43:51", "tok1", "10.0.8.4")])
    assert map_tokens(evs) == {"tok1": "user-a.ra"}
