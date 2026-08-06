"""Bearbeitungsstand von Checks: erfolgreich gelaufen ⇒ erledigt."""
from __future__ import annotations

import pytest

from routers.checks import StatusUpdate, apply_status


def _doc() -> dict:
    return {"groups": [{"id": "g1", "name": "OT", "checks": [
        {"id": "c1", "src": "10.1.1.10", "dst": "10.2.1.30",
         "protocol": "tcp", "dst_port": 443, "expect": "ALLOW"},
        {"id": "c2", "src": "10.1.1.10", "dst": "10.2.9.9",
         "protocol": "tcp", "dst_port": 23, "expect": "DENY"},
    ]}]}


def _check(doc: dict, cid: str) -> dict:
    return next(c for c in doc["groups"][0]["checks"] if c["id"] == cid)


def test_erfolgreicher_lauf_markiert_erledigt():
    doc = apply_status(
        _doc(), "g1",
        [StatusUpdate(check_id="c1", record_run=True, actual="ALLOW", ok=True)],
        username="jan", now="2026-08-06T10:00:00+00:00")
    c1 = _check(doc, "c1")
    assert c1["done"] is True
    assert c1["done_at"] == "2026-08-06T10:00:00+00:00"
    assert c1["done_by"] == "jan"
    assert c1["last_run"] == {"at": "2026-08-06T10:00:00+00:00", "actual": "ALLOW",
                              "ok": True, "error": None}


def test_fehlgeschlagener_lauf_markiert_nicht_erledigt():
    doc = apply_status(
        _doc(), "g1",
        [StatusUpdate(check_id="c1", record_run=True, actual="DENY", ok=False)],
        username="jan", now="2026-08-06T10:00:00+00:00")
    c1 = _check(doc, "c1")
    assert c1.get("done") is not True
    assert c1["last_run"]["ok"] is False


def test_erledigt_datiert_auf_den_ersten_gruenen_lauf():
    doc = apply_status(
        _doc(), "g1",
        [StatusUpdate(check_id="c1", record_run=True, actual="ALLOW", ok=True)],
        username="jan", now="2026-08-06T10:00:00+00:00")
    doc = apply_status(
        doc, "g1",
        [StatusUpdate(check_id="c1", record_run=True, actual="ALLOW", ok=True)],
        username="lisa", now="2026-08-07T09:00:00+00:00")
    c1 = _check(doc, "c1")
    assert c1["done_at"] == "2026-08-06T10:00:00+00:00"   # nicht neu gestempelt
    assert c1["done_by"] == "jan"
    assert c1["last_run"]["at"] == "2026-08-07T09:00:00+00:00"


def test_regression_laesst_erledigt_stehen():
    """Fällt ein erledigter Check später um, bleibt done=True — die Regression
    ist am roten last_run erkennbar, der Haken wird nicht still zurückgesetzt."""
    doc = apply_status(
        _doc(), "g1",
        [StatusUpdate(check_id="c1", record_run=True, actual="ALLOW", ok=True)],
        username="jan", now="2026-08-06T10:00:00+00:00")
    doc = apply_status(
        doc, "g1",
        [StatusUpdate(check_id="c1", record_run=True, actual="DENY", ok=False)],
        username="jan", now="2026-08-08T10:00:00+00:00")
    c1 = _check(doc, "c1")
    assert c1["done"] is True
    assert c1["last_run"]["ok"] is False


def test_manuell_erledigen_und_wieder_oeffnen():
    doc = apply_status(_doc(), "g1", [StatusUpdate(check_id="c2", done=True)],
                       username="jan", now="2026-08-06T10:00:00+00:00")
    assert _check(doc, "c2")["done"] is True

    doc = apply_status(doc, "g1", [StatusUpdate(check_id="c2", done=False)],
                       username="jan", now="2026-08-06T11:00:00+00:00")
    c2 = _check(doc, "c2")
    assert c2["done"] is False
    assert c2["done_at"] is None and c2["done_by"] is None


def test_unbekannte_gruppe_und_unbekannter_check():
    with pytest.raises(ValueError):
        apply_status(_doc(), "gX", [StatusUpdate(check_id="c1", done=True)],
                     username="jan", now="2026-08-06T10:00:00+00:00")
    with pytest.raises(ValueError):   # nur gelöschte Checks im Update
        apply_status(_doc(), "g1", [StatusUpdate(check_id="weg", done=True)],
                     username="jan", now="2026-08-06T10:00:00+00:00")


def test_geloeschter_check_wird_uebersprungen_ohne_den_rest_zu_kippen():
    doc = apply_status(
        _doc(), "g1",
        [StatusUpdate(check_id="weg", record_run=True, actual="ALLOW", ok=True),
         StatusUpdate(check_id="c1", record_run=True, actual="ALLOW", ok=True)],
        username="jan", now="2026-08-06T10:00:00+00:00")
    assert _check(doc, "c1")["done"] is True
