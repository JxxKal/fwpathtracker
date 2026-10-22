"""Wochenreport: Zeitfenster, Kapitel-Auswertungen, Querabgleich, Gesamtlauf."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from report import build, chapters as ch, period, winlog_chapters as wch
from webdrive.parse import Event

CFG = {"enabled": True, "weekday": 4, "time": "06:30", "timezone": "Europe/Berlin"}
# Freitag, 23.10.2026 06:30 Berlin = 04:30 UTC (Sommerzeit)
SLOT = datetime(2026, 10, 23, 4, 30, tzinfo=timezone.utc)
START = SLOT - timedelta(days=7)


def at(day: int, hour: int, minute: int = 0) -> datetime:
    """Ortszeit Berlin (UTC+2 im Oktober bis zum 25.)."""
    return datetime(2026, 10, day, hour, minute, tzinfo=timezone.utc) - timedelta(hours=2)


def test_last_slot_and_due_windows_are_gapless():
    assert period.last_slot(SLOT + timedelta(minutes=1), CFG) == SLOT
    assert period.last_slot(SLOT - timedelta(minutes=1), CFG) == SLOT - timedelta(days=7)
    assert period.due(SLOT + timedelta(hours=1), CFG, None) == [(START, SLOT)]
    assert period.due(SLOT + timedelta(hours=1), CFG, SLOT) == []
    # Zwei Läufe verpasst → zwei Berichte, nahtlos.
    two = period.due(SLOT + timedelta(hours=1), CFG, SLOT - timedelta(days=14))
    assert two == [(SLOT - timedelta(days=14), START), (START, SLOT)]
    assert period.due(SLOT, {**CFG, "enabled": False}, None) == []


def test_label_days_and_off_hours():
    lb = period.label(START, SLOT, CFG)
    assert lb["kw"] == "KW 43/2026" and lb["from"] == "16.10.2026 06:30"
    days = period.days(START, SLOT, CFG)
    assert len(days) == 8 and days[0]["label"] == "Fr 16.10." and days[-1]["label"] == "Fr 23.10."
    assert period.off_hours(at(17, 10), CFG) == "Wochenende"
    assert period.off_hours(at(20, 23), CFG) == "nachts"
    assert period.off_hours(at(20, 10), CFG) is None


def ctx():
    return ch.Ctx(START, SLOT, CFG)


def test_firewall_chapter_counts_changes_and_flags_off_hours():
    logs = [
        {"cfgpath": "firewall.policy", "cfgobj": "12", "action": "Edit", "user": "jan",
         "devname": "fw-a", "vd": "root", "t": at(20, 10)},
        {"cfgpath": "firewall.address", "cfgobj": "h1", "action": "Add", "user": "jan",
         "devname": "fw-b", "vd": "root", "t": at(18, 3)},          # Sonntag
        {"logdesc": "Admin login successful", "user": "jan", "t": at(20, 9)},   # keine Änderung
        {"cfgpath": "x", "t": START - timedelta(hours=1)},          # außerhalb
    ]
    c = ch.firewall_chapter(logs, ctx(), log_time=lambda r: r["t"])
    assert c["kpis"][0]["value"] == 2 and c["kpis"][1]["value"] == 1
    assert c["tables"][0]["rows"][0][1] == "fw-b"
    assert c["attention"][0]["title"].startswith("Firewall-Änderung Wochenende: fw-b")
    assert sum(c["daily"]) == 2 and c["status"] == "ok"
    partial = ch.firewall_chapter(logs, ctx(), log_time=lambda r: r["t"], total=9000)
    assert partial["status"] == "partial"


def test_hosts_chapter_marks_unmanaged_and_warns_about_young_history():
    arp = {"history_start": START - timedelta(days=30), "seen": 10,
           "new": [{"mac": "aa", "ip": "10.0.0.5", "first_seen": at(19, 9), "device": "fw-a",
                    "interface": "lan"},
                   {"mac": "bb", "ip": "10.0.0.6", "first_seen": at(20, 9), "device": "fw-a",
                    "interface": "lan"}],
           "gone": [{"mac": "cc", "ip": "10.0.0.7", "last_seen": at(15, 9), "device": "fw-a"}]}
    names = [{"ip": "10.0.0.5", "name": "neu01", "first_seen": at(19, 10)}]
    c = ch.hosts_chapter(arp, names, ctx(), itop_ips={"10.0.0.6"}, zabbix_ips=set())
    assert [k["value"] for k in c["kpis"]] == [2, 1, 1]
    assert "neu01" in c["attention"][0]["title"]
    young = ch.hosts_chapter({**arp, "history_start": at(19, 0)}, names, ctx(),
                             itop_ips=set(), zabbix_ips=set())
    assert young["status"] == "partial" and young["attention"] == []


def test_zabbix_chapter_durations_open_and_severity():
    ev = [{"clock": int(at(19, 10).timestamp()), "r_clock": int(at(19, 12).timestamp()),
           "severity": "4", "name": "Disk voll", "hosts": [{"name": "srv1"}]},
          {"clock": int(at(21, 8).timestamp()), "r_clock": None, "severity": "5",
           "name": "Host down", "hosts": [{"name": "srv2"}], "acknowledged": "0"},
          {"clock": int(at(21, 9).timestamp()), "r_clock": None, "severity": "2",
           "name": "Last", "hosts": [{"name": "srv1"}]}]
    c = ch.zabbix_chapter(ev, ctx())
    assert [k["value"] for k in c["kpis"]] == [3, 2, 2]
    assert c["tables"][0]["rows"][0][1] == "srv2"                 # längstes zuerst
    assert c["attention"][0]["level"] == "high" and "srv2" in c["attention"][0]["title"]
    assert c["charts"][0]["series"][0]["label"] == "Katastrophe"


def test_librenms_chapter_classifies_events():
    rows = [{"datetime": "2026-10-19 10:00:00", "hostname": "sw1", "type": "interface",
             "message": "ifOperStatus: up -> down"},
            {"datetime": "2026-10-19 10:05:00", "hostname": "sw1", "type": "interface",
             "message": "ifOperStatus: down -> up"},
            {"datetime": "2026-10-20 03:00:00", "hostname": "sw2", "type": "system",
             "message": "Device rebooted after 12 days"}]
    c = ch.librenms_chapter(rows, ctx())
    assert [k["value"] for k in c["kpis"]] == [1, 1]
    assert c["attention"][0]["title"] == "Neustart: sw2"


def test_webdrive_chapter():
    ev = [Event("1", at(19, 9), "fac", "portal_login_ok", "u1"),
          Event("2", at(19, 9), "fac", "portal_login_failed", "u2"),
          Event("3", at(20, 9), "oc", "upload_finished", "u1")]
    c = ch.webdrive_chapter(ev, ctx())
    assert [k["value"] for k in c["kpis"]] == [1, 1]


def test_ad_rows_name_members_and_alert_on_privileged_groups():
    p = "winlogbeat_"
    msgs = [{"timestamp": "2026-10-19T08:00:00.000Z", "winlogbeat_winlog_event_id": "4728",
             "winlogbeat_winlog_event_data_TargetUserName": "Domain Admins",
             "winlogbeat_winlog_event_data_MemberName": "CN=Max Muster,OU=x,DC=corp",
             "winlogbeat_winlog_event_data_SubjectUserName": "admin1",
             "winlogbeat_host_name": "DC01.corp"},
            {"timestamp": "2026-10-19T09:00:00.000Z", "winlogbeat_winlog_event_id": "4720",
             "winlogbeat_winlog_event_data_TargetUserName": "neu.user",
             "winlogbeat_winlog_event_data_SubjectUserName": "admin1"},
            {"timestamp": "2026-10-19T10:00:00.000Z", "winlogbeat_winlog_event_id": "1102"},
            {"timestamp": "2026-10-19T11:00:00.000Z", "winlogbeat_winlog_event_id": "4625"}]
    rows, attention = wch.ad_rows(msgs, p, ctx(), {"domain admins"})
    assert len(rows) == 3
    assert rows[0][2] == "Max Muster" and rows[0][3] == "Domain Admins" and rows[0][5] == "DC01.corp"
    assert [a["level"] for a in attention] == ["high", "high"]
    assert attention[0]["title"].startswith("Privilegierte Gruppe Domain Admins")


def test_cross_check_links_outage_to_preceding_firewall_change():
    chapters = {"firewall": {"_changes": [{"ts": at(19, 10).isoformat(), "device": "fw-a"}]},
                "zabbix": {"_high": [{"ts": at(19, 10, 40).isoformat(), "host": "srv1",
                                      "name": "down"},
                                     {"ts": at(19, 13).isoformat(), "host": "srv2",
                                      "name": "down"}]}}
    out = build.cross_checks(chapters, ctx())
    assert len(out) == 1 and "srv1" in out[0]["title"] and "fw-a" in out[0]["why"]


def test_summary_tiles_with_previous_week_and_status():
    chs = [{"status": "ok", "kpis": [{"key": "fw_changes", "label": "x", "value": 5}]},
           {"status": "off", "kpis": []},
           {"status": "error", "kpis": []}]
    prev = {"summary": {"kpis": [{"key": "fw_changes", "value": 3}]}}
    s = build.summarize(chs, prev)
    assert s["kpis"] == [{"key": "fw_changes", "label": "x", "value": 5, "prev": 3}]
    assert s["status"] == "partial"
    assert build.summarize([{"status": "error", "kpis": []}, {"status": "off", "kpis": []}],
                           None)["status"] == "failed"


async def test_build_survives_failing_and_missing_sources(monkeypatch):
    class State:
        class arp_store:
            @staticmethod
            async def week(frm, to):
                raise RuntimeError("db weg")

        class dns_cache:
            @staticmethod
            async def new_names(frm, to):
                return []

    async def read_config(key):
        return {}

    data = await build.build(State(), read_config, START, SLOT, CFG)
    st = {s["id"]: s["status"] for s in data["sources"]}
    assert st["hosts"] == "error"
    assert st["firewall"] == st["zabbix"] == st["ad"] == st["ifix"] == "off"
    assert data["period"]["kw"] == "KW 43/2026" and data["summary"]["status"] == "failed"
