"""Windows-Inventar: Dateinamen, CSV-Format des Collectors, Regeln, Import."""
from __future__ import annotations

import os
from datetime import date, datetime, timedelta, timezone

from wininv import importer, parse, risks, service
from wininv.source import LocalSource, SourceError, build_source, unc_parts

BOM = "\ufeff"
SYSTEM = (BOM + '"Hostname";"Domain";"OS";"IPs";"CPU";"RAM_GB";"Disks"\r\n'
          '"HOST01";"corp.example";"Microsoft Windows Server 2008 R2 Enterprise ";'
          '"169.254.20.149, 127.0.0.1, 10.1.2.3";"8";"3,9";'
          '"C: (5.0GB frei von 58GB) | D: (156.3GB frei von 165GB)"\r\n')
SOFTWARE = (BOM + '"Hostname";"DisplayName";"DisplayVersion";"Publisher"\r\n'
            '"HOST01";"";;\r\n"HOST01";"Editor ""Pro""";"1.0";"ACME"\r\n')
GROUPS = (BOM + '"Hostname";"GroupName";"MemberName";"Source"\r\n'
          '"HOST01";"Administratoren";"CORP\\Domain Admins";"ActiveDirectory"\r\n'
          '"HOST01";"Hauptbenutzer";"";"-"\r\n')
PORTS = BOM + '"Hostname";"Port"\r\n"HOST01";"3389"\r\n"HOST01";"445"\r\n'
CERTS = (BOM + '"Hostname";"Subject";"Issuer";"Thumbprint";"ValidUntil";"SAN"\r\n'
         '"HOST01";"CN=alt, O=x";"CN=CA";"AA";"2020-01-01";""\r\n')


def test_file_names():
    assert parse.split_name("BARRC01_08_Software.csv") == ("BARRC01", "software")
    assert parse.split_name("svo9100-ot_01_System.CSV") == ("SVO9100-OT", "system")
    assert parse.split_name("MY_HOST_10_Certificates.csv") == ("MY_HOST", "certificates")
    assert parse.split_name("Collector_Scripts.ps1") is None
    assert parse.split_name("HOST_99_Unknown.csv") is None


def test_collector_csv_and_system():
    rows = parse.parse_csv(SOFTWARE.encode("utf-8"), "software")
    assert rows == [{"DisplayName": 'Editor "Pro"', "DisplayVersion": "1.0",
                     "Publisher": "ACME"}]                       # leere Zeile fällt weg
    nul = SOFTWARE.replace('"1.0"', '"1.0\x00"').encode("utf-8")
    assert parse.parse_csv(nul, "software")[0]["DisplayVersion"] == "1.0"
    assert parse.parse_csv(GROUPS.encode("utf-16"), "groups")[0]["MemberName"] \
        == "CORP\\Domain Admins"                                 # UTF-16 geht auch
    s = parse.system(parse.parse_csv(SYSTEM.encode("utf-8"), "system"))
    assert s["ips"] == ["10.1.2.3"]                              # ohne APIPA und Loopback
    assert s["ram_gb"] == 3.9 and s["cpu"] == 8
    assert s["disks"][0] == {"drive": "C:", "free_gb": 5.0, "total_gb": 58.0}


def test_risks_like_the_bechtle_dashboard():
    today = date(2026, 11, 4)
    r = risks.host_risks({"os": "Microsoft Windows Server 2008 R2 Enterprise",
                          "disks": [{"drive": "C:", "free_gb": 5.0, "total_gb": 58.0},
                                    {"drive": "D:", "free_gb": 15.0, "total_gb": 58.0}]},
                         [{"Subject": "CN=web, O=x", "ValidUntil": "2026-11-20"},
                          {"Subject": "CN=ok", "ValidUntil": "2030-01-01"}], today)
    assert [(x["kind"], x["level"]) for x in r] == [("os", "red"), ("cert", "red"),
                                                     ("disk", "red"), ("disk", "orange")]
    assert risks.host_risks({"os": "Microsoft Windows 10 Enterprise LTSC"}, [], today) == []
    assert risks.host_risks({"os": "Microsoft Windows 10 Pro"}, [], today)[0]["level"] == "red"
    assert risks.host_risks({"os": "Microsoft Windows Server 2016 Standard"}, [],
                            today)[0]["level"] == "orange"


def test_unc_paths_and_sources(tmp_path):
    assert unc_parts(r"\\svo3001-ot\Inventory$") == ("svo3001-ot", r"\\svo3001-ot\Inventory$")
    assert unc_parts("//srv/share/Daten/")[1] == r"\\srv\share\Daten"
    assert isinstance(build_source({"path": str(tmp_path)}), LocalSource)
    try:
        unc_parts(r"\\nurserver")
        raise AssertionError
    except SourceError:
        pass


class FakeStore:
    def __init__(self) -> None:
        self.cur: dict[tuple[str, str], dict] = {}
        self.history: list[tuple] = []

    async def known(self):
        return {k: {kk: v[kk] for kk in ("name", "size", "mtime", "sha256")}
                for k, v in self.cur.items()}

    async def touch(self, keys, now):
        pass

    async def save(self, host, kind, name, size, mtime, sha, rows, changed, now):
        old = self.cur.get((host, kind), {})
        self.cur[(host, kind)] = {"name": name, "size": size, "mtime": mtime, "sha256": sha,
                                  "rows": rows if changed else old["rows"],
                                  "changed_at": now if changed else old["changed_at"]}
        if changed:
            self.history.append((host, kind, sha))

    async def current(self, host=None):
        return [{"hostname": h, "kind": k, "file_mtime": v["mtime"],
                 "changed_at": v["changed_at"], "checked_at": v["changed_at"], "rows": v["rows"]}
                for (h, k), v in self.cur.items() if host in (None, h)]


def _write(d, name, text, mtime):
    p = d / name
    p.write_text(text, encoding="utf-8")
    os.utime(p, (mtime.timestamp(), mtime.timestamp()))


async def test_import_reads_only_what_changed(tmp_path):
    t0 = datetime(2026, 11, 2, 23, 0, tzinfo=timezone.utc)
    for name, text in [("HOST01_01_System.csv", SYSTEM), ("HOST01_08_Software.csv", SOFTWARE),
                       ("HOST01_04_Groups.csv", GROUPS), ("HOST01_06_Ports.csv", PORTS),
                       ("HOST01_10_Certificates.csv", CERTS), ("Collector_Script.ps1", "x")]:
        _write(tmp_path, name, text, t0)
    store, src = FakeStore(), LocalSource(str(tmp_path))
    st = await importer.run(src, store)
    assert (st["files"], st["hosts"], st["changed"], st["foreign"]) == (5, 1, 5, 1)
    # Nichts geändert → nichts gelesen.
    st = await importer.run(src, store)
    assert (st["read"], st["skipped"]) == (0, 5)
    # Nächte Nacht: gleiche Ports neu geschrieben, Software geändert.
    t1 = t0 + timedelta(days=1)
    _write(tmp_path, "HOST01_06_Ports.csv", PORTS, t1)
    _write(tmp_path, "HOST01_08_Software.csv",
           SOFTWARE + '"HOST01";"Neu";"2.0";"ACME"\r\n', t1)
    st = await importer.run(src, store)
    assert (st["read"], st["changed"], st["unchanged"]) == (2, 1, 1)
    assert len(store.history) == 6
    assert store.cur[("HOST01", "ports")]["mtime"] == t1

    [h] = service.summarize(await store.current(), stale_days=3, today=date(2026, 11, 4))
    assert h["hostname"] == "HOST01" and h["ips"] == ["10.1.2.3"]
    assert h["admins"] == ["CORP\\Domain Admins"] and h["ports"] == [445, 3389]
    assert h["kinds"]["software"] == 2
    assert {r["kind"] for r in h["risks"]} == {"os", "cert", "disk"}


async def test_trace_looks_up_the_destination_in_the_inventory():
    from routers import trace

    class Svc:
        async def index(self, cfg):
            return service.build_index([
                {"hostname": "SRV1", "kind": "system", "file_mtime": datetime.now(timezone.utc),
                 "rows": [{"OS": "Windows Server 2022", "IPs": "10.1.2.3"}]},
                {"hostname": "SRV1", "kind": "ports", "file_mtime": datetime.now(timezone.utc),
                 "rows": [{"Port": "443"}]}], 3)

    class State:
        wininv = Svc()

    async def cfg(key):
        return {"path": "x"}

    trace.read_config, orig = cfg, trace.read_config
    try:
        w = await trace._dst_windows(State(), "10.1.2.3")
        assert w["hostname"] == "SRV1" and w["ports"] == [443] and w["stale"] is False
        assert await trace._dst_windows(State(), "10.9.9.9") is None
        assert await trace._dst_windows(object(), "10.1.2.3") is None   # ohne Inventar
    finally:
        trace.read_config = orig
