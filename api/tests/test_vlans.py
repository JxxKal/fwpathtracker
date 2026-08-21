"""VLAN-Übersicht und Netzwerkport-Check.

Nachgebautes Feldszenario: VLAN 44 kennt sowohl der Switch (LibreNMS) als auch
die Firewall (FMG-Interface mit Subnetz), VLAN 90 nur der Switch, VLAN 7 nur die
Firewall. Der Host hängt in VLAN 44 — auf dem Access-Port und (als gelernte MAC)
auf dem Uplink.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from inventory.store import Inventory  # noqa: E402
from librenms.client import LibrenmsNotConfigured  # noqa: E402
from vlan import hostports, overview  # noqa: E402

CFG = {"base_url": "https://librenms.example", "token": "x"}

# LibreNMS-VLAN-Tabelle: vlan_id ist die interne Zeilen-ID, auf die die FDB
# verweist — vlan_vlan ist die eigentliche VLAN-Nummer.
VLAN_ROWS = [
    {"vlan_id": 101, "device_id": 3, "vlan_vlan": 44, "vlan_name": "OT-PLT-Bockstedt"},
    {"vlan_id": 102, "device_id": 3, "vlan_vlan": 90, "vlan_name": "OT-Mgmt"},
    {"vlan_id": 103, "device_id": 4, "vlan_vlan": 44, "vlan_name": "OT-PLT"},
]


def _fmg_rows() -> list[dict]:
    def row(kind, key, data):
        return {"adom": "root", "kind": kind, "key": key, "data": data}

    return [
        row("device", "fw-bt", {"name": "fw-bt", "vdom": [{"name": "root"}]}),
        row("interface", "fw-bt", [
            {"name": "PLT", "ip": ["10.124.44.1", "255.255.255.0"], "vdom": ["root"],
             "vlanid": 44, "alias": "OT PLT Bockstedt", "type": 1},
            {"name": "MGMT-ALT", "ip": ["10.124.7.1", "255.255.255.0"], "vdom": ["root"],
             "vlanid": ["7"], "description": "Alt-Management", "type": 1},
            {"name": "wan1", "ip": ["10.180.33.6", "255.255.255.248"], "vdom": ["root"]},
        ]),
        row("zone", "PLT-Zone", {"name": "PLT-Zone", "dynamic_mapping": [
            {"_scope": [{"name": "fw-bt", "vdom": "root"}], "local-intf": ["PLT"]},
        ]}),
    ]


@pytest.fixture
def inv() -> Inventory:
    return Inventory.build(_fmg_rows(), synced_at="2026-08-17T06:00:00+00:00")


@pytest.fixture
def prefixes(inv: Inventory):
    return inv.build_prefix_table()


class FakeClient:
    """Stub mit den Signaturen, die overview/hostports benutzen."""

    def __init__(self, *, vlans=None, ports=None, device_fdb=None, port_vlans=None,
                 devices=None, fail_vlans: Exception | None = None):
        self._vlans = vlans if vlans is not None else VLAN_ROWS
        self._ports = ports or {}
        self._device_fdb = device_fdb or {}
        self._port_vlans = port_vlans or {}
        self._devices = devices or {}
        self._fail = fail_vlans
        self.port_vlan_calls: list[str] = []

    async def vlans(self, cfg):
        if self._fail is not None:
            raise self._fail
        return self._vlans

    async def device_vlans(self, cfg, device_id):
        return [v for v in self._vlans if str(v["device_id"]) == str(device_id)]

    async def port_vlans(self, cfg, port_id):
        self.port_vlan_calls.append(str(port_id))
        return self._port_vlans.get(str(port_id), [])

    async def device_ports(self, cfg, device_id):
        return self._ports.get(str(device_id), [])

    async def device_fdb(self, cfg, device_id):
        return self._device_fdb.get(str(device_id), [])

    async def device_index(self, cfg):
        return self._devices


# ── Freie Nummern ────────────────────────────────────────────────────────────

def test_free_ranges_are_gaps_between_used():
    assert overview.free_ranges({1, 44, 45}, lo=1, hi=50) == [[2, 43], [46, 50]]
    assert overview.free_ranges(set(), lo=1, hi=3) == [[1, 3]]
    assert overview.free_ranges({1, 2, 3}, lo=1, hi=3) == []
    # Randfall: belegtes Ende schließt den Lauf sauber ab
    assert overview.free_ranges({50}, lo=48, hi=50) == [[48, 49]]


# ── Globale Übersicht ────────────────────────────────────────────────────────

async def test_overview_merges_both_sources(inv, prefixes):
    client = FakeClient(devices={"sw1": {"device_id": 3, "hostname": "sw-bocks-01"},
                                 "sw2": {"device_id": 4, "hostname": "sw-bocks-02"}})
    res = await overview.build(inv, client, CFG)

    by_num = {v["vlan"]: v for v in res["vlans"]}
    assert sorted(by_num) == [7, 44, 90]

    # 44: beide Quellen — Switch-Namen und Firewall-Interface mit Subnetz
    v44 = by_num[44]
    assert v44["sources"] == ["fmg", "librenms"]
    assert v44["switch_count"] == 2
    assert {s["hostname"] for s in v44["switches"]} == {"sw-bocks-01", "sw-bocks-02"}
    assert v44["networks"] == ["10.124.44.0/24"]
    assert v44["firewall_interfaces"][0]["interface"] == "PLT"
    assert v44["firewall_interfaces"][0]["zone"] == "PLT-Zone"
    assert "OT-PLT-Bockstedt" in v44["names"] and "OT PLT Bockstedt" in v44["names"]

    # 90 nur Switch, 7 nur Firewall (vlanid als String in Liste!)
    assert by_num[90]["sources"] == ["librenms"] and by_num[90]["firewall_interfaces"] == []
    assert by_num[7]["sources"] == ["fmg"]
    assert by_num[7]["names"] == ["Alt-Management"]

    assert res["used_count"] == 3
    assert res["free"][0] == [1, 6]          # 7 ist belegt
    assert res["free"] == [[1, 6], [8, 43], [45, 89], [91, 4094]]
    assert res["free_count"] == 4094 - 3
    assert res["sources"] == {"librenms": True, "fmg": True}


async def test_overview_without_librenms_keeps_firewall_view(inv):
    client = FakeClient(fail_vlans=LibrenmsNotConfigured("nicht konfiguriert"))
    res = await overview.build(inv, client, {})

    assert [v["vlan"] for v in res["vlans"]] == [7, 44]      # nur FMG-Seite
    assert res["sources"]["librenms"] is False
    assert any("nicht konfiguriert" in w for w in res["warnings"])
    assert res["vlans"][1]["switches"] == []


# ── Host-Portcheck ───────────────────────────────────────────────────────────

def _locate_result(**over) -> dict:
    base = {
        "mac": "001b1baabbcc", "mac_readable": "00:1b:1b:aa:bb:cc",
        "arp": {"provenance": "fortigate", "device": "fw-bt"},
        "confidence": "high",
        "best": {"port_id": 55},
        "candidates": [
            {"device_id": 3, "hostname": "sw-bocks-01", "port_id": 55,
             "if_name": "Gi1/0/7", "if_alias": "BOCKS2 SPS", "oper_status": "up",
             "port_kind": "access", "vlan_id": 101, "mac_count": 2, "stale": False},
            {"device_id": 4, "hostname": "sw-bocks-02", "port_id": 90,
             "if_name": "Te1/0/1", "if_alias": "Uplink", "oper_status": "up",
             "port_kind": "uplink", "vlan_id": 103, "mac_count": 400, "stale": False},
        ],
        "self_device": None,
        "warnings": [],
    }
    base.update(over)
    return base


async def test_host_ports_resolves_vlan_per_finding(inv, prefixes):
    client = FakeClient(port_vlans={
        "55": [{"vlan": 44, "untagged": 1}],
        "90": [{"vlan": 44, "untagged": 0}, {"vlan": 90, "untagged": 0},
               {"vlan": 1, "untagged": 1}],
    })
    res = await hostports.check(
        ip="10.124.44.169", names=["BOCKS2"], inv=inv, prefixes=prefixes,
        client=client, librenms_cfg=CFG, locate_result=_locate_result())

    assert [f["vlan"]["number"] for f in res["findings"]] == [44, 44]
    assert res["findings"][0]["vlan"]["name"] == "OT-PLT-Bockstedt"
    assert res["findings"][0]["best"] is True
    # Access-Port: untagged 44 — Uplink: 1 untagged, 44/90 tagged
    assert res["findings"][0]["port_vlans"] == {"untagged": [44], "tagged": []}
    assert res["findings"][1]["port_vlans"] == {"untagged": [1], "tagged": [44, 90]}

    # L3-Sicht aus dem FMG-Inventar
    assert len(res["l3"]) == 1
    l3 = res["l3"][0]
    assert (l3["device"], l3["interface"], l3["vlan"]) == ("fw-bt", "PLT", 44)
    assert l3["network"] == "10.124.44.0/24" and l3["zone"] == "PLT-Zone"
    assert l3["prefix_source"] == "connected"

    # Zusammenfassung: das VLAN des Hosts, mit allen Fundorten
    assert [v["vlan"] for v in res["vlan_summary"]] == [44]
    assert len(res["vlan_summary"][0]["where"]) == 3      # 2 Ports + Firewall-IF


async def test_host_ports_lists_all_ports_when_host_is_a_device(inv, prefixes):
    """Ist der Host selbst überwacht, zählt die komplette Portliste — die VLANs
    je Port kommen aus der Geräte-FDB (ein Request statt einem pro Port)."""
    client = FakeClient(
        ports={"3": [
            {"port_id": 55, "ifName": "Gi1/0/7", "ifAlias": "BOCKS2 SPS",
             "ifOperStatus": "up", "ifAdminStatus": "up"},
            {"port_id": 56, "ifName": "Gi1/0/8", "ifAlias": None,
             "ifOperStatus": "down", "ifAdminStatus": "up"},
        ]},
        device_fdb={"3": [
            {"port_id": 55, "vlan_id": 101}, {"port_id": 55, "vlan_id": 102},
            {"port_id": 55, "vlan_id": 0},          # MOXA-Platzhalter: kein VLAN
        ]},
    )
    res = await hostports.check(
        ip="10.124.44.2", names=[], inv=inv, prefixes=prefixes, client=client,
        librenms_cfg=CFG,
        locate_result=_locate_result(candidates=[], best=None,
                                     self_device={"device_id": 3,
                                                  "hostname": "sw-bocks-01"}))

    dev = res["device"]
    assert dev["hostname"] == "sw-bocks-01"
    assert [p["if_name"] for p in dev["ports"]] == ["Gi1/0/7", "Gi1/0/8"]
    assert dev["ports"][0]["vlans_observed"] == [44, 90]   # 0 ignoriert
    assert dev["ports"][0]["mac_count"] == 3
    assert dev["ports"][1]["vlans_observed"] == [] and dev["ports"][1]["oper_status"] == "down"
    assert [v["number"] for v in dev["vlans"]] == [44, 90]
    assert client.port_vlan_calls == []        # keine Einzelabfrage je Port


async def test_host_ports_warns_when_no_vlan_resolvable(inv, prefixes):
    """FDB ohne VLAN-Zuordnung (MOXA meldet 0) — der Check sagt das, statt
    stumm eine leere Spalte zu zeigen."""
    client = FakeClient(vlans=[])
    res = await hostports.check(
        ip="10.124.44.169", names=[], inv=inv, prefixes=prefixes, client=client,
        librenms_cfg=CFG, locate_result=_locate_result())

    assert all(f["vlan"] is None for f in res["findings"])
    assert any("kein VLAN auflösen" in w or "keine VLAN-Zuordnung" in w
               for w in res["warnings"])


async def test_host_ports_warns_when_no_connected_interface(inv, prefixes):
    client = FakeClient()
    res = await hostports.check(
        ip="10.9.9.9", names=[], inv=inv, prefixes=prefixes, client=client,
        librenms_cfg=CFG, locate_result=_locate_result(candidates=[], best=None))

    assert res["l3"] == []
    assert any("Kein connected VLAN-Interface" in w for w in res["warnings"])


async def test_overview_reports_unusable_vlan_rows(inv):
    """Zeilen ohne verwertbare Nummer (0, leer, Unsinn) dürfen nicht spurlos
    verschwinden — sonst fehlt ein VLAN und niemand erfährt warum."""
    rows = VLAN_ROWS + [
        {"vlan_id": 200, "device_id": 9, "vlan_vlan": 0, "vlan_name": "moxa-l2"},
        {"vlan_id": 201, "device_id": 9, "vlan_vlan": "", "vlan_name": "leer"},
        {"vlan_id": 202, "device_id": 9, "vlan_vlan": 9999, "vlan_name": "zu-gross"},
    ]
    client = FakeClient(vlans=rows,
                        devices={"sw9": {"device_id": 9, "hostname": "hpe-l2-01"}})
    res = await overview.build(inv, client, CFG)

    assert res["stats"]["librenms_rows"] == 6
    assert res["stats"]["librenms_skipped"] == 3
    warn = " ".join(res["warnings"])
    assert "3 VLAN-Zeile(n)" in warn and "hpe-l2-01" in warn
    assert "0" in warn and "9999" in warn
    # Die verwertbaren Zeilen stehen weiterhin drin
    assert [v["vlan"] for v in res["vlans"]] == [7, 44, 90]


async def test_overview_stats_show_contributing_devices(inv):
    """Fehlt ein VLAN, ist die erste Frage: hat sein Switch überhaupt VLANs
    geliefert? Die Bilanz macht das beantwortbar."""
    client = FakeClient(devices={
        "sw1": {"device_id": 3, "hostname": "sw-bocks-01"},
        "sw2": {"device_id": 4, "hostname": "sw-bocks-02"},
        "sw3": {"device_id": 5, "hostname": "hpe-ohne-vlan-discovery"},
    })
    res = await overview.build(inv, client, CFG)

    st = res["stats"]
    assert st["librenms_devices"] == 2          # nur 3 und 4 liefern VLANs
    assert st["librenms_devices_known"] == 3    # LibreNMS überwacht drei
    assert st["contributing_devices"] == ["sw-bocks-01", "sw-bocks-02"]
    assert "hpe-ohne-vlan-discovery" not in st["contributing_devices"]
    assert st["fmg_interfaces"] == 2


# ── Bezeichnung reiner L2-VLANs ──────────────────────────────────────────────

def test_placeholder_name_detection():
    """LibreNMS schreibt 'VLAN <Nr>', wenn dot1qVlanStaticName leer ist — das ist
    keine Bezeichnung, sondern deren Fehlen."""
    assert overview.is_placeholder_name("VLAN 44", 44) is True
    assert overview.is_placeholder_name("vlan44", 44) is True
    assert overview.is_placeholder_name("VLAN 0044", 44) is False   # anderer Wert
    assert overview.is_placeholder_name("OT-PLT-Bockstedt", 44) is False
    assert overview.is_placeholder_name("VLAN 44", 45) is False


async def test_l2_only_vlan_keeps_switch_description(inv):
    """Ein reines L2-VLAN (kein Firewall-Interface) muss seine Beschreibung vom
    Switch tragen — sie ist dort die einzige Quelle."""
    rows = [
        {"vlan_id": 300, "device_id": 9, "vlan_vlan": 815, "vlan_name": "Kamera-Netz Halle 3"},
        {"vlan_id": 301, "device_id": 10, "vlan_vlan": 815, "vlan_name": "Kamera-Netz Halle 3"},
    ]
    client = FakeClient(vlans=rows, devices={
        "a": {"device_id": 9, "hostname": "hpe-l2-01"},
        "b": {"device_id": 10, "hostname": "hpe-l2-02"}})
    res = await overview.build(inv, client, CFG)

    v = next(v for v in res["vlans"] if v["vlan"] == 815)
    assert v["sources"] == ["librenms"]           # rein L2, kein Firewall-IF
    assert v["names"] == ["Kamera-Netz Halle 3"]  # Beschreibung steht trotzdem da
    assert v["unnamed"] is False
    assert v["switch_count"] == 2
    assert all(s["placeholder"] is False for s in v["switches"])
    assert res["stats"]["unnamed_vlans"] == 0


async def test_placeholder_is_not_shown_as_description(inv):
    """Meldet der Switch keinen Namen, darf der LibreNMS-Platzhalter nicht als
    Bezeichnung durchgehen — sonst verdeckt er, dass die Angabe fehlt."""
    rows = [
        {"vlan_id": 300, "device_id": 9, "vlan_vlan": 815, "vlan_name": "VLAN 815"},
        {"vlan_id": 301, "device_id": 10, "vlan_vlan": 816, "vlan_name": "Gäste-WLAN"},
    ]
    client = FakeClient(vlans=rows, devices={"a": {"device_id": 9, "hostname": "hpe-l2-01"},
                                             "b": {"device_id": 10, "hostname": "hpe-l2-02"}})
    res = await overview.build(inv, client, CFG)

    v815 = next(v for v in res["vlans"] if v["vlan"] == 815)
    assert v815["names"] == [] and v815["unnamed"] is True
    assert v815["switches"][0]["name"] == "VLAN 815"      # Rohwert bleibt sichtbar
    assert v815["switches"][0]["placeholder"] is True

    v816 = next(v for v in res["vlans"] if v["vlan"] == 816)
    assert v816["names"] == ["Gäste-WLAN"] and v816["unnamed"] is False

    assert res["stats"]["unnamed_vlans"] == 1
    warn = " ".join(res["warnings"])
    assert "815" in warn and "dot1qVlanStaticName" in warn and "description" in warn
