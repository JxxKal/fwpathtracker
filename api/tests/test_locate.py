"""Switchport-Suche: Anreicherung, Ranking, Konfidenz.

Nachgebautes Feldszenario — dieselbe MAC steht auf drei Ports:
  moxa-iks   Port 5    3 MACs, kein LLDP   ← der echte Access-Port
  moxa-iks   Port 23 180 MACs, kein LLDP   ← Ring-Uplink (MOXA fährt ohne LLDP)
  hpe-core   Gi1/0/1 400 MACs, mit LLDP    ← Uplink zum Core
"""
from __future__ import annotations

import sys
from datetime import datetime, timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from locate import fdb_librenms  # noqa: E402
from locate.mac import normalize_mac, readable_mac  # noqa: E402

MAC = "000c2911891a"
CFG = {"base_url": "https://librenms.example", "token": "x"}


def _ts(age_s: int) -> str:
    return (datetime.now() - timedelta(seconds=age_s)).strftime("%Y-%m-%d %H:%M:%S")


class FakeClient:
    """Minimal-Stub mit derselben Signatur wie LibrenmsClient."""

    def __init__(self, fdb_rows, devices, ports, device_fdb, neighbours):
        self._fdb, self._devices = fdb_rows, devices
        self._ports, self._device_fdb, self._neighbours = ports, device_fdb, neighbours

    async def fdb(self, cfg, mac):
        return self._fdb

    async def neighbours(self, cfg):
        return self._neighbours

    async def device(self, cfg, device_id):
        return self._devices[str(device_id)]

    async def device_ports(self, cfg, device_id):
        return self._ports[str(device_id)]

    async def device_fdb(self, cfg, device_id):
        return self._device_fdb[str(device_id)]


def field_client(access_age_s: int = 120) -> FakeClient:
    return FakeClient(
        fdb_rows=[
            {"port_id": 3701, "device_id": 169, "vlan_id": 0, "updated_at": _ts(access_age_s)},
            {"port_id": 3789, "device_id": 169, "vlan_id": 0, "updated_at": _ts(access_age_s)},
            {"port_id": 9001, "device_id": 42, "vlan_id": 7, "updated_at": _ts(access_age_s)},
        ],
        devices={
            "169": {"hostname": "moxa-iks", "sysName": "bpvo049"},
            "42": {"hostname": "hpe-core", "sysName": "core-01"},
        },
        ports={
            "169": [
                {"port_id": 3701, "ifName": "Port 5", "ifAlias": "Anlage 3", "ifOperStatus": "up"},
                {"port_id": 3789, "ifName": "Port 23", "ifAlias": "Ring A", "ifOperStatus": "up"},
            ],
            "42": [{"port_id": 9001, "ifName": "Gi1/0/1", "ifAlias": "", "ifOperStatus": "up"}],
        },
        device_fdb={
            "169": [{"port_id": 3701} for _ in range(3)] + [{"port_id": 3789} for _ in range(180)],
            "42": [{"port_id": 9001} for _ in range(400)],
        },
        # Nur der HPE-Uplink meldet einen LLDP-Nachbarn.
        neighbours={9001: "moxa-iks / Port 23"},
    )


async def test_access_port_wins_over_ring_and_core():
    warnings: list[str] = []
    cands = await fdb_librenms.candidates(field_client(), CFG, MAC, warnings)
    ranked = fdb_librenms.rank(cands)

    assert len(ranked) == 3
    best = ranked[0]
    assert (best["hostname"], best["if_name"]) == ("moxa-iks", "Port 5")
    assert best["mac_count"] == 3
    assert best["has_neighbor"] is False
    assert fdb_librenms.confidence(ranked, CFG) == "high"


async def test_lldp_neighbour_ranks_last_despite_low_mac_count():
    """LLDP schlägt die MAC-Zahl: ein Port mit Nachbarn ist nie der Access-Port."""
    client = field_client()
    client._device_fdb["42"] = [{"port_id": 9001}]      # Core-Uplink mit nur 1 MAC
    warnings: list[str] = []
    ranked = fdb_librenms.rank(await fdb_librenms.candidates(client, CFG, MAC, warnings))

    assert ranked[-1]["hostname"] == "hpe-core"
    assert ranked[0]["if_name"] == "Port 5"


async def test_only_uplinks_gives_low_confidence():
    """Zugangsswitch fehlt in LibreNMS — nur Uplink-Treffer, das muss man sehen."""
    client = field_client()
    client._neighbours = {3701: "sw-unknown / 1", 3789: "sw-x / 2", 9001: "moxa / 23"}
    ranked = fdb_librenms.rank(await fdb_librenms.candidates(client, CFG, MAC, []))

    assert all(c["has_neighbor"] for c in ranked)
    assert fdb_librenms.confidence(ranked, CFG) == "low"


async def test_stale_entry_downgrades_confidence():
    warnings: list[str] = []
    cands = await fdb_librenms.candidates(field_client(access_age_s=30 * 3600), CFG, MAC, warnings)
    ranked = fdb_librenms.rank(cands)

    assert ranked[0]["stale"] is True
    assert fdb_librenms.confidence(ranked, CFG) == "medium"   # sonst "high"


async def test_unknown_mac_count_does_not_win():
    """mac_count 0 heißt 'nicht ermittelbar', nicht 'leerer Port'."""
    client = field_client()
    client._device_fdb["42"] = []                       # Anreicherung liefert nichts
    ranked = fdb_librenms.rank(await fdb_librenms.candidates(client, CFG, MAC, []))

    assert ranked[0]["if_name"] == "Port 5"
    assert ranked[0]["mac_count"] == 3


async def test_empty_fdb_yields_no_candidates():
    client = field_client()
    client._fdb = []
    warnings: list[str] = []
    assert await fdb_librenms.candidates(client, CFG, MAC, warnings) == []
    assert fdb_librenms.confidence([], CFG) == "none"


async def test_missing_lldp_still_ranks_and_warns():
    """Ohne LLDP bleibt die MAC-Zahl — das Ergebnis stimmt, die Warnung kommt."""
    class NoLinks(FakeClient):
        async def neighbours(self, cfg):
            raise RuntimeError("links endpoint down")

    c = field_client()
    client = NoLinks(c._fdb, c._devices, c._ports, c._device_fdb, {})
    warnings: list[str] = []
    ranked = fdb_librenms.rank(await fdb_librenms.candidates(client, CFG, MAC, warnings))

    assert ranked[0]["if_name"] == "Port 5"
    assert any("LLDP" in w for w in warnings)


def test_mac_normalisation_accepts_every_notation():
    for raw in ("00:0c:29:11:89:1a", "000c.2911.891a", "00-0C-29-11-89-1A", "000C2911891A"):
        assert normalize_mac(raw) == MAC
    assert normalize_mac("06000c2911891a") == MAC     # Längenbyte-Präfix
    assert normalize_mac("keine mac") is None
    assert normalize_mac(None) is None
    assert readable_mac(MAC) == "00:0c:29:11:89:1a"
