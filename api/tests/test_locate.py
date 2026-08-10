"""Switchport-Suche: Anreicherung, Portklassifikation, Ranking, Konfidenz.

Nachgebautes Feldszenario — dieselbe MAC steht auf drei Ports:
  moxa-iks   Port 5    3 MACs, kein LLDP              ← der echte Access-Port
  moxa-iks   Port 23 180 MACs, kein LLDP              ← Ring-Uplink (MOXA ohne LLDP)
  hpe-core   Gi1/0/1 400 MACs, LLDP auf überwachtes Gerät ← Switch-zu-Switch-Uplink
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


def _nb(label: str, monitored: bool) -> dict:
    return {"label": label, "monitored": monitored, "device_id": 7 if monitored else None}


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


def field_client(access_age_s: int = 120, core_age_s: int | None = None) -> FakeClient:
    core_age = access_age_s if core_age_s is None else core_age_s
    return FakeClient(
        fdb_rows=[
            {"port_id": 3701, "device_id": 169, "vlan_id": 0, "updated_at": _ts(access_age_s)},
            {"port_id": 3789, "device_id": 169, "vlan_id": 0, "updated_at": _ts(access_age_s)},
            {"port_id": 9001, "device_id": 42, "vlan_id": 7, "updated_at": _ts(core_age)},
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
        # Nur der Core-Uplink meldet einen LLDP-Nachbarn, und der ist überwacht.
        neighbours={9001: _nb("moxa-iks / Port 23", monitored=True)},
    )


async def _ranked(client, cfg=CFG, warnings=None):
    return fdb_librenms.rank(
        await fdb_librenms.candidates(client, cfg, MAC, warnings if warnings is not None else [])
    )


# ── Portklassifikation ────────────────────────────────────────────────────────

def test_classify_port_covers_all_four_classes():
    c = fdb_librenms.classify_port
    assert c(False, False, 3, 8) == "access"      # wenige MACs, kein LLDP
    assert c(False, False, 180, 8) == "trunk"     # viele MACs, kein LLDP
    assert c(True, True, 400, 8) == "uplink"      # LLDP auf überwachtes Gerät
    assert c(True, False, 40, 8) == "edge"        # LLDP, Nachbar nicht überwacht
    assert c(False, False, 0, 8) == "unknown"     # Anreicherung fehlgeschlagen


# ── Ranking ───────────────────────────────────────────────────────────────────

async def test_access_port_wins_over_ring_and_core():
    ranked = await _ranked(field_client())

    assert len(ranked) == 3
    best = ranked[0]
    assert (best["hostname"], best["if_name"]) == ("moxa-iks", "Port 5")
    assert best["port_kind"] == "access"
    assert best["mac_count"] == 3
    assert fdb_librenms.confidence(ranked, CFG) == "high"


async def test_monitored_lldp_neighbour_ranks_last_despite_low_mac_count():
    """Ein Uplink zu einem überwachten Switch scheidet aus, egal wie leer er ist."""
    client = field_client()
    client._device_fdb["42"] = [{"port_id": 9001}]      # Core-Uplink mit nur 1 MAC
    ranked = await _ranked(client)

    assert ranked[-1]["hostname"] == "hpe-core"
    assert ranked[-1]["port_kind"] == "uplink"
    assert ranked[0]["if_name"] == "Port 5"


async def test_recency_beats_port_class():
    """Frischer Eintrag schlägt die Heuristik — die MAC ist vom alten Port weg."""
    client = field_client(access_age_s=8 * 3600, core_age_s=60)
    ranked = await _ranked(client)

    assert ranked[0]["hostname"] == "hpe-core"          # trotz Uplink-Klasse vorn
    assert ranked[0]["age_bucket"] < ranked[1]["age_bucket"]


async def test_equally_fresh_entries_stay_grouped_by_class():
    """Sekunden Versatz zwischen Discovery-Läufen darf nichts umsortieren."""
    client = field_client()
    client._fdb[2]["updated_at"] = _ts(45)              # Core 75 s frischer
    ranked = await _ranked(client)

    assert ranked[0]["if_name"] == "Port 5"             # gleicher Bucket → Klasse zählt


# ── Hypervisor-Fall ───────────────────────────────────────────────────────────

async def test_hypervisor_trunk_beats_real_uplinks():
    """Eine VM hängt legitim hinter einem Trunk mit vielen MACs.

    Der Trunk zum ESX hat kein LLDP zu einem überwachten Gerät — er ist damit
    kein Switch-zu-Switch-Uplink und muss vor den echten Uplinks landen.
    """
    client = field_client()
    client._device_fdb["169"] = (
        [{"port_id": 3701} for _ in range(40)]          # ESX-Trunk statt Access
        + [{"port_id": 3789} for _ in range(180)]
    )
    client._neighbours = {
        3789: _nb("moxa-iks-02 / Port 24", monitored=True),   # echter Ring-Uplink
        9001: _nb("moxa-iks / Port 23", monitored=True),
    }
    ranked = await _ranked(client)

    assert ranked[0]["if_name"] == "Port 5"
    assert ranked[0]["port_kind"] == "trunk"
    assert fdb_librenms.confidence(ranked, CFG) == "medium"


async def test_unmonitored_lldp_neighbour_counts_as_edge_not_uplink():
    """ESXi meldet sich per LLDP, ist aber kein überwachter Switch."""
    client = field_client()
    client._neighbours = {
        3701: _nb("esx-04 / vmnic2", monitored=False),
        3789: _nb("moxa-iks-02 / Port 24", monitored=True),
        9001: _nb("moxa-iks / Port 23", monitored=True),
    }
    ranked = await _ranked(client)

    assert ranked[0]["if_name"] == "Port 5"
    assert ranked[0]["port_kind"] == "edge"
    assert ranked[0]["neighbor"] == "esx-04 / vmnic2"
    assert ranked[0]["neighbor_monitored"] is False


# ── Konfidenz und Randfälle ───────────────────────────────────────────────────

async def test_only_uplinks_gives_low_confidence():
    """Zugangsswitch fehlt in LibreNMS — nur Uplink-Treffer, das muss man sehen."""
    client = field_client()
    client._neighbours = {
        3701: _nb("sw-unknown / 1", True),
        3789: _nb("sw-x / 2", True),
        9001: _nb("moxa / 23", True),
    }
    ranked = await _ranked(client)

    assert all(c["port_kind"] == "uplink" for c in ranked)
    assert fdb_librenms.confidence(ranked, CFG) == "low"


async def test_stale_entry_downgrades_confidence():
    ranked = await _ranked(field_client(access_age_s=30 * 3600, core_age_s=30 * 3600))

    assert ranked[0]["stale"] is True
    assert fdb_librenms.confidence(ranked, CFG) == "medium"   # sonst "high"


async def test_unknown_mac_count_does_not_win():
    """mac_count 0 heißt 'nicht ermittelbar', nicht 'leerer Port'."""
    client = field_client()
    client._device_fdb["42"] = []                       # Anreicherung liefert nichts
    ranked = await _ranked(client)

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
    ranked = await _ranked(client, warnings=warnings)

    assert ranked[0]["if_name"] == "Port 5"
    assert any("LLDP" in w for w in warnings)


def test_mac_normalisation_accepts_every_notation():
    for raw in ("00:0c:29:11:89:1a", "000c.2911.891a", "00-0C-29-11-89-1A", "000C2911891A"):
        assert normalize_mac(raw) == MAC
    assert normalize_mac("06000c2911891a") == MAC     # Längenbyte-Präfix
    assert normalize_mac("keine mac") is None
    assert normalize_mac(None) is None
    assert readable_mac(MAC) == "00:0c:29:11:89:1a"
