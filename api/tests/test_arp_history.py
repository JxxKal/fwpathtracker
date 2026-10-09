"""IP↔MAC-Historie: Aufzeichnen, Offline-Fallback und dessen Ehrlichkeit.

Der Speicher ist eingespeist (kein Postgres im Test) — geprüft wird die
Entscheidungslogik der Locate-Kette, nicht SQL.
"""
from __future__ import annotations

import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from config import Config  # noqa: E402
from locate import arp_fortigate  # noqa: E402
from locate.arp_store import age_s, normalize_ip  # noqa: E402
from locate.arp_sweep import l3_targets  # noqa: E402
from locate.chain import LocateChain  # noqa: E402

MAC_A = "001b1baabbcc"
MAC_B = "001b1bddeeff"


def _binding(ip: str, mac: str, age_days: float, **over) -> dict:
    seen = datetime.now(timezone.utc) - timedelta(days=age_days)
    out = {"ip": ip, "mac": mac, "device": "fw-a", "vdom": "root",
           "interface": "lan1", "source": "fortigate",
           "first_seen": (seen - timedelta(days=30)).isoformat(),
           "last_seen": seen.isoformat(), "age_s": int(age_days * 86400),
           "seen_count": 42}
    out.update(over)
    return out


class FakeStore:
    """Attrappe mit derselben Schnittstelle wie ArpStore."""

    def __init__(self, by_ip: dict | None = None, fail: bool = False):
        self._by_ip = by_ip or {}
        self.recorded: list[dict] = []
        self.fail = fail

    async def record(self, observations):
        if self.fail:
            raise RuntimeError("DB weg")
        self.recorded.extend(observations)
        return len(observations)

    async def by_ip(self, ip, limit=20):
        if self.fail:
            raise RuntimeError("DB weg")
        return self._by_ip.get(ip, [])


class FakeLibrenms:
    """Genug LibreNMS, damit die Portsuche einen Access-Port findet."""

    def __init__(self, mac_on_port: str):
        self._mac = mac_on_port

    async def fdb(self, cfg, mac):
        if mac != self._mac:
            return []
        return [{"device_id": 3, "port_id": 55, "vlan_id": 101,
                 "updated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")}]

    async def neighbours(self, cfg):
        return {}

    async def device(self, cfg, device_id):
        return {"hostname": "sw-01", "sysName": "sw-01"}

    async def device_ports(self, cfg, device_id):
        return [{"port_id": 55, "ifName": "Gi1/0/7", "ifAlias": "SPS",
                 "ifOperStatus": "up", "ifDescr": "Gi1/0/7"}]

    async def device_fdb(self, cfg, device_id):
        return [{"port_id": 55}, {"port_id": 55}]

    async def device_index(self, cfg):
        return {}


def _chain(store, mac_on_port: str = MAC_A) -> LocateChain:
    chain = LocateChain(ttl_s=0, store=store)
    chain.librenms = FakeLibrenms(mac_on_port)
    return chain


async def _locate(chain, prefixes, ip: str) -> dict:
    # Kein FMG konfiguriert → die FortiGate-ARP-Quelle steigt sofort aus,
    # LibreNMS-ARP kennt nichts: genau die Lage bei einem stillen Host.
    return await chain.locate(ip, prefixes, {"base_url": "", "token": ""},
                              {"host": ""}, Config())


# ── Hilfsfunktionen ──────────────────────────────────────────────────────────

def test_normalize_ip_rejects_ambiguous_forms():
    assert normalize_ip(" 10.1.1.10 ") == "10.1.1.10"
    assert normalize_ip("010.1.1.10") is None      # führende Null ist mehrdeutig
    assert normalize_ip("kein-ip") is None


def test_age_uses_timezone_of_the_stamp():
    assert age_s(datetime.now(timezone.utc) - timedelta(hours=2)) == pytest.approx(7200, abs=5)
    assert age_s(None) is None


def test_l3_targets_are_unique_per_vdom(prefixes):
    """Ein VDOM mit zwanzig Netzen darf nicht zwanzigmal abgefragt werden."""
    targets = l3_targets(prefixes)
    assert len(targets) == len(set(targets))
    assert all(len(t) == 3 for t in targets)
    assert ("corp", "fw-a", "root") in targets


def test_arp_rows_become_observations():
    rows = [
        {"ip": "10.1.1.10", "mac": "00:1b:1b:aa:bb:cc", "interface": "lan1"},
        {"ip": "10.1.1.11", "mac": "invalid"},          # unbrauchbar → raus
        {"ip": "", "mac": "00:1b:1b:dd:ee:ff"},         # ohne IP → raus
        "kein-dict",
    ]
    obs = arp_fortigate.observations(rows, "fw-a", "root", "fallback-if")
    assert obs == [{"ip": "10.1.1.10", "mac": MAC_A, "device": "fw-a",
                    "vdom": "root", "interface": "lan1", "source": "fortigate"}]


# ── Offline-Fallback ─────────────────────────────────────────────────────────

async def test_offline_host_is_located_from_history(inventory, prefixes):
    """Der eigentliche Zweck: Host ist aus, Live-ARP kennt ihn nicht — die
    aufgezeichnete Bindung führt trotzdem zum Port."""
    store = FakeStore({"10.1.1.10": [_binding("10.1.1.10", MAC_A, age_days=3)]})
    res = await _locate(_chain(store), prefixes, "10.1.1.10")

    assert res["mac"] == MAC_A
    assert res["arp"]["provenance"] == "cache"
    assert res["from_cache"]["mac"] == MAC_A
    assert res["best"]["if_name"] == "Gi1/0/7"        # Portsuche lief durch
    warn = " ".join(res["warnings"])
    assert "antwortet gerade nicht" in warn
    assert "letzten bekannten Stand" in warn and "nicht den aktuellen" in warn


async def test_cache_hit_never_claims_high_confidence(inventory, prefixes):
    """Ein Access-Port-Treffer wäre live 'high'. Aus der Historie darf er das
    nicht sein — die Gegenwart ist nicht belegt."""
    store = FakeStore({"10.1.1.10": [_binding("10.1.1.10", MAC_A, age_days=1)]})
    res = await _locate(_chain(store), prefixes, "10.1.1.10")

    assert res["best"]["port_kind"] == "access"
    assert res["confidence"] == "medium"


async def test_multiple_macs_on_one_ip_are_flagged(inventory, prefixes):
    """Gerätetausch: an derselben IP standen nacheinander zwei MACs. Die neuere
    gewinnt, die ältere muss sichtbar bleiben."""
    store = FakeStore({"10.1.1.10": [
        _binding("10.1.1.10", MAC_A, age_days=2),
        _binding("10.1.1.10", MAC_B, age_days=40),
    ]})
    res = await _locate(_chain(store), prefixes, "10.1.1.10")

    assert res["mac"] == MAC_A                       # zuletzt gesehene
    assert [h["mac"] for h in res["ip_history"]] == [MAC_A, MAC_B]
    warn = " ".join(res["warnings"])
    assert "mehrere MACs" in warn and MAC_B in warn
    assert "Gerätetausch" in warn


async def test_without_history_the_old_message_stands(inventory, prefixes):
    store = FakeStore({})
    res = await _locate(_chain(store), prefixes, "10.1.1.10")

    assert res["mac"] is None and res["from_cache"] is None
    assert res["ip_history"] == []
    assert "aufgezeichnete Historie" in " ".join(res["warnings"])


async def test_broken_store_does_not_break_the_search(inventory, prefixes):
    """Eine hakende Datenbank ist Beiwerk — sie darf die Suche nicht kippen."""
    res = await _locate(_chain(FakeStore(fail=True)), prefixes, "10.1.1.10")

    assert res["mac"] is None          # kein Treffer, aber auch keine Exception
    assert res["warnings"]


# ── FortiAnalyzer als MAC-Quelle ─────────────────────────────────────────────

def _faz(mac: str | None, age_s: int | None, name: str = "plc-10"):
    async def lookup(ip):
        return {"ip": ip, "mac": mac, "name": name, "last_seen": "2026-10-09T10:00:00+00:00",
                "age_s": age_s, "os": None, "epid": 1} if mac else None
    return lookup


async def _locate_faz(chain, prefixes, ip: str, faz) -> dict:
    return await chain.locate(ip, prefixes, {"base_url": "", "token": ""},
                              {"host": ""}, Config(), faz=faz)


async def test_faz_mac_is_used_before_the_history(inventory, prefixes):
    """Der FAZ ist aktueller als die Aufzeichnung — seine MAC gewinnt."""
    store = FakeStore({"10.1.1.10": [_binding("10.1.1.10", MAC_B, age_days=20)]})
    res = await _locate_faz(_chain(store), prefixes, "10.1.1.10", _faz(MAC_A, 600))

    assert res["mac"] == MAC_A and res["arp"]["provenance"] == "faz"
    assert res["from_faz"]["name"] == "plc-10" and res["from_cache"] is None
    assert res["best"]["if_name"] == "Gi1/0/7" and res["confidence"] == "high"
    assert "FortiAnalyzer" in " ".join(res["warnings"])
    assert store.recorded == []                     # FAZ-Zeit ist nicht „jetzt"


async def test_old_faz_entry_does_not_claim_high_confidence(inventory, prefixes):
    res = await _locate_faz(_chain(FakeStore({})), prefixes, "10.1.1.10", _faz(MAC_A, 3 * 86400))
    assert res["arp"]["provenance"] == "faz" and res["confidence"] == "medium"


async def test_without_faz_hit_the_history_still_answers(inventory, prefixes):
    store = FakeStore({"10.1.1.10": [_binding("10.1.1.10", MAC_A, age_days=3)]})
    res = await _locate_faz(_chain(store), prefixes, "10.1.1.10", _faz(None, None))
    assert res["arp"]["provenance"] == "cache" and res["from_faz"] is None


async def test_broken_faz_does_not_break_the_search(inventory, prefixes):
    async def broken(ip):
        raise RuntimeError("FAZ weg")
    store = FakeStore({"10.1.1.10": [_binding("10.1.1.10", MAC_A, age_days=3)]})
    res = await _locate_faz(_chain(store), prefixes, "10.1.1.10", broken)
    assert res["arp"]["provenance"] == "cache"
    assert "FortiAnalyzer nicht abrufbar: FAZ weg" in res["warnings"]
