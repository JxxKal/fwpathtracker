"""Reverse-DNS-Cache: was gemerkt wird, was nicht, und was er spart.

Der teure Teil sind die Adressen OHNE PTR-Eintrag — die laufen jedes Mal in
die volle Zeitüberschreitung. Genau deshalb muss auch die Fehlanzeige in den
Cache, sonst bringt er wenig.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from resolver.dns_cache import ReverseResolver, normalize_ip  # noqa: E402


class FakeCache:
    def __init__(self, rows=None):
        self.rows = dict(rows or {})
        self.written: dict = {}
        self.touched: list = []

    async def get(self, ips, hit_ttl_s=0, miss_ttl_s=0):
        return {ip: self.rows[ip] for ip in ips if ip in self.rows}

    async def put(self, entries):
        self.written.update(entries)
        self.rows.update(entries)
        return len(entries)

    async def touch(self, ips):
        self.touched.extend(ips)


def test_ip_is_normalised_before_it_becomes_a_key():
    assert normalize_ip(" 10.1.2.3 ") == "10.1.2.3"
    assert normalize_ip("010.1.2.3") is None      # führende Nullen sind mehrdeutig
    assert normalize_ip("kein.host") is None


async def test_known_names_cost_no_query():
    asked = []

    async def ask(ip):
        asked.append(ip)
        return "neu.op-tech.com"

    cache = FakeCache({"10.1.1.5": "alt.op-tech.com"})
    rev = ReverseResolver(cache, ask)
    await rev.prime(["10.1.1.5", "10.1.1.6"])
    assert await rev("10.1.1.5") == "alt.op-tech.com"
    assert asked == [], "bekannte Adresse wurde trotzdem gefragt"
    assert await rev("10.1.1.6") == "neu.op-tech.com"
    assert asked == ["10.1.1.6"]
    assert rev.stats == {"cached": 1, "asked": 1, "found": 1}


async def test_a_miss_is_remembered_too():
    """Sonst läuft jede Zeichnung wieder in dieselben Zeitüberschreitungen."""
    asked = []

    async def ask(ip):
        asked.append(ip)
        return None

    cache = FakeCache()
    rev = ReverseResolver(cache, ask)
    assert await rev("10.1.1.9") is None
    await rev.flush()
    assert cache.written == {"10.1.1.9": None}

    # Zweiter Lauf, frischer Resolver: die Fehlanzeige trägt.
    rev2 = ReverseResolver(cache, ask)
    await rev2.prime(["10.1.1.9"])
    assert await rev2("10.1.1.9") is None
    assert asked == ["10.1.1.9"], "die Fehlanzeige wurde nicht genutzt"
    assert rev2.stats["cached"] == 1


async def test_a_failing_lookup_is_not_remembered():
    """Ein Netzfehler ist keine Aussage über den Namen — sonst hält der Cache
    eine Störung tagelang fest."""
    async def ask(ip):
        raise TimeoutError("DNS weg")

    cache = FakeCache()
    rev = ReverseResolver(cache, ask)
    assert await rev("10.1.1.4") is None
    await rev.flush()
    assert cache.written == {}


async def test_a_broken_cache_never_breaks_the_lookup():
    """Der Cache ist Beiwerk: fällt er aus, wird eben gefragt."""
    class Broken(FakeCache):
        async def get(self, ips, hit_ttl_s=0, miss_ttl_s=0):
            raise RuntimeError("DB weg")

        async def put(self, entries):
            raise RuntimeError("DB weg")

        async def touch(self, ips):
            raise RuntimeError("DB weg")

    async def ask(ip):
        return "da.op-tech.com"

    rev = ReverseResolver(Broken(), ask)
    await rev.prime(["10.1.1.7"])
    assert await rev("10.1.1.7") == "da.op-tech.com"
    await rev.flush()


async def test_without_a_cache_it_simply_resolves():
    async def ask(ip):
        return "ohne-cache.op-tech.com"

    rev = ReverseResolver(None, ask)
    await rev.prime(["10.1.1.8"])
    assert await rev("10.1.1.8") == "ohne-cache.op-tech.com"
    await rev.flush()


# ── Einstellungen ────────────────────────────────────────────────────────────

class FakeState:
    dns_cache = "der-cache"


async def test_settings_steer_the_lifetimes():
    from resolver.dns_cache import build_reverse

    rev = await build_reverse(FakeState(), {
        "search_domains": ["op-tech.com"],
        "cache_hit_days": 3, "cache_miss_hours": 6,
    })
    assert rev._hit_ttl_s == 3 * 24 * 3600
    assert rev._miss_ttl_s == 6 * 3600
    assert rev._cache == "der-cache"


async def test_zero_lifetimes_switch_the_cache_off():
    """Sonst kostet jeder Aufruf eine Abfrage, die garantiert nichts liefert."""
    from resolver.dns_cache import build_reverse

    rev = await build_reverse(FakeState(), {
        "search_domains": ["op-tech.com"], "cache_hit_days": 0, "cache_miss_hours": 0,
    })
    assert rev is not None
    assert rev._cache is None


async def test_a_nonsense_setting_falls_back_instead_of_breaking():
    from resolver.dns_cache import build_reverse

    rev = await build_reverse(FakeState(), {
        "search_domains": ["op-tech.com"], "cache_hit_days": "", "cache_miss_hours": None,
    })
    assert rev._hit_ttl_s == 7 * 24 * 3600
    assert rev._miss_ttl_s == 24 * 3600


async def test_without_resolvers_and_domains_nobody_is_asked():
    """Jede Anfrage liefe in die Zeitüberschreitung — hundertfach pro Zeichnung."""
    from resolver.dns_cache import build_reverse

    assert await build_reverse(FakeState(), {}) is None
    assert await build_reverse(FakeState(), {"resolvers": [], "search_domains": []}) is None
