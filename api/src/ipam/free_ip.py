"""Freie IP-Adresse finden: iTop-Bestand × Live-Ping × Reverse-DNS × ARP.

Warum vier Quellen: iTop sagt, was *vergeben* ist — nicht, was *benutzt* wird.
Eine als frei geführte Adresse kann längst ein Gerät tragen, das nie
eingetragen wurde; eine „zugewiesene" muss nicht reserviert sein und
umgekehrt. Deshalb zählt in iTop beides als belegt: ein IPv4Address-Objekt
mit Status allocated/reserved UND eine Management-IP eines Servers/Netzgeräts,
selbst wenn zu ihr gar kein Adressobjekt existiert. Die Firewall-Interfaces
aus dem FMG-Inventar kommen dazu.

Was iTop als frei durchlässt, wird live geprüft: Ping (antwortet jemand?),
PTR-Eintrag (kennt das DNS die Adresse?) und die IP↔MAC-Historie (hat hier
kürzlich ein Gerät gesprochen, das gerade aus ist?). Erst wenn alle drei
still sind, gilt die Adresse als frei. Ping allein reicht nicht — ein Host
mit strenger Host-Firewall antwortet nicht und ist trotzdem da.
"""
from __future__ import annotations

import asyncio
import ipaddress
from collections.abc import Awaitable, Callable

# TeemIP IPv4Address.status — nur diese beiden binden die Adresse.
USED_STATUS = {"allocated", "reserved"}

MAX_WANT = 50
MAX_PROBE = 256
CONCURRENCY = 32

PingFn = Callable[[str], Awaitable[bool | None]]
DnsFn = Callable[[str], Awaitable[str | None]]
ArpFn = Callable[[str], Awaitable[dict | None]]


def _range_bounds(net: ipaddress.IPv4Network, start: str | None,
                  end: str | None) -> tuple[ipaddress.IPv4Address, ipaddress.IPv4Address]:
    lo = ipaddress.IPv4Address(start) if start else net.network_address
    hi = ipaddress.IPv4Address(end) if end else net.broadcast_address
    if lo not in net or hi not in net:
        raise ValueError(f"Start/Ende liegen nicht in {net}.")
    if hi < lo:
        raise ValueError("Ende liegt vor dem Start.")
    return lo, hi


def host_addresses(net: ipaddress.IPv4Network, start: str | None = None,
                   end: str | None = None):
    """Host-Adressen des Netzes (ohne Netz-/Broadcast-Adresse), optional auf
    [start, end] eingeschränkt. /31 und /32 haben keine Netz-/Broadcast-Adresse."""
    lo, hi = _range_bounds(net, start, end)
    skip = set()
    if net.prefixlen < 31:
        skip = {net.network_address, net.broadcast_address}
    addr = lo
    while addr <= hi:
        if addr not in skip:
            yield addr
        if addr == ipaddress.IPv4Address("255.255.255.255"):
            break
        addr += 1


def verdict(ping: bool | None, dns: str | None, arp: dict | None) -> str:
    """in_use: antwortet gerade. suspect: still, aber DNS oder ARP-Historie kennen
    sie. free: nichts spricht dagegen. unknown: Ping nicht prüfbar UND keine
    andere Quelle — das Ergebnis wäre bloß geraten."""
    if ping:
        return "in_use"
    if dns or arp:
        return "suspect"
    if ping is None:
        return "unknown"
    return "free"


async def find_free(
    net: ipaddress.IPv4Network, *,
    itop_addresses: dict[str, dict],      # ip → {status, name}
    ci_hosts: dict[str, str],             # ip → CI-Name (Management-IP)
    fw_ips: dict[str, str],               # ip → "device/vdom/intf"
    dhcp_ranges: list[tuple[ipaddress.IPv4Address, ipaddress.IPv4Address, str]],
    gateway: str | None,
    ping: PingFn, dns: DnsFn, arp: ArpFn,
    want: int = 10, start: str | None = None, end: str | None = None,
    max_probe: int = MAX_PROBE, concurrency: int = CONCURRENCY,
) -> dict:
    want = max(1, min(want, MAX_WANT))
    stats = {"hosts": 0, "itop_used": 0, "ci_used": 0, "fw_used": 0,
             "dhcp_skipped": 0, "gateway_skipped": 0, "probed": 0, "free": 0}

    def in_dhcp(addr: ipaddress.IPv4Address) -> str | None:
        for lo, hi, name in dhcp_ranges:
            if lo <= addr <= hi:
                return name or "DHCP"
        return None

    # Erst der Bestand: was iTop/FMG belegen, wird gar nicht erst angefasst.
    candidates: list[tuple[str, dict | None]] = []
    for addr in host_addresses(net, start, end):
        stats["hosts"] += 1
        ip = str(addr)
        if gateway and ip == gateway:
            stats["gateway_skipped"] += 1
            continue
        rec = itop_addresses.get(ip)
        if rec and (rec.get("status") or "").lower() in USED_STATUS:
            stats["itop_used"] += 1
            continue
        if ip in ci_hosts:
            stats["ci_used"] += 1
            continue
        if ip in fw_ips:
            stats["fw_used"] += 1
            continue
        if in_dhcp(addr):
            stats["dhcp_skipped"] += 1
            continue
        candidates.append((ip, rec))

    sem = asyncio.Semaphore(concurrency)

    async def probe(ip: str, rec: dict | None) -> dict:
        async with sem:
            p, d, a = await asyncio.gather(ping(ip), dns(ip), arp(ip))
        return {
            "ip": ip,
            "itop": ({"status": rec.get("status"), "name": rec.get("name")} if rec else None),
            "ping": p, "dns": d, "arp": a,
            "verdict": verdict(p, d, a),
        }

    # Dann in Wellen prüfen, bis genug freie beisammen sind — die ganze
    # Kandidatenliste zu pingen wäre in einem /16 nicht zu verantworten.
    results: list[dict] = []
    pos = 0
    free = 0
    while pos < len(candidates) and free < want and stats["probed"] < max_probe:
        wave = candidates[pos:pos + min(concurrency, max_probe - stats["probed"])]
        pos += len(wave)
        got = await asyncio.gather(*(probe(ip, rec) for ip, rec in wave))
        stats["probed"] += len(got)
        for r in got:
            results.append(r)
            if r["verdict"] == "free":
                free += 1
    stats["free"] = free
    return {
        "results": results, "stats": stats,
        "exhausted": pos >= len(candidates),
        "ping_available": not results or any(r["ping"] is not None for r in results),
    }
