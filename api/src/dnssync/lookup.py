"""PTR je IP und Gegenprobe (A des PTR-Namens zeigt wieder auf die IP)."""
from __future__ import annotations

import asyncio

import dns.asyncresolver
import dns.exception
import dns.reversename

from resolver.dns_source import _resolver

PARALLEL = 24


async def check(dns_cfg: dict, ips: list[str], timeout_s: float = 2.5) -> dict[str, dict]:
    """ip → {ptr: [namen], forward: {name: [ips]}}."""
    res: dns.asyncresolver.Resolver = _resolver(dns_cfg, timeout_s)
    sem = asyncio.Semaphore(PARALLEL)
    out: dict[str, dict] = {}

    async def one(ip: str) -> None:
        async with sem:
            names: list[str] = []
            try:
                ans = await res.resolve(dns.reversename.from_address(ip), "PTR")
                names = sorted({r.to_text().rstrip(".").lower() for r in ans})
            except (dns.exception.DNSException, asyncio.TimeoutError, ValueError):
                pass
            fwd: dict[str, list[str]] = {}
            for n in names[:3]:
                try:
                    a = await res.resolve(n + ".", "A")
                    fwd[n] = sorted(r.to_text() for r in a)
                except (dns.exception.DNSException, asyncio.TimeoutError):
                    fwd[n] = []
            out[ip] = {"ptr": names, "forward": fwd}

    await asyncio.gather(*(one(ip) for ip in ips))
    return out
