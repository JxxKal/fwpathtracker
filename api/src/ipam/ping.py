"""ICMP-Erreichbarkeit einer Adresse — über das ping-Binary des Containers.

Kein Raw-Socket in Python: das ping-Binary (iputils) bringt die nötigen
File-Capabilities mit und ist im Image installiert. Fehlt es (lokaler Dev-Lauf
ohne iputils), liefert die Probe None statt zu raten — das Ergebnis zeigt dann
„nicht prüfbar" statt „frei".

Zwei Pakete kurz hintereinander, damit ein Host, der das erste ARP-bedingt
verschluckt, nicht als tot durchgeht. Exit 0 = mindestens eine Antwort.
"""
from __future__ import annotations

import asyncio
import shutil

_TIMEOUT_S = 1


def available() -> bool:
    return shutil.which("ping") is not None


async def ping(ip: str, timeout_s: float = _TIMEOUT_S) -> bool | None:
    """True = antwortet, False = keine Antwort, None = Ping nicht verfügbar."""
    try:
        proc = await asyncio.create_subprocess_exec(
            "ping", "-n", "-q", "-c", "2", "-i", "0.3", "-W", str(int(timeout_s)), ip,
            stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL,
        )
    except (FileNotFoundError, PermissionError):
        return None
    try:
        rc = await asyncio.wait_for(proc.wait(), timeout=timeout_s * 2 + 2)
    except asyncio.TimeoutError:
        proc.kill()
        await proc.wait()
        return False
    return rc == 0
