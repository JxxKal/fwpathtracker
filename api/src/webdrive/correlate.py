"""Verknüpfung der Ereignisse über drei Schlüssel.

Kein Log enthält alles: der FAC kennt den Usernamen und eine Token-Maske,
OpenCloud nur seine interne opaque_id. Die Brücke:

    Username ──(Portal-Login, ≤ 5 s)──▶ Token ──(Userinfo-Abrufe ≙ Sitzungen)──▶ opaque_id

Jeder Userinfo-Abruf von OpenCloud beim FAC fällt sekundengenau auf eine
OpenCloud-Sitzung desselben Users (am 07.10.2026: 33 von 33, 60 von 60 …).
Zugeordnet wird deshalb über *wiederholtes* Zusammentreffen, nicht über einen
einzelnen Zeitpunkt — eine zufällig gleichzeitige Sitzung eines anderen Users
kann so keinen falschen Namen erzeugen.
"""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime

from webdrive.parse import Event

PAIR_S = 2         # Fehlversuch ↔ Grund (FAC schreibt beide in derselben Sekunde)
TOKEN_S = 5        # Portal-Login ↔ Token (am 07.10.2026 bis zu 4 s Abstand)
MATCH_S = 1        # Userinfo-Abruf ↔ OpenCloud-Sitzung
MIN_MATCHES = 2


def _dt(a: datetime, b: datetime) -> float:
    return abs((a - b).total_seconds())


@dataclass
class Failure:
    username: str
    ts: datetime
    reason: str        # Rohgrund des FAC ('invalid password', …); '' = unbekannt
    client_ip: str
    entered: str       # wie eingegeben — bei Realm-Fehlern genau das Problem


def pair_failures(events: list[Event]) -> list[Failure]:
    """Fehlgeschlagener Portal-Login + der Grund, den der FAC daneben schreibt."""
    reasons = [e for e in events if e.kind == "auth_failed_reason"]
    out = []
    for e in events:
        if e.kind != "portal_login_failed" or not e.username:
            continue
        cand = [r for r in reasons if r.username == e.username and _dt(r.ts, e.ts) <= PAIR_S]
        best = min(cand, key=lambda r: _dt(r.ts, e.ts)) if cand else None
        out.append(Failure(e.username, e.ts, best.data["reason"] if best else "",
                           e.data.get("client_ip", ""), e.data.get("entered") or e.username))
    return out


def map_tokens(events: list[Event]) -> dict[str, str]:
    """Token-Maske → Username. Der FAC stellt den Token wenige Sekunden nach dem
    Portal-Login aus, nicht immer über denselben Knoten (Client-IP kann
    abweichen). Mehrdeutig → keine Zuordnung statt einer falschen."""
    logins = [e for e in events if e.kind == "portal_login_ok" and e.username]
    out: dict[str, str] = {}
    for t in events:
        if t.kind != "token_issued" or not t.token:
            continue
        cand = [l for l in logins if 0 <= (t.ts - l.ts).total_seconds() <= TOKEN_S]
        same_ip = [l for l in cand if l.data.get("client_ip") == t.data.get("client_ip")]
        names = {l.username for l in (same_ip or cand)}
        if len(names) == 1:
            out[t.token] = names.pop()
    return out


def new_identities(events: list[Event], known: set[str]) -> dict[str, tuple[str, datetime]]:
    """Neue Zuordnungen opaque_id → (Username, erste Sitzung) für bisher unbekannte IDs."""
    tokens = map_tokens(events)
    infos: dict[str, list[datetime]] = defaultdict(list)
    sessions: dict[str, list[datetime]] = defaultdict(list)
    for e in events:
        if e.kind == "userinfo_ok" and e.token in tokens:
            infos[e.token].append(e.ts)
        elif e.kind == "session_seen" and e.opaque_id and e.opaque_id not in known:
            sessions[e.opaque_id].append(e.ts)

    out: dict[str, tuple[str, datetime]] = {}
    for tok, times in infos.items():
        if len(times) < MIN_MATCHES:
            continue          # 1 Abruf = abgelehnte Erstanmeldung, keine Sitzung
        scores = sorted(
            ((sum(1 for t in times if any(_dt(t, s) <= MATCH_S for s in ss)), o)
             for o, ss in sessions.items()),
            reverse=True,
        )
        if not scores:
            continue
        top, best = scores[0]
        if top < max(MIN_MATCHES, len(times) // 2):
            continue
        if len(scores) > 1 and scores[1][0] == top:
            continue
        if best not in out:
            out[best] = (tokens[tok], min(sessions[best]))
    return out
