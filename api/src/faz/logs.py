"""Traffic-Logs des FortiAnalyzer auswerten — das Ist neben der Theorie.

Der Pfad-Tracker weiß, was die Regeln JETZT erlauben. Die Logs wissen, was
tatsächlich passiert ist, und zwar auch gestern. Daraus zwei Fragen:

- „Gestern ging es noch": derselbe Flow über die Zeit — wann zuletzt erlaubt,
  seit wann geblockt, auf welcher Firewall von welcher Regel.
- „Was wird bei Host X gerade geblockt?": alle Denies eines Hosts, gruppiert
  nach Gegenstelle und Port.

Alles hier ist rein funktional (Logzeilen rein, Auswertung raus); die Suche
selbst macht `FazSource.logsearch`.
"""
from __future__ import annotations

import ipaddress
from collections import Counter
from datetime import datetime, timedelta, timezone
from typing import Any, Callable
from zoneinfo import ZoneInfo

PROTO_NUM = {"tcp": 6, "udp": 17, "icmp": 1}
PROTO_NAME = {v: k for k, v in PROTO_NUM.items()}

# Abschlussgründe einer erlaubten Session. 'ip-conn' heißt: erlaubt, aber die
# Gegenstelle hat nicht geantwortet — für die Firewall-Frage ist das „durch".
ALLOW_ACTIONS = {"accept", "close", "timeout", "server-rst", "client-rst", "start",
                 "ip-conn", "dns", "perf-stats"}
DENY_ACTIONS = {"deny", "blocked", "block", "reject", "drop"}

IMPLICIT_DENY = 0
# Ab hier kein Verkehr mehr gesehen → „kommt nicht mehr an" statt „läuft".
SILENT_AFTER_S = 3600


def tz_of(cfg: dict) -> ZoneInfo | timezone:
    try:
        return ZoneInfo(str(cfg.get("timezone") or "Europe/Berlin"))
    except Exception:
        return timezone.utc


def time_range(hours: float, tz, now: datetime | None = None) -> tuple[str, str]:
    """Zeitfenster in FAZ-Schreibweise. Der FAZ liest es in SEINER Zeitzone —
    daher die konfigurierbare tz statt UTC."""
    now = (now or datetime.now(timezone.utc)).astimezone(tz)
    start = now - timedelta(hours=hours)
    fmt = "%Y-%m-%d %H:%M:%S"
    return start.strftime(fmt), now.strftime(fmt)


def _ip(value: str) -> str:
    """Nur gültige IPv4 (oder Netz) gelangt in einen Filterausdruck."""
    v = str(value).strip()
    if "/" in v:
        return str(ipaddress.IPv4Network(v, strict=False))
    return str(ipaddress.IPv4Address(v))


def flow_filter(src: str, dst: str, protocol: str | None = None,
                dst_port: int | None = None) -> str:
    parts = [f"srcip=={_ip(src)}", f"dstip=={_ip(dst)}"]
    proto = PROTO_NUM.get((protocol or "").lower())
    if proto is not None:
        parts.append(f"proto=={proto}")
    if dst_port and proto in (6, 17):
        parts.append(f"dstport=={int(dst_port)}")
    return " and ".join(parts)


def deny_filter(ip: str, direction: str) -> str:
    field = "srcip" if direction == "src" else "dstip"
    return f"{field}=={_ip(ip)} and action==deny"


def outcome(rec: dict) -> str:
    action = str(rec.get("action") or "").strip().lower()
    utm = str(rec.get("utmaction") or "").strip().lower()
    if action in DENY_ACTIONS or utm in ("block", "blocked"):
        return "deny"
    if action in ALLOW_ACTIONS:
        return "allow"
    return "other"


def _epoch(value: Any) -> float | None:
    try:
        n = float(value)
    except (TypeError, ValueError):
        return None
    if n <= 0:
        return None
    while n > 1e11:          # ns/µs/ms → s (eventtime ist je nach FortiOS ns oder µs)
        n /= 1000
    return n


def log_time(rec: dict, tz) -> datetime | None:
    """Zeit des Ereignisses: eventtime vom Gerät, sonst itime (Empfang am FAZ),
    sonst date+time in FAZ-Zeitzone."""
    for k in ("eventtime", "itime", "dtime"):
        n = _epoch(rec.get(k))
        if n is not None:
            return datetime.fromtimestamp(n, tz=timezone.utc)
    d, t = rec.get("date"), rec.get("time")
    if d and t:
        try:
            return datetime.fromisoformat(f"{d}T{t}").replace(tzinfo=tz).astimezone(timezone.utc)
        except ValueError:
            return None
    return None


def _int(value: Any) -> int | None:
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return None


def _bytes(rec: dict) -> int:
    return (_int(rec.get("sentbyte")) or 0) + (_int(rec.get("rcvdbyte")) or 0)


PolicyName = Callable[[str | None, str | None, int | None], str | None]


def _policy_label(pid: int | None, name: str | None) -> str:
    if pid == IMPLICIT_DENY:
        return "Implicit Deny"
    if pid is None:
        return "—"
    return f"{pid}" + (f" · {name}" if name else "")


def _iso(ts: datetime | None) -> str | None:
    return ts.isoformat() if ts else None


def _bucket_size(hours: float) -> timedelta:
    if hours <= 6:
        return timedelta(minutes=15)
    if hours <= 48:
        return timedelta(hours=1)
    return timedelta(days=1)


def _timeline(events: list[tuple[datetime, str]], start: datetime, end: datetime,
              size: timedelta) -> list[dict]:
    """Erlaubt/geblockt je Zeitscheibe — lückenlos, damit Stille sichtbar ist."""
    n = max(1, int((end - start) / size) + 1)
    slots = [{"start": (start + i * size).isoformat(), "allow": 0, "deny": 0}
             for i in range(n)]
    for ts, kind in events:
        i = int((ts - start) / size)
        if 0 <= i < n and kind in ("allow", "deny"):
            slots[i][kind] += 1
    return slots


def flow_history(logs: list[dict], *, hours: float, tz, policy_name: PolicyName,
                 now: datetime | None = None, complete: bool = True,
                 limit_hit: bool = False) -> dict:
    """Verlauf eines Flows: je Firewall/VDOM/Regel, als Zeitleiste und als
    Befund („seit … geblockt", „seit … kein Verkehr", „durchgehend erlaubt")."""
    now = now or datetime.now(timezone.utc)
    start = now - timedelta(hours=hours)
    hops: dict[tuple, dict] = {}
    events: list[tuple[datetime, str]] = []
    for rec in logs:
        ts = log_time(rec, tz)
        kind = outcome(rec)
        if ts is None:
            continue
        events.append((ts, kind))
        dev, vd = rec.get("devname") or rec.get("devid"), rec.get("vd") or None
        pid = _int(rec.get("policyid"))
        key = (dev, vd, pid, kind)
        h = hops.get(key)
        if h is None:
            h = hops[key] = {
                "device": dev, "vdom": vd, "policyid": pid,
                "policy": _policy_label(pid, policy_name(dev, vd, pid)),
                "outcome": kind, "count": 0, "bytes": 0, "first": ts, "last": ts,
                "srcintf": rec.get("srcintf"), "dstintf": rec.get("dstintf"),
                "actions": Counter(), "services": Counter()}
        h["count"] += 1
        h["bytes"] += _bytes(rec)
        h["first"], h["last"] = min(h["first"], ts), max(h["last"], ts)
        h["actions"][str(rec.get("action") or "?")] += 1
        if rec.get("service"):
            h["services"][str(rec["service"])] += 1

    events.sort()
    allows = [ts for ts, k in events if k == "allow"]
    denies = [ts for ts, k in events if k == "deny"]
    last_allow, last_deny = (allows[-1] if allows else None), (denies[-1] if denies else None)

    verdict, since, blocker = "none", None, None
    if not events:
        verdict = "none"
    elif last_deny and (not last_allow or last_deny > last_allow):
        # Erster Deny nach dem letzten Allow = der Wendepunkt.
        since = next((ts for ts in denies if not last_allow or ts > last_allow), last_deny)
        verdict = "blocked_since" if last_allow else "always_blocked"
        recent = [h for h in hops.values() if h["outcome"] == "deny" and h["last"] >= since]
        blocker = max(recent, key=lambda h: h["count"], default=None)
    elif last_allow and (now - last_allow).total_seconds() > SILENT_AFTER_S:
        verdict, since = "silent_since", last_allow
    elif denies:
        verdict, since = "allowed_again", next(ts for ts in allows if ts > last_deny)
    else:
        verdict = "always_allowed"

    def out(h: dict) -> dict:
        return dict(h, first=_iso(h["first"]), last=_iso(h["last"]),
                    actions=dict(h["actions"].most_common()),
                    services=[s for s, _ in h["services"].most_common(3)])

    rows = sorted((out(h) for h in hops.values()), key=lambda h: h["last"], reverse=True)
    return {
        "verdict": verdict, "since": _iso(since),
        "last_allow": _iso(last_allow), "last_deny": _iso(last_deny),
        "first_seen": _iso(events[0][0]) if events else None,
        "last_seen": _iso(events[-1][0]) if events else None,
        "blocker": out(blocker) if blocker else None,
        "counts": {"allow": len(allows), "deny": len(denies),
                   "other": len(events) - len(allows) - len(denies), "lines": len(logs)},
        "hops": rows,
        "timeline": _timeline(events, start, now, _bucket_size(hours)),
        "bucket_s": int(_bucket_size(hours).total_seconds()),
        "complete": complete, "limit_hit": limit_hit,
    }


def blocked(logs: list[dict], *, direction: str, tz, policy_name: PolicyName) -> list[dict]:
    """Denies eines Hosts je Gegenstelle/Port/Firewall/Regel, häufigste zuerst."""
    peer_key = "dstip" if direction == "src" else "srcip"
    groups: dict[tuple, dict] = {}
    for rec in logs:
        if outcome(rec) != "deny":
            continue
        ts = log_time(rec, tz)
        proto = _int(rec.get("proto"))
        port = _int(rec.get("dstport")) if proto in (6, 17) else None
        dev, vd, pid = rec.get("devname") or rec.get("devid"), rec.get("vd") or None, \
            _int(rec.get("policyid"))
        key = (rec.get(peer_key), proto, port, dev, vd, pid)
        g = groups.get(key)
        if g is None:
            g = groups[key] = {
                "direction": direction, "peer": rec.get(peer_key),
                "src": rec.get("srcip"), "dst": rec.get("dstip"),
                "protocol": PROTO_NAME.get(proto, str(proto) if proto is not None else None),
                "dst_port": port, "service": rec.get("service"),
                "device": dev, "vdom": vd, "policyid": pid,
                "policy": _policy_label(pid, policy_name(dev, vd, pid)),
                "srcintf": rec.get("srcintf"), "dstintf": rec.get("dstintf"),
                "count": 0, "first": ts, "last": ts}
        g["count"] += 1
        if ts:
            g["first"] = min(filter(None, (g["first"], ts)))
            g["last"] = max(filter(None, (g["last"], ts)))
    rows = [dict(g, first=_iso(g["first"]), last=_iso(g["last"])) for g in groups.values()]
    return sorted(rows, key=lambda g: (g["count"], g["last"] or ""), reverse=True)
