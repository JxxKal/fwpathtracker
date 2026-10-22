"""Zeitfenster des Wochenreports: lückenlos von Lauf zu Lauf.

Der Bericht deckt genau die Zeit seit dem letzten Bericht ab — keine Lücke,
keine Überlappung. Ist ein Lauf ausgefallen, holt der nächste ihn als eigenen
Bericht nach, statt ein Doppelfenster zu bilden.
"""
from __future__ import annotations

from datetime import datetime, time, timedelta, timezone
from zoneinfo import ZoneInfo

WEEK = timedelta(days=7)
MAX_CATCHUP = 4
DAY_NAMES = ("Mo", "Di", "Mi", "Do", "Fr", "Sa", "So")


def tz_of(cfg: dict):
    try:
        return ZoneInfo(str(cfg.get("timezone") or "Europe/Berlin"))
    except Exception:
        return timezone.utc


def _slot_time(cfg: dict) -> time:
    try:
        h, m = str(cfg.get("time") or "06:30").split(":", 1)
        return time(int(h), int(m))
    except ValueError:
        return time(6, 30)


def last_slot(now: datetime, cfg: dict) -> datetime:
    """Der jüngste planmäßige Zeitpunkt ≤ now (Wochentag 0 = Montag, Default Freitag)."""
    tz = tz_of(cfg)
    local = now.astimezone(tz)
    weekday = int(cfg.get("weekday", 4)) % 7
    day = local.date() - timedelta(days=(local.weekday() - weekday) % 7)
    slot = datetime.combine(day, _slot_time(cfg), tzinfo=tz)
    if slot > local:
        slot = datetime.combine(day - WEEK, _slot_time(cfg), tzinfo=tz)
    return slot.astimezone(timezone.utc)


def due(now: datetime, cfg: dict, last_end: datetime | None) -> list[tuple[datetime, datetime]]:
    """Fällige Zeitfenster. Leer, wenn abgeschaltet oder schon erledigt."""
    if not cfg.get("enabled"):
        return []
    slot = last_slot(now, cfg)
    if last_end is None:
        return [(slot - WEEK, slot)]
    if last_end >= slot:
        return []
    out, start = [], max(last_end, slot - WEEK * MAX_CATCHUP)
    while start < slot:
        end = min(start + WEEK, slot)
        out.append((start, end))
        start = end
    return out


def label(start: datetime, end: datetime, cfg: dict) -> dict:
    """KW (nach dem Tag vor dem Ende — der Bericht am Freitagmorgen gilt der
    Woche, die gerade endet) und lesbare Zeitangaben."""
    tz = tz_of(cfg)
    ls, le = start.astimezone(tz), end.astimezone(tz)
    year, week, _ = (le - timedelta(seconds=1)).isocalendar()
    return {"kw": f"KW {week}/{year}", "kw_key": f"{year}-W{week:02d}",
            "from": ls.strftime("%d.%m.%Y %H:%M"), "to": le.strftime("%d.%m.%Y %H:%M")}


def days(start: datetime, end: datetime, cfg: dict) -> list[dict]:
    """Tagesraster für Diagramme: lokale Kalendertage, die das Fenster berührt (≤ 31)."""
    tz = tz_of(cfg)
    d, last = start.astimezone(tz).date(), (end - timedelta(seconds=1)).astimezone(tz).date()
    out = []
    while d <= last and len(out) < 31:
        out.append({"date": d.isoformat(), "label": f"{DAY_NAMES[d.weekday()]} {d.day:02d}.{d.month:02d}."})
        d += timedelta(days=1)
    return out


def day_index(ts: datetime, start: datetime, cfg: dict, n: int) -> int | None:
    tz = tz_of(cfg)
    i = (ts.astimezone(tz).date() - start.astimezone(tz).date()).days
    return i if 0 <= i < n else None


def off_hours(ts: datetime, cfg: dict) -> str | None:
    """Außerhalb der Arbeitszeit? 'Wochenende' oder 'nachts', sonst None.
    Arbeitszeit konfigurierbar als work_hours 'HH-HH' (Default 06-20)."""
    local = ts.astimezone(tz_of(cfg))
    if local.weekday() >= 5:
        return "Wochenende"
    try:
        a, b = (int(x) for x in str(cfg.get("work_hours") or "06-20").split("-", 1))
    except ValueError:
        a, b = 6, 20
    return None if a <= local.hour < b else "nachts"
