"""Router-Helfer: Zeitraum-Beginn aus dem Browser begrenzen."""
from __future__ import annotations

from datetime import datetime, timedelta

from routers.webdrive import clamp_since
from webdrive_fixtures import NOW, at


def test_default_is_24h():
    assert clamp_since(None, NOW, 7) == NOW - timedelta(hours=24)


def test_capped_by_retention_and_now():
    assert clamp_since(NOW - timedelta(days=30), NOW, 7) == NOW - timedelta(days=7)
    assert clamp_since(NOW + timedelta(hours=1), NOW, 7) == NOW


def test_naive_timestamp_is_utc():
    assert clamp_since(datetime(2026, 10, 7, 0, 0), NOW, 7) == at("00:00:00")
