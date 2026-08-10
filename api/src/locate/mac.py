"""MAC-Normalisierung.

Jede Quelle schreibt MACs anders: FortiOS `00:0c:29:11:89:1a`, LibreNMS
`000c2911891a`, Cisco-Welt `000c.2911.891a`. Intern arbeiten wir durchgängig
mit der LibreNMS-Form (12 Zeichen Kleinbuchstaben, ohne Trenner), weil die
FDB-Abfrage genau die erwartet.
"""
from __future__ import annotations

import re

_SEPARATORS = re.compile(r"[\s:.\-]")
_HEX12 = re.compile(r"^[0-9a-f]{12}$")


def normalize_mac(value: str | None) -> str | None:
    """Beliebige MAC-Schreibweise → 12 Zeichen Kleinbuchstaben, oder None."""
    if not value:
        return None
    cleaned = _SEPARATORS.sub("", str(value)).lower()
    # Manche Agenten stellen ein Längenbyte voran (7 Byte statt 6).
    if len(cleaned) == 14 and cleaned.startswith("06"):
        cleaned = cleaned[2:]
    return cleaned if _HEX12.match(cleaned) else None


def readable_mac(value: str | None) -> str | None:
    """Normalisierte MAC → `00:0c:29:11:89:1a` für die Anzeige."""
    norm = normalize_mac(value)
    if norm is None:
        return None
    return ":".join(norm[i:i + 2] for i in range(0, 12, 2))
