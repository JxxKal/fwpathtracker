"""Hinweise je Host — die drei Regeln des Bechtle-Dashboards (Betriebssystem
am Ende, Zertifikate, Plattenplatz), damit A38 dasselbe zeigt."""
from __future__ import annotations

import re
from datetime import date, timedelta

EOL_RE = re.compile(r"2003|2008|2012|windows\s*(xp|vista|7|8|8\.1)\b", re.IGNORECASE)
# Windows 10 ohne LTSC/LTSB: Support endete am 14.10.2025.
WIN10_RE = re.compile(r"windows\s*10\b", re.IGNORECASE)
LTSC_RE = re.compile(r"\bLTS[BC]\b", re.IGNORECASE)


def host_risks(sysinfo: dict, certs: list[dict], today: date) -> list[dict]:
    out: list[dict] = []
    os_name = sysinfo.get("os") or ""
    if EOL_RE.search(os_name):
        out.append({"level": "red", "kind": "os", "text": f"Betriebssystem ohne Support: {os_name}"})
    elif "2016" in os_name:
        out.append({"level": "orange", "kind": "os", "text": "Windows Server 2016 – Support endet 2027"})
    elif WIN10_RE.search(os_name) and not LTSC_RE.search(os_name):
        out.append({"level": "red", "kind": "os",
                    "text": f"Windows 10 ohne LTSC – Support seit 14.10.2025 beendet: {os_name}"})
    for c in certs:
        try:
            until = date.fromisoformat((c.get("ValidUntil") or "")[:10])
        except ValueError:
            continue
        subj = (c.get("Subject") or "?").split(",")[0].removeprefix("CN=")
        if until < today:
            out.append({"level": "red", "kind": "cert", "text": f"Zertifikat abgelaufen ({until}): {subj}"})
        elif until <= today + timedelta(days=30):
            out.append({"level": "red", "kind": "cert", "text": f"Zertifikat läuft ab ({until}): {subj}"})
        elif until <= today + timedelta(days=60):
            out.append({"level": "orange", "kind": "cert", "text": f"Zertifikat läuft ab ({until}): {subj}"})
    for d in sysinfo.get("disks") or []:
        free, total = d.get("free_gb"), d.get("total_gb")
        if not total or free is None:
            continue
        share = free / total
        if share < 0.1:
            out.append({"level": "red", "kind": "disk",
                        "text": f"{d['drive']} fast voll: {free:g} von {total:g} GB frei"})
        elif share < 0.3:
            out.append({"level": "orange", "kind": "disk",
                        "text": f"{d['drive']} wird knapp: {free:g} von {total:g} GB frei"})
    return out
