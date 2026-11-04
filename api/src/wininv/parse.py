"""Dateinamen und Inhalt der Inventar-CSVs lesen und normalisieren."""
from __future__ import annotations

import csv
import io
import ipaddress
import re

# <HOST>_<NN>_<Art>.csv — der Hostname darf selbst Unterstriche enthalten.
FILE_RE = re.compile(r"^(?P<host>.+)_(?P<nn>\d{2})_(?P<kind>[A-Za-z]+)\.csv$", re.IGNORECASE)

# Art im Dateinamen → Schlüssel in A38 (Reihenfolge wie im Collector).
KINDS = {"system": "system", "services": "services", "tasks": "tasks", "groups": "groups",
         "shares": "shares", "ports": "ports", "secpol": "secpol", "software": "software",
         "features": "features", "certificates": "certificates", "users": "users"}
KIND_LABEL = {"system": "System", "services": "Dienste", "tasks": "Geplante Aufgaben",
              "groups": "Lokale Gruppen", "shares": "Freigaben", "ports": "Lauschende Ports",
              "secpol": "Anmelderechte", "software": "Software", "features": "Rollen & Features",
              "certificates": "Zertifikate", "users": "Lokale Benutzer"}
# Pro Art die Spalte, die eine Zeile kennzeichnet — leere Zeilen (z. B. eine
# Software ohne Namen) fallen weg.
KEY_COLUMN = {"services": "Name", "tasks": "TaskName", "groups": "GroupName", "shares": "Name",
              "ports": "Port", "secpol": "Right", "software": "DisplayName", "features": "Name",
              "certificates": "Thumbprint", "users": "Name"}

MAX_FILE_BYTES = 20 * 1024 * 1024


def split_name(name: str) -> tuple[str, str] | None:
    """'BARRC01_08_Software.csv' → ('BARRC01', 'software'); fremde Dateien → None."""
    m = FILE_RE.match(name)
    if not m:
        return None
    kind = KINDS.get(m["kind"].lower())
    if kind is None:
        return None
    return m["host"].upper(), kind


def decode(raw: bytes) -> str:
    """PowerShell schreibt je nach Version UTF-8 mit BOM, UTF-16 oder ANSI."""
    if raw.startswith(b"\xff\xfe") or raw.startswith(b"\xfe\xff"):
        return raw.decode("utf-16")
    try:
        return raw.decode("utf-8-sig")
    except UnicodeDecodeError:
        return raw.decode("cp1252", errors="replace")


def parse_csv(raw: bytes, kind: str) -> list[dict]:
    # NUL kommt in Registry-Werten vor (z. B. DisplayVersion) — Postgres nimmt
    # es in jsonb nicht an.
    text = decode(raw).replace("\x00", "")
    first = text.split("\n", 1)[0]
    delim = ";" if first.count(";") >= first.count(",") else ","
    rows = []
    for r in csv.DictReader(io.StringIO(text), delimiter=delim):
        row = {(k or "").strip(): (v or "").strip() for k, v in r.items() if k is not None}
        key = KEY_COLUMN.get(kind)
        if key and not row.get(key):
            continue
        row.pop("Hostname", None)
        rows.append(row)
    return rows


def _num(text: str) -> float | None:
    try:
        return float(str(text).replace(",", "."))
    except (TypeError, ValueError):
        return None


DISK_RE = re.compile(r"([A-Za-z0-9_-]+:?)\s*\(([\d,.]+)\s*GB frei von\s*([\d,.]+)\s*GB\)")


def usable_ip(ip: str) -> bool:
    try:
        a = ipaddress.IPv4Address(ip)
    except ValueError:
        return False
    return not (a.is_loopback or a.is_link_local or a.is_unspecified)


def system(rows: list[dict]) -> dict:
    """01_System → Betriebssystem, IPs (ohne APIPA/Loopback), CPU, RAM, Platten."""
    r = rows[0] if rows else {}
    ips = [i.strip() for i in (r.get("IPs") or "").split(",") if i.strip()]
    disks = [{"drive": d, "free_gb": _num(f), "total_gb": _num(t)}
             for d, f, t in DISK_RE.findall(r.get("Disks") or "")]
    cpu = _num(r.get("CPU") or "")
    return {"domain": r.get("Domain") or None, "os": (r.get("OS") or "").strip() or None,
            "ips": [i for i in ips if usable_ip(i)], "ips_all": ips,
            "cpu": int(cpu) if cpu is not None else None, "ram_gb": _num(r.get("RAM_GB") or ""),
            "disks": disks}
