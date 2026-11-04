"""Windows-Inventar als Dienst: Import anstoßen, Stand und Hosts liefern."""
from __future__ import annotations

import time
from datetime import date, datetime, timedelta, timezone

from wininv import importer, parse, risks
from wininv.source import build_source


def summarize(rows: list[dict], stale_days: int, today: date | None = None) -> list[dict]:
    """Zeilen aus win_inventory → je Host eine Übersicht mit Hinweisen."""
    today = today or datetime.now(timezone.utc).date()
    by: dict[str, dict] = {}
    for r in rows:
        h = by.setdefault(r["hostname"], {"hostname": r["hostname"], "kinds": {},
                                          "newest": None, "oldest": None, "_rows": {}})
        h["kinds"][r["kind"]] = len(r["rows"])
        h["_rows"][r["kind"]] = r["rows"]
        m = r["file_mtime"]
        h["newest"] = max(h["newest"] or m, m)
        h["oldest"] = min(h["oldest"] or m, m)
    out = []
    limit = datetime.now(timezone.utc) - timedelta(days=stale_days)
    for h in sorted(by.values(), key=lambda h: h["hostname"]):
        sysinfo = parse.system(h["_rows"].get("system") or [])
        groups = h["_rows"].get("groups") or []
        admins = [g["MemberName"] for g in groups
                  if g.get("GroupName") in ("Administratoren", "Administrators")
                  and g.get("MemberName")]
        ports = sorted({int(p["Port"]) for p in h["_rows"].get("ports") or []
                        if str(p.get("Port", "")).isdigit()})
        out.append({
            "hostname": h["hostname"], **{k: sysinfo[k] for k in
                                          ("domain", "os", "ips", "cpu", "ram_gb", "disks")},
            "kinds": h["kinds"], "admins": admins, "ports": ports,
            "file_time": h["newest"].isoformat(), "stale": h["newest"] < limit,
            "risks": risks.host_risks(sysinfo, h["_rows"].get("certificates") or [], today),
        })
    return out


INDEX_TTL_S = 300


def build_index(rows: list[dict], stale_days: int, now: datetime | None = None) -> dict:
    """System- und Port-Zeilen → je IP und je Kurzname: Host, OS, Ports, Stand.
    Grundlage für Bestandsabgleich, Netzpläne und Portprüfung."""
    now = now or datetime.now(timezone.utc)
    limit = now - timedelta(days=stale_days)
    hosts: dict[str, dict] = {}
    for r in rows:
        h = hosts.setdefault(r["hostname"], {"hostname": r["hostname"], "os": None, "ips": [],
                                             "ports": None, "file_time": None})
        if r["kind"] == "system":
            sysinfo = parse.system(r["rows"])
            h["os"], h["ips"] = sysinfo["os"], sysinfo["ips"]
            h["file_time"] = r["file_mtime"]
        elif r["kind"] == "ports":
            h["ports"] = sorted({int(p["Port"]) for p in r["rows"]
                                 if str(p.get("Port", "")).isdigit()})
            h["ports_time"] = r["file_mtime"]
    by_ip: dict[str, dict] = {}
    by_name: dict[str, dict] = {}
    for h in hosts.values():
        h["stale"] = h["file_time"] is None or h["file_time"] < limit
        h["file_time"] = h["file_time"].isoformat() if h["file_time"] else None
        if h.get("ports_time"):
            h["ports_time"] = h["ports_time"].isoformat()
        for ip in h["ips"]:
            by_ip.setdefault(ip, h)
        by_name[h["hostname"].lower()] = h
    return {"by_ip": by_ip, "by_name": by_name, "hosts": len(hosts)}


def lookup(index: dict | None, ip: str | None = None, name: str | None = None) -> dict | None:
    if not index:
        return None
    if ip and ip in index["by_ip"]:
        return index["by_ip"][ip]
    if name:
        short = name.split(".")[0].lower()
        return index["by_name"].get(short)
    return None


def tooltip(h: dict | None) -> str:
    """Zeilen für Host-Tooltips im Netzplan."""
    if not h:
        return ""
    lines = [f"Windows-Inventar: {h['hostname']}" + (" (veraltet)" if h["stale"] else "")]
    if h.get("os"):
        lines.append(f"OS: {h['os']}")
    if h.get("ports"):
        shown = ", ".join(str(p) for p in h["ports"][:20])
        lines.append(f"lauscht: {shown}" + (" …" if len(h["ports"]) > 20 else ""))
    return "\n".join(lines)


class WinInventory:
    def __init__(self, store) -> None:
        self.store = store
        self.last: dict | None = None
        self.running = False
        self._index: tuple[float, int, dict] | None = None

    async def index(self, cfg: dict) -> dict | None:
        """IP-Index (5 min gecacht, nach jedem Import neu). None, wenn die
        Quelle nicht eingerichtet ist."""
        if not cfg.get("path"):
            return None
        stale = int(cfg.get("stale_days") or 3)
        if self._index and self._index[1] == stale and time.monotonic() - self._index[0] < INDEX_TTL_S:
            return self._index[2]
        idx = build_index(await self.store.current_kinds(["system", "ports"]), stale)
        self._index = (time.monotonic(), stale, idx)
        return idx

    async def run(self, cfg: dict) -> dict:
        if self.running:
            raise RuntimeError("Import läuft bereits.")
        self.running = True
        src = build_source(cfg)
        try:
            self.last = await importer.run(src, self.store)
            self._index = None
            self.last["finished"] = datetime.now(timezone.utc).isoformat()
            return self.last
        except Exception as exc:
            self.last = {"error": str(exc), "finished": datetime.now(timezone.utc).isoformat()}
            raise
        finally:
            self.running = False
            await src.close()

    async def test(self, cfg: dict) -> dict:
        """Freigabe erreichbar? Wie viele Hosts und Arten, wie alt — und eine
        System-Datei als Probe gelesen."""
        src = build_source(cfg)
        try:
            entries = await src.list()
            kinds: dict[str, int] = {}
            hosts: set[str] = set()
            mine = []
            for e in entries:
                key = parse.split_name(e.name)
                if key:
                    hosts.add(key[0])
                    kinds[key[1]] = kinds.get(key[1], 0) + 1
                    mine.append((key, e))
            sample = None
            probe = next(((k, e) for k, e in mine if k[1] == "system"), None)
            if probe:
                sysinfo = parse.system(parse.parse_csv(await src.read(probe[1].name), "system"))
                sample = {"hostname": probe[0][0], "os": sysinfo["os"], "ips": sysinfo["ips"]}
            times = [e.mtime for _, e in mine]
            return {"files": len(mine), "foreign": len(entries) - len(mine), "hosts": len(hosts),
                    "kinds": kinds,
                    "newest": max(times).isoformat() if times else None,
                    "oldest": min(times).isoformat() if times else None, "sample": sample}
        finally:
            await src.close()

    async def hosts(self, stale_days: int) -> list[dict]:
        return summarize(await self.store.current(), stale_days)

    async def host(self, hostname: str, stale_days: int) -> dict | None:
        rows = await self.store.current(hostname.upper())
        if not rows:
            return None
        head = summarize(rows, stale_days)[0]
        head["data"] = {r["kind"]: r["rows"] for r in rows}
        head["files"] = {r["kind"]: {"file_time": r["file_mtime"].isoformat(),
                                     "changed_at": r["changed_at"].isoformat()} for r in rows}
        return head
