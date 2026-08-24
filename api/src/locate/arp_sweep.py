"""ARP-Sweep: die IP↔MAC-Historie füllen, solange die Hosts noch reden.

Ein Host, der seit Tagen aus ist, hinterlässt keine Spur mehr, die man
abfragen könnte — die Bindung muss aufgezeichnet worden sein, ALS er noch lief.
Genau das ist die Aufgabe hier: regelmäßig die ARP-Tabellen aller FortiGates
abholen und wegschreiben.

Abgefragt wird je (Gerät, VDOM), das laut PrefixTable ein connected Netz hält —
das sind die L3-Instanzen, bei denen ARP überhaupt anfällt. Ein Durchlauf ist
ein Monitor-Aufruf pro VDOM; dieselbe Antwort, die auch die Einzelsuche holt.

Getaktet wird deutlich enger als der FMG-Sync (Default 15 min), weil die
FortiGate ARP-Einträge nach Minuten verwirft. Was zwischen zwei Läufen kurz
auftaucht und wieder verschwindet, entgeht dem Sweep — dagegen hilft die
opportunistische Aufzeichnung bei jeder Locate-Suche.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone

from config import Config
from fmg.client import FmgError, FmgTargetOffline
from fmg.factory import build_fmg_client
from inventory.prefixes import PrefixTable
from locate import arp_fortigate
from locate.arp_store import ArpStore

log = logging.getLogger("locate.arp_sweep")


def _ts() -> str:
    return datetime.now(timezone.utc).strftime("%H:%M:%S")


def l3_targets(prefixes: PrefixTable) -> list[tuple[str, str, str]]:
    """(adom, device, vdom) aller VDOMs mit connected Netz — dort fällt ARP an.

    Sortiert und dedupliziert, damit ein Lauf reproduzierbar dieselbe Reihenfolge
    hat und ein VDOM mit zwanzig Netzen nicht zwanzigmal abgefragt wird.
    """
    out = {(e.adom or "root", e.device, e.vdom)
           for e in prefixes.entries if e.source in ("connected", "override")}
    return sorted(out)


class ArpSweeper:
    """Periodischer Sammler mit Status/Log — wie der FMG-SyncManager."""

    def __init__(self) -> None:
        self.state: dict = {
            "phase": "idle",          # idle | running | done | error
            "log": [],
            "started_at": None,
            "finished_at": None,
            "vdoms": 0,
            "observations": 0,
            "purged": 0,
        }

    def _log(self, msg: str) -> None:
        self.state["log"].append(f"[{_ts()}] {msg}")
        if len(self.state["log"]) > 200:
            self.state["log"] = self.state["log"][-100:]
        log.info(msg)

    async def run(self, store: ArpStore, prefixes: PrefixTable, fmg_cfg: dict,
                  app_cfg: Config, retention_days: int = 180) -> dict:
        if self.state["phase"] == "running":
            return self.state
        targets = l3_targets(prefixes)
        self.state.update({
            "phase": "running", "log": [], "vdoms": 0, "observations": 0,
            "purged": 0, "started_at": datetime.now(timezone.utc).isoformat(),
            "finished_at": None,
        })
        if not targets:
            self._log("Keine VDOMs mit connected Netz — FMG-Sync zuerst laufen lassen.")
            self.state.update({"phase": "done",
                               "finished_at": datetime.now(timezone.utc).isoformat()})
            return self.state

        try:
            client = build_fmg_client(fmg_cfg, app_cfg)
        except Exception as exc:
            self._log(f"FEHLER: FortiManager nicht verfügbar: {exc}")
            self.state.update({"phase": "error",
                               "finished_at": datetime.now(timezone.utc).isoformat()})
            return self.state

        total = 0
        reached = 0
        try:
            for adom, device, vdom in targets:
                warnings: list[str] = []
                try:
                    rows = await arp_fortigate.fetch_table(
                        client, adom, device, vdom, warnings)
                except (FmgError, FmgTargetOffline) as exc:
                    # Ein stilles Gerät darf den ganzen Lauf nicht kippen.
                    self._log(f"{device}/{vdom}: {exc}")
                    continue
                except Exception as exc:
                    self._log(f"{device}/{vdom}: unerwarteter Fehler: {exc}")
                    continue
                if rows is None:
                    for w in warnings:
                        self._log(f"{device}/{vdom}: {w}")
                    continue
                obs = arp_fortigate.observations(rows, device, vdom)
                if obs:
                    total += await store.record(obs)
                reached += 1
            self.state["vdoms"] = reached
            self.state["observations"] = total
            self.state["purged"] = await store.purge(retention_days)
            self._log(f"{total} Bindungen aus {reached}/{len(targets)} VDOMs; "
                      f"{self.state['purged']} veraltete entfernt.")
            self.state["phase"] = "done"
        except Exception as exc:
            self._log(f"FEHLER: {exc}")
            self.state["phase"] = "error"
        finally:
            await client.close()
            self.state["finished_at"] = datetime.now(timezone.utc).isoformat()
        return self.state
