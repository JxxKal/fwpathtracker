"""Netzwerkport-Check eines Hosts: an welchen Ports hängt er, in welchen VLANs?

Die Switchport-Suche beantwortet „wo steckt das Gerät" und verengt dafür bewusst
auf EINEN besten Treffer. Hier ist die Frage eine andere: das vollständige Bild —
alle Fundstellen, alle VLANs. Deshalb bleibt die Rangfolge zwar erhalten (der
beste Treffer steht oben), aber nichts wird ausgeblendet.

Drei Sichten, die sich ergänzen:

    Fundstellen   Jeder Switchport, auf dem eine MAC des Hosts steht, mit dem
                  VLAN, in dem sie gelernt wurde (FDB) und — wo abrufbar — der
                  konfigurierten VLAN-Mitgliedschaft des Ports (untagged/tagged).
    Gerät         Ist der Host selbst überwacht (Switch, Firewall, SNMP-Server),
                  seine komplette Portliste mit den je Port beobachteten VLANs.
    L3            Welches VLAN-Interface welcher Firewall das Subnetz des Hosts
                  terminiert — aus dem FMG-Inventar, ohne Live-Abfrage.

Wichtig bei den VLANs: Die FDB sagt, worin MACs tatsächlich gelernt wurden
(beobachtet), `ports_vlans` sagt, was konfiguriert ist. Beides kann auseinander
liegen — ein konfiguriertes VLAN ohne Verkehr taucht in der FDB nie auf. Die
Herkunft steht deshalb an jeder Zeile.
"""
from __future__ import annotations

import logging
from collections import defaultdict

from inventory.prefixes import PrefixTable
from inventory.store import Inventory
from librenms.client import LibrenmsClient, LibrenmsNotConfigured

log = logging.getLogger("vlan.hostports")

# Bei so vielen Ports lohnt die Einzelabfrage der konfigurierten VLANs nicht
# mehr — /ports/:id?with=vlans ist ein Request pro Port. Für die Fundstellen
# (wenige) wird sie immer gemacht, für die volle Portliste eines Switches nicht.
MAX_PORT_VLAN_LOOKUPS = 12


async def _vlan_index(client: LibrenmsClient, cfg: dict,
                      warnings: list[str]) -> dict[str, dict]:
    """LibreNMS-`vlan_id` (interne Zeilen-ID) → {number, name, device_id}.

    Die FDB verweist mit dieser ID auf die VLAN-Tabelle; ohne die Auflösung
    steht in den Fundstellen nur eine nichtssagende Zahl.
    """
    try:
        rows = await client.vlans(cfg)
    except LibrenmsNotConfigured:
        return {}
    except Exception as exc:
        log.info("VLAN-Tabelle nicht abrufbar: %s", exc)
        warnings.append(f"VLAN-Tabelle konnte nicht geladen werden: {exc}")
        return {}
    out: dict[str, dict] = {}
    for r in rows:
        vid = r.get("vlan_id")
        if vid is None:
            continue
        try:
            number = int(str(r.get("vlan_vlan")).strip())
        except (TypeError, ValueError):
            continue
        out[str(vid)] = {
            "number": number,
            "name": (r.get("vlan_name") or "").strip() or None,
            "device_id": r.get("device_id"),
        }
    return out


def _resolve_vlan(index: dict[str, dict], vlan_id) -> dict | None:
    """FDB-`vlan_id` → VLAN-Details. `0` ist bei manchen Geräten (MOXA) ein
    Platzhalter für 'kein VLAN gemeldet' und keine echte Zuordnung."""
    if vlan_id in (None, 0, "0"):
        return None
    return index.get(str(vlan_id))


async def _port_vlans(client: LibrenmsClient, cfg: dict, port_id,
                      warnings: list[str]) -> dict | None:
    """Konfigurierte VLAN-Mitgliedschaft eines Ports (untagged/tagged)."""
    if port_id in (None, -1):
        return None
    try:
        rows = await client.port_vlans(cfg, port_id)
    except LibrenmsNotConfigured:
        return None
    except Exception as exc:
        log.info("Port-VLANs für %s nicht abrufbar: %s", port_id, exc)
        return None
    if not rows:
        return None
    untagged, tagged = [], []
    for r in rows:
        try:
            num = int(str(r.get("vlan")).strip())
        except (TypeError, ValueError):
            continue
        (untagged if r.get("untagged") in (1, "1", True) else tagged).append(num)
    if not untagged and not tagged:
        return None
    return {"untagged": sorted(set(untagged)), "tagged": sorted(set(tagged))}


async def _device_view(client: LibrenmsClient, cfg: dict, device_id,
                       warnings: list[str]) -> dict | None:
    """Komplette Portliste eines überwachten Geräts mit VLAN-Bezug.

    Die VLANs je Port kommen hier aus der FDB des Geräts (EIN Request, statt
    einem pro Port) — also die beobachtete Sicht: in welchen VLANs auf diesem
    Port MACs gelernt wurden. Für einen 48-Port-Switch ist das der einzige
    Weg, der nicht in 48 Einzelabfragen ausartet.
    """
    try:
        ports = await client.device_ports(cfg, device_id)
    except LibrenmsNotConfigured:
        return None
    except Exception as exc:
        warnings.append(f"Portliste des Geräts nicht abrufbar: {exc}")
        return None

    index = await _vlan_index(client, cfg, warnings)
    try:
        fdb = await client.device_fdb(cfg, device_id)
    except Exception as exc:
        log.info("Geräte-FDB nicht abrufbar: %s", exc)
        fdb = []

    observed: dict[str, set[int]] = defaultdict(set)
    mac_count: dict[str, int] = defaultdict(int)
    for row in fdb:
        pid = str(row.get("port_id"))
        mac_count[pid] += 1
        vlan = _resolve_vlan(index, row.get("vlan_id"))
        if vlan is not None:
            observed[pid].add(vlan["number"])

    try:
        device_vlans = await client.device_vlans(cfg, device_id)
    except Exception:
        device_vlans = []

    out_ports = []
    for p in ports:
        pid = str(p.get("port_id"))
        out_ports.append({
            "port_id": p.get("port_id"),
            "if_name": p.get("ifName") or p.get("ifDescr"),
            "if_alias": p.get("ifAlias") or None,
            "oper_status": p.get("ifOperStatus"),
            "admin_status": p.get("ifAdminStatus"),
            "vlans_observed": sorted(observed.get(pid, ())),
            "mac_count": mac_count.get(pid, 0),
        })
    out_ports.sort(key=lambda p: (p["if_name"] or "").lower())

    vlans = []
    for r in device_vlans:
        try:
            vlans.append({"number": int(str(r.get("vlan_vlan")).strip()),
                          "name": (r.get("vlan_name") or "").strip() or None})
        except (TypeError, ValueError):
            continue
    vlans.sort(key=lambda v: v["number"])
    return {"ports": out_ports, "vlans": vlans}


def _l3_view(inv: Inventory, prefixes: PrefixTable, ip: str) -> list[dict]:
    """VLAN-Interfaces der Firewalls, die das Subnetz des Hosts tragen.

    Nur connected/override zählt: eine statische Route sagt 'erreichbar über',
    nicht 'dieses VLAN liegt hier an' — für die VLAN-Frage wäre das irreführend.
    """
    out = []
    seen = set()
    for entry in prefixes.lookup_all(ip):
        if entry.source not in ("connected", "override") or not entry.interface:
            continue
        key = (entry.device, entry.vdom, entry.interface)
        if key in seen:
            continue
        seen.add(key)
        facts = inv.interface_facts(entry.device, entry.interface)
        facts["prefix_source"] = entry.source
        facts["matched_network"] = str(entry.network)
        out.append(facts)
    return out


async def check(*, ip: str, names: list[str], inv: Inventory, prefixes: PrefixTable,
                client: LibrenmsClient, librenms_cfg: dict, locate_result: dict) -> dict:
    """Portcheck aus einem bereits gelaufenen Locate-Ergebnis aufbauen.

    Bewusst auf `locate_result` aufgesetzt statt daneben: MAC-Ermittlung,
    Fundstellen-Ranking und Portklassifikation sind dort erprobt — hier kommen
    nur die VLAN-Auflösung, die Geräte-Portliste und die L3-Sicht dazu. So
    können Locate und Portcheck nicht auseinanderlaufen.
    """
    warnings: list[str] = list(locate_result.get("warnings") or [])
    index = await _vlan_index(client, librenms_cfg, warnings)

    findings = []
    for i, cand in enumerate(locate_result.get("candidates") or []):
        vlan = _resolve_vlan(index, cand.get("vlan_id"))
        # Konfigurierte Mitgliedschaft nur für die vordersten Fundstellen —
        # ein Request je Port, und weiter unten stehen ohnehin Uplinks.
        port_vlans = None
        if i < MAX_PORT_VLAN_LOOKUPS:
            port_vlans = await _port_vlans(client, librenms_cfg,
                                           cand.get("port_id"), warnings)
        findings.append({**cand, "vlan": vlan, "port_vlans": port_vlans,
                         "best": bool(locate_result.get("best"))
                         and cand.get("port_id") == (locate_result["best"] or {}).get("port_id")})

    if findings and all(f["vlan"] is None for f in findings):
        warnings.append(
            "Zu keiner Fundstelle ließ sich ein VLAN auflösen — die Switches "
            "melden in der FDB keine VLAN-Zuordnung (bei MOXA siehe Wiki) oder "
            "die VLAN-Tabelle in LibreNMS ist leer."
        )

    device = None
    self_dev = locate_result.get("self_device")
    if self_dev:
        view = await _device_view(client, librenms_cfg, self_dev.get("device_id"), warnings)
        if view is not None:
            device = {**self_dev, **view}

    l3 = _l3_view(inv, prefixes, ip)
    if not l3:
        warnings.append(
            f"Kein connected VLAN-Interface für {ip} im FMG-Inventar — entweder "
            "routet ein L3-Switch dieses Netz, oder der Sync ist veraltet."
        )

    # Was der Host insgesamt an VLANs berührt — die eigentliche Antwort auf
    # „gib mir den VLAN-Überblick".
    summary: dict[int, dict] = {}
    for f in findings:
        if f["vlan"]:
            e = summary.setdefault(f["vlan"]["number"],
                                   {"vlan": f["vlan"]["number"],
                                    "name": f["vlan"]["name"], "where": []})
            e["where"].append(f"{f.get('hostname') or '?'} / {f.get('if_name') or '?'}")
    for intf in l3:
        if intf.get("vlan"):
            e = summary.setdefault(intf["vlan"], {"vlan": intf["vlan"],
                                                  "name": intf.get("alias"), "where": []})
            e["name"] = e.get("name") or intf.get("alias")
            e["where"].append(f"{intf['device']}/{intf['vdom']} · {intf['interface']}")

    return {
        "ip": ip,
        "names": names,
        "mac": locate_result.get("mac"),
        "mac_readable": locate_result.get("mac_readable"),
        "arp": locate_result.get("arp"),
        "confidence": locate_result.get("confidence"),
        "findings": findings,
        "device": device,
        "l3": l3,
        "vlan_summary": [summary[k] for k in sorted(summary)],
        "warnings": warnings,
    }
