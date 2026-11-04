"""Lauf erzeugen (lesen, prüfen, Liste speichern) und freigegebene Zeilen
schreiben — jede Zeile vor dem Schreiben erneut gegen iTop und DNS geprüft."""
from __future__ import annotations

import logging

from dnssync import build, itop, lookup

log = logging.getLogger("dnssync")


class DnsSyncError(Exception):
    pass


async def generate(store, read_config, *, trigger: str, user: str | None) -> int:
    itop_cfg = await read_config("itop")
    if not itop_cfg.get("base_url"):
        raise DnsSyncError("iTop ist nicht konfiguriert.")
    data = await itop.read_all(itop_cfg)
    ignored = {r["ip_id"] for r in await store.ignored()}
    ips = sorted({str(a.get("ip") or "").strip() for a in data["addresses"]
                  if str(a.get("status") or "").lower() not in build.SKIP_STATUS
                  and str(a.get("_key") or "") not in ignored} - {""})
    dns = await lookup.check(await read_config("dns"), ips)
    items, stats = build.items(data["addresses"], data["cis"], data["domains"], dns, ignored)
    stats["errors"] = data["errors"]
    stats["domains"] = len(data["domains"])
    rid = await store.create(trigger, user, stats, items)
    log.info("DNS-Abgleich #%d: %d Vorschläge aus %d Adressen", rid, len(items),
             stats["addresses"])
    return rid


def toggle(items: list[dict], ids: set[str], selected: bool) -> list[dict]:
    for it in items:
        if it["id"] in ids and it["selectable"]:
            it["selected"] = selected
    return items


async def apply(store, read_config, run: dict, user: str) -> dict:
    cfg = await read_config("dnssync")
    if not cfg.get("write_enabled"):
        raise DnsSyncError("Schreiben ins iTop ist abgeschaltet (Einstellungen → "
                           "iTop-DNS-Abgleich → „Schreiben erlauben\").")
    if run["status"] != "open":
        raise DnsSyncError(f"Lauf #{run['id']} ist nicht mehr offen ({run['status']}).")
    itop_cfg = dict(await read_config("itop"))
    itop_cfg["write_user"] = cfg.get("write_user") or ""
    itop_cfg["write_password"] = cfg.get("write_password") or ""
    dns_cfg = await read_config("dns")
    items = run["items"]
    todo = [it for it in items if it.get("selected") and it.get("selectable")]
    counts = {"ok": 0, "skipped": 0, "error": 0}
    fresh = await lookup.check(dns_cfg, sorted({it["ip"] for it in todo}))
    comment = f"A38 iTop-DNS-Abgleich #{run['id']}, freigegeben von {user}"
    for it in todo:
        res: dict
        try:
            cur = await itop.get_address(itop_cfg, it["id"])
            if cur is None:
                res = {"state": "skipped", "text": "Adressobjekt gibt es nicht mehr."}
            elif ((str(cur.get("short_name") or "") or None) != it["itop_short"]
                  or str(cur.get("domain_id") or "0") != it["itop_domain_id"]):
                res = {"state": "skipped", "text": "Im iTop inzwischen geändert — nicht überschrieben."}
            elif it["dns_name"] not in (fresh.get(it["ip"]) or {}).get("ptr", []):
                res = {"state": "skipped", "text": "DNS hat sich seit dem Vorschlag geändert."}
            else:
                got = await itop.update_address(
                    itop_cfg, it["id"], {"short_name": it["short_name"],
                                         "domain_id": int(it["domain_id"])}, comment)
                res = {"state": "ok", "text": f"geschrieben: {got.get('fqdn') or it['dns_name']}"}
        except itop.ItopWriteBlocked:
            raise
        except Exception as exc:
            res = {"state": "error", "text": str(exc)[:300]}
        it["result"] = res
        counts[res["state"]] += 1
    status = ("applied" if counts["ok"] == len(todo)
              else "failed" if not counts["ok"] and counts["error"] else "partial")
    result = {**counts, "selected": len(todo)}
    await store.decide(run["id"], status, user, items, result)
    log.info("DNS-Abgleich #%d von %s: %s", run["id"], user, result)
    return {"status": status, **result}
