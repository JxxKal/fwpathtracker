"""Live-Session-Probe: firewall/session (GET) als IST-Nachweis zum Policy-Lookup.

Der Policy-Lookup beantwortet die Theorie ("welche Regel WÜRDE greifen"), die
Session-Tabelle den Ist-Zustand ("läuft dort gerade Verkehr — und über welche
Regel"). Erst zusammen decken sie die Fälle auf, die sonst im Nebel bleiben:
Regel erlaubt, aber es fließt nichts; oder es fließt über eine ANDERE Regel als
der Lookup meldet (globale Header-Regel, VIP/NAT, asymmetrischer Pfad).

Der Aufruf ist ein reiner GET über denselben FMG-Proxy wie router/lookup und
firewall/policy-lookup — die No-Write-Garantie (fmg.client) bleibt unberührt.

ASSUMPTION (Lab): Serverseitiges Filtern ist bei DIESER Tabelle
build-abhängig. Der generische ``filter=``-Ausdruck wird für firewall/session
dokumentiert ignoriert (Fortinet-KB FD224183: "the API will run without errors,
but ... it will show all sessions"), die dedizierten Parameter
(srcaddr/dstaddr/dstport/protocol) greifen erst auf neueren Builds. Deshalb:
Parameter mitschicken (dann ist die Antwort klein und präzise) UND das Ergebnis
immer clientseitig nachfiltern. ``server_filtered`` sagt, ob das Gerät gefiltert
hat, ``truncated``, ob die Liste am count-Limit endete — nur so ist ein
"keine Session gefunden" ehrlich zu lesen: bei abgeschnittener Liste ist
Abwesenheit KEIN Beweis.
"""
from __future__ import annotations

import logging
from typing import Any

from fmg.client import FmgClient
from fmg.proxy import fortios_results, monitor_get

log = logging.getLogger("engine.sessions")

# FortiOS erlaubt count 20..1000; 1000 = größtmögliches Fenster pro Abfrage.
SESSION_COUNT = 1000
# So viele Sessions wandern als Beispiel in die Antwort (und damit in die
# Trace-History) — der Rest wird nur gezählt.
MAX_SAMPLES = 5

PROTO_NUMBERS = {"icmp": 1, "tcp": 6, "udp": 17}
PROTO_NAMES = {v: k for k, v in PROTO_NUMBERS.items()}


def session_params(src_ip: str, dst_ip: str, protocol: str,
                   dst_port: int | None = None, *,
                   count: int = SESSION_COUNT) -> dict:
    """Querystring der Session-Abfrage — von Engine UND Test-Fixtures genutzt,
    damit beide garantiert dieselbe Anfrage bauen."""
    params: dict[str, Any] = {
        "ip_version": "ipv4",
        "count": count,
        "summary": "false",
        "srcaddr": src_ip,
        "dstaddr": dst_ip,
    }
    proto = PROTO_NUMBERS.get(protocol.lower())
    if proto is not None:
        params["protocol"] = proto
    if dst_port is not None:
        params["dstport"] = dst_port
    return params


def _first(entry: dict, *keys: str):
    for key in keys:
        if entry.get(key) not in (None, ""):
            return entry[key]
    return None


def _as_int(value) -> int | None:
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return None


def normalize_session(entry: Any) -> dict | None:
    """Eine Session der FortiOS-Antwort auf feste Feldnamen bringen.

    ASSUMPTION (Lab): Die Feldnamen unterscheiden sich je Build
    (src/srcip/source_address …) — deshalb Alias-Listen statt fester Keys.
    """
    if not isinstance(entry, dict):
        return None
    proto_raw = _first(entry, "proto", "protocol")
    proto_num = _as_int(proto_raw)
    if proto_num is None and isinstance(proto_raw, str):
        proto_num = PROTO_NUMBERS.get(proto_raw.lower())
    return {
        "src": _first(entry, "src", "srcip", "source_address", "saddr"),
        "srcport": _as_int(_first(entry, "srcport", "sport", "source_port")),
        "dst": _first(entry, "dst", "dstip", "destination_address", "daddr"),
        "dstport": _as_int(_first(entry, "dstport", "dport", "destination_port")),
        "proto": proto_num,
        "protocol": PROTO_NAMES.get(proto_num) if proto_num is not None else (
            proto_raw.lower() if isinstance(proto_raw, str) else None),
        "srcintf": _first(entry, "src_intf", "srcintf", "src_interface"),
        "dstintf": _first(entry, "dst_intf", "dstintf", "dst_interface"),
        "policyid": _as_int(_first(entry, "policyid", "policy_id")),
        "nat_src": _first(entry, "nat_src", "natsrc", "natsourceaddress"),
        "nat_dst": _first(entry, "nat_dst", "natdst", "natdestaddress"),
        "duration": _as_int(_first(entry, "duration")),
        "expire": _as_int(_first(entry, "expire", "timeout")),
    }


def session_matches(sess: dict, src_ip: str, dst_ip: str, protocol: str,
                    dst_port: int | None = None) -> bool:
    """Passt die Session zum getracten Flow?

    Quelle muss stimmen; beim Ziel zählt auch die NAT-Adresse, damit ein Flow
    auf eine VIP (DNAT) nicht durchs Raster fällt. Fehlende Felder gelten als
    Treffer — lieber eine Session zu viel zeigen als den Nachweis verlieren.
    """
    if sess.get("src") not in (None, src_ip):
        return False
    dsts = {sess.get("dst"), sess.get("nat_dst")} - {None}
    if dsts and dst_ip not in dsts:
        return False
    want_proto = protocol.lower()
    have_proto = sess.get("protocol")
    if have_proto is not None and have_proto != want_proto:
        return False
    if dst_port is not None and sess.get("dstport") is not None:
        if sess["dstport"] != dst_port:
            return False
    return True


async def probe_sessions(client: FmgClient, adom: str, device: str, vdom: str, *,
                         src_ip: str, dst_ip: str, protocol: str,
                         dst_port: int | None = None,
                         count: int = SESSION_COUNT) -> dict:
    """firewall/session lesen und auf den Flow eindampfen.

    Liefert Zähler + bis zu MAX_SAMPLES Beispiel-Sessions. Fehler werden NICHT
    behandelt (der Aufrufer entscheidet, ob ein Trace daran scheitern darf).
    """
    params = session_params(src_ip, dst_ip, protocol, dst_port, count=count)
    resp = await monitor_get(client, adom, device, vdom, "firewall/session", params)
    results = fortios_results(resp)
    entries = results if isinstance(results, list) else []
    if not entries and isinstance(results, dict):
        # Manche Builds verschachteln die Liste (z.B. {"details": [...]}).
        for key in ("details", "sessions", "session"):
            if isinstance(results.get(key), list):
                entries = results[key]
                break

    matches: list[dict] = []
    for entry in entries:
        sess = normalize_session(entry)
        if sess is not None and session_matches(sess, src_ip, dst_ip, protocol, dst_port):
            matches.append(sess)

    returned = len(entries)
    policy_ids = sorted({s["policyid"] for s in matches if s.get("policyid") is not None})
    return {
        "match_count": len(matches),
        "returned": returned,
        # Am count-Limit abgeschnitten ⇒ ein Negativ-Ergebnis ist nicht belastbar.
        "truncated": returned >= count,
        # Heuristik: hat das Gerät selbst gefiltert, passen ALLE gelieferten
        # Sessions zum Flow. Bei leerer Liste nicht entscheidbar → None.
        "server_filtered": (len(matches) == returned) if returned else None,
        "samples": matches[:MAX_SAMPLES],
        "policy_ids": policy_ids,
        "params": params,
    }


def session_warnings(probe: dict, *, verdict: str, policy_id: int | None) -> list[str]:
    """Nur die überraschenden Befunde melden — kein Rauschen.

    Ein Trace ist meist hypothetisch ("dürfte der Flow?"); dass gerade keine
    Session läuft, ist der Normalfall und deshalb keine Warnung. Gemeldet wird,
    was der Theorie widerspricht: Verkehr trotz DENY, Verkehr über eine andere
    Regel — und ein Negativ-Ergebnis, das mangels vollständiger Liste gar keins
    ist.
    """
    out: list[str] = []
    count = probe.get("match_count", 0)
    ids = probe.get("policy_ids") or []

    if count and verdict == "DENY":
        out.append(
            f"Auf dem Gerät laufen aktuell {count} passende Session(s) für diesen "
            "Flow, der Policy-Lookup meldet aber DENY. Typische Ursachen: die "
            "Sessions stammen aus einer inzwischen geänderten Regel und laufen bis "
            "zum Timeout weiter, der echte Verkehr nimmt einen anderen Pfad/VDOM, "
            "oder es ist NAT im Spiel."
            + (f" Getroffene Regel laut Session-Tabelle: #{', #'.join(str(i) for i in ids)}."
               if ids else "")
        )
    elif count and policy_id is not None and ids and policy_id not in ids:
        out.append(
            f"Der Live-Verkehr läuft über Regel #{', #'.join(str(i) for i in ids)}, "
            f"der Policy-Lookup ordnet den Flow dagegen Regel #{policy_id} zu. "
            "Beide Angaben kommen vom selben Gerät — die Abweichung deutet auf "
            "einen anderen Quell-/Zielport, NAT oder eine geänderte Regel hin."
        )

    if not count and probe.get("truncated"):
        out.append(
            f"Keine passende Session gefunden — die Session-Liste war aber bei "
            f"{probe.get('returned')} Einträgen abgeschnitten"
            + ("" if probe.get("server_filtered") else
               " und das Gerät hat die Filter offenbar ignoriert")
            + ". Das Ergebnis ist damit kein Beweis, dass gerade kein Verkehr läuft."
        )
    return out
