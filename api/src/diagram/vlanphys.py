"""Switch-Physik eines VLANs: welche Switches tragen die Hosts, wie hängen sie zusammen.

Der Segmentplan (segments.py) zeigt das VLAN logisch — eine Leiste, die Hosts
daran. Hier steht die Physik dahinter, für EIN VLAN eines Service:

    SD-WAN
      │ Uplink
    Firewall  (Segment-VDOM ── Router-VDOM)
      │ Firewall-Port ↔ Switch-Port   (LLDP)
    Switch ── Switch ── …              (LLDP, Ports an beiden Enden)
      └ Port · Host                     (FDB)

Ein Host steht nur dort, wo er physisch zu Hause ist — am Access-Port.
Laut FDB steht seine MAC auf JEDEM Switch im Pfad, dort aber an Trunks und
Uplinks, durch die sie nur durchläuft. Portklassen wie in der Switchport-Suche:

    uplink   LLDP-Nachbar ist ein bekannter Switch oder die Firewall
    edge     LLDP-Nachbar, der kein Switch ist (Hypervisor, AP, Telefon) —
             der Host hängt dahinter, die Zeile nennt den Nachbarn
    access   kein LLDP-Nachbar, wenige MACs (über ALLE VLANs gezählt), ≤ 2 VLANs
    trunk    alles andere

Gezeichnet wird ein Host nur an access- oder edge-Ports, Access zuerst. Wer
nur an Trunks und Uplinks auftaucht, kommt mit Grund in die Liste daneben —
meist hängt er an einem Switch, den LibreNMS nicht kennt. Trunks und Uplinks
zwischen Switches sind die LLDP-Kanten der Zeichnung.

Damit der Baum bis zur Firewall geschlossen ist, kommen die Switches auf dem
LLDP-Weg dazwischen mit — als Transit, ohne Hosts.

Kandidaten sind die Switches des Standorts mit diesem VLAN
(segments.vlan_switches: LLDP von der Firewall aus oder Management-IP in
einem Netz der Firewall).
"""
from __future__ import annotations

import asyncio
import re
from collections import deque
from collections.abc import Awaitable, Callable

from diagram import drawio, segments, services as service_view, titleblock
from diagram.mx import Doc, esc
from inventory.store import Inventory
from locate.mac import normalize_mac

Fetch = Callable[[str], Awaitable[list[dict]]]

MAX_SWITCHES = 60          # Kandidaten, deren FDB abgefragt wird
CONCURRENCY = 6
HOST_ROWS_MAX = 30
MAX_SERVERS = 100          # ARP-Abfragen für Hypervisor-Server je Zeichnung
# Access-Port: höchstens so viele MACs (über alle VLANs; wie die Switchport-
# Suche, einstellbar unter LibreNMS) und höchstens zwei VLANs — Daten plus
# Voice am Telefon-Port. Mehr ist ein Trunk.
ACCESS_MAX_MACS = 8
ACCESS_MAX_VLANS = 2
KIND_RANK = {"access": 0, "edge": 1, "trunk": 2}
# Link-Aggregation führt hier immer zu einem Switch oder einer Firewall — nie
# zu einem Host. Dazu logische Ports (VLAN-Interface, Loopback), an denen
# höchstens die eigene SVI-MAC steht.
LAG_PORT = re.compile(
    r"(?i)^(bridge-?agg|route-?agg|.*aggregat|port-?channel|po\d|ae\d|lag\s*\d|trk\d|bond|"
    r"vlan-?interface|vlan\d|vlanif|loopback|in-?loop-?back|null\d|tunnel\d)")


def _port_name(p: dict) -> str:
    return str(p.get("ifName") or p.get("ifDescr") or p.get("port_id") or "?")


def _remote_port(ln: dict) -> str:
    """LLDP-Portname des Nachbarn ohne angehängte Chassis-MAC — FortiGates
    melden `port13 (0401a13f4fb3)`."""
    return re.sub(r"\s*\([0-9a-fA-F:.-]{8,}\)\s*$", "", str(ln.get("remote_port") or "")) or "?"


def _short(name) -> str:
    return str(name or "").strip().lower().split(".")[0]


def split(seg: dict) -> list[dict]:
    """Segmentmodell mit mehreren Netzen → je Netz ein Modell mit genau einem
    Netz und seiner Firewall — Eingabe für build()."""
    out = []
    for site in seg["sites"]:
        for net in site["segments"]:
            fw = next(f for f in site["firewalls"] if f["device"] == net["device"])
            out.append(dict(seg, sites=[dict(site, segments=[net], firewalls=[fw])]))
    return out


async def build(seg: dict, inv: Inventory, *, lldp: dict | None, fdb: Fetch, ports: Fetch,
                hide_not_in_itop: bool = False, hide_not_in_service: bool = False,
                access_max: int = ACCESS_MAX_MACS, virt: dict | None = None,
                itop_hosts: list[dict] | None = None,
                mac_of: Callable[[str], Awaitable[str | None]] | None = None) -> dict:
    """seg: Ergebnis von segments.build für genau EIN Netz (Hosts, Firewall-Kette)."""
    site = seg["sites"][0]
    net, fw = site["segments"][0], site["firewalls"][0]
    svc = seg["service"]
    ips = set(svc["ips"])
    warnings: list[str] = []
    out = {"title": f"Switch-Physik {svc['name']} · "
                    + (f"VLAN {net['vlan']}" if net.get("vlan") is not None else net["cidr"])
                    + f" · {site['name']}",
           "service": svc, "family": seg["family"], "site": site["name"], "net": net, "fw": fw,
           "switches": [], "links": [], "fw_links": [], "unplaced": [], "warnings": warnings}
    hosts = segments._visible_hosts(net, ips, hide_not_in_itop, hide_not_in_service)
    if lldp is None:
        warnings.append("LibreNMS nicht verfügbar — ohne LLDP und FDB gibt es keine Physik.")
        out["unplaced"] = [{"host": h, "reason": "LibreNMS nicht verfügbar"} for h in hosts]
        out["stats"] = _stats(out, hosts)
        return out

    by_id = segments.librenms_by_id(lldp["index"])
    fw_ips, site_nets = segments.device_nets(inv, net["device"])
    fw_names = {d.lower() for d in inv.devices}
    is_me_name, me_ids = segments.firewall_match(net["device"], by_id, fw_ips)
    cands = segments.vlan_switches(net["device"], net["vlan"], lldp, fw_names, fw_ips, site_nets)
    if len(cands) > MAX_SWITCHES:
        warnings.append(f"{len(cands)} Switches führen das VLAN — abgefragt werden die ersten "
                        f"{MAX_SWITCHES} (LLDP-Nähe zuerst).")
        cands = sorted(cands, key=lambda c: c["how"] != "lldp")[:MAX_SWITCHES]
    cand_ids = {c["id"] for c in cands}

    # LLDP je Port: überwachter Nachbar, bekannter Switch oder die Firewall →
    # Uplink; ein anderer Nachbar (Hypervisor, AP, Telefon) → Edge.
    known = {n for d in by_id.values() for k in ("sysName", "hostname")
             if (n := str(d.get(k) or "").strip().lower().split(".")[0])}
    port_nb: dict[tuple[str, str], str] = {}
    port_peer: dict[tuple[str, str], str] = {}
    adj: dict[str, set[str]] = {}
    for ln in lldp["links"]:
        a, b = str(ln.get("local_device_id") or ""), str(ln.get("remote_device_id") or "")
        key = (a, str(ln.get("local_port_id") or ""))
        rname = str(ln.get("remote_hostname") or "").strip()
        if a in by_id and key[1]:
            if b in by_id or rname.lower().split(".")[0] in known or is_me_name(rname):
                port_nb[key] = "uplink"
            elif rname or ln.get("remote_platform"):
                # Nachbar ohne Switch-Rolle. Nur ein Hostname taugt als „via" —
                # meldet sich bloß eine Plattform oder eine Beschreibung mit
                # Leerzeichen (Server-NIC mit eigenem LLDP-Agenten: „Broadcom
                # P210p NetXtreme-E …"), ist der Nachbar der Host selbst.
                port_nb.setdefault(key, "edge")
                if rname and not re.search(r"\s", rname):
                    port_peer[key] = rname
        if a in by_id and b in by_id:
            adj.setdefault(a, set()).add(b)
            adj.setdefault(b, set()).add(a)

    vlan_ids = ({str(r.get("vlan_id")) for r in lldp["vlans"]
                 if segments._vlan_num(r) == net["vlan"]} if net["vlan"] is not None else None)
    host_by_mac = {m: h for h in hosts if (m := normalize_mac(h.get("mac")))}

    sem = asyncio.Semaphore(CONCURRENCY)
    port_names: dict[str, dict[str, str]] = {}

    async def load(did: str) -> tuple[str, list[dict]]:
        async with sem:
            try:
                rows, plist = await fdb(did), await ports(did)
            except Exception as exc:
                warnings.append(f"{by_id[did].get('sysName') or did}: FDB nicht abrufbar ({exc}).")
                return did, []
        port_names[did] = {str(p.get("port_id")): _port_name(p) for p in plist}
        return did, rows

    # Je Port: ALLE MACs und VLANs (die Portklasse) und die MACs dieses VLANs.
    # Gezählt über alle VLANs — ein Trunk trägt in EINEM VLAN oft nur eine
    # MAC und sähe sonst aus wie ein Access-Port.
    all_macs: dict[tuple[str, str], set[str]] = {}
    port_vlans: dict[tuple[str, str], set[str]] = {}
    in_vlan: dict[tuple[str, str], set[str]] = {}
    for did, rows in await asyncio.gather(*(load(c) for c in sorted(cand_ids))):
        for r in rows:
            pid = str(r.get("port_id") or "")
            mac = normalize_mac(r.get("mac_address"))
            if not pid or not mac:
                continue
            key = (did, pid)
            all_macs.setdefault(key, set()).add(mac)
            port_vlans.setdefault(key, set()).add(str(r.get("vlan_id")))
            if vlan_ids is None or str(r.get("vlan_id")) in vlan_ids:
                in_vlan.setdefault(key, set()).add(mac)

    def kind(key: tuple[str, str]) -> str:
        if key in port_nb:
            return port_nb[key]
        if LAG_PORT.match(port_names.get(key[0], {}).get(key[1], "")):
            return "uplink"
        if len(all_macs[key]) <= access_max and len(port_vlans[key]) <= ACCESS_MAX_VLANS:
            return "access"
        return "trunk"

    kinds = {key: kind(key) for key in in_vlan}
    # Ein Host steht NUR an seinem Zuhause: Access-Port, sonst ein Edge-Port
    # (hinter einem Gerät mit LLDP). Gibt es beides nicht, ist er eine VM
    # hinter einem Hypervisor-Trunk ohne LLDP — dann der Trunk mit den
    # wenigsten MACs, das ist der nächste am Hypervisor. Uplinks und LAGs
    # (immer Switch oder Firewall) tragen ihn nur durch.
    # VMs laut iTop: Hypervisor bzw. Farm und deren physische Server. Die MAC
    # des Servers (ARP-Historie) zeigt seinen Switchport — dort hängen auch
    # seine VMs, selbst wenn ihre MAC in keiner FDB steht.
    hyp = await _hypervisors(hosts, virt, itop_hosts or [], mac_of)
    server_keys: dict[str, set[tuple[str, str]]] = {}
    for info in hyp.values():
        for hv in info["hvs"]:
            if hv["name"] in server_keys:
                continue
            server_keys[hv["name"]] = {key for key, macs in all_macs.items()
                                       if hv.get("mac") in macs and kind(key) != "uplink"}

    best: dict[str, tuple[int, int, str, str]] = {}
    seen_uplink: set[str] = set()
    for key, macs in in_vlan.items():
        hits = macs & host_by_mac.keys()
        if kinds[key] == "uplink":
            seen_uplink |= hits
            continue
        for mac in hits:
            info = hyp.get(id(host_by_mac[mac]))
            on_server = info and any(key in server_keys.get(hv["name"], ())
                                     for hv in info["hvs"])
            rank = (-1 if on_server else KIND_RANK[kinds[key]], len(all_macs[key]), *key)
            if mac not in best or rank < best[mac]:
                best[mac] = rank
    attached: dict[str, list[dict]] = {}

    def attach(host: dict, did: str, pid: str, k: int, n: int, basis: str) -> None:
        peer = port_peer.get((did, pid))
        if peer and _short(peer) in (_short(host.get("name")), host["ip"]):
            peer = None                                   # der Nachbar IST der Host
        info = hyp.get(id(host))
        attached.setdefault(did, []).append(
            {"host": host, "port": port_names.get(did, {}).get(pid, pid),
             "via": peer, "shared": n > 1, "trunk": k == KIND_RANK["trunk"],
             "trunk_macs": n, "trunk_vlans": len(port_vlans.get((did, pid), ())),
             "hypervisor": info["label"] if info else None, "basis": basis})

    for mac, (k, n, did, pid) in best.items():
        attach(host_by_mac[mac], did, pid, k, n, "fdb")
    placed = {id(r["host"]) for rows in attached.values() for r in rows}
    # VM ohne eigenen FDB-Eintrag: an den Port ihres Servers — nur wenn der
    # Hypervisor eindeutig ist (eine Farm lässt offen, auf welchem sie läuft).
    for h in hosts:
        info = hyp.get(id(h))
        if id(h) in placed or not info or len(info["hvs"]) != 1:
            continue
        keys = sorted(server_keys.get(info["hvs"][0]["name"], ()),
                      key=lambda k: (KIND_RANK.get(kinds.get(k) or kind(k), 3),
                                     len(all_macs[k]), k))
        if keys:
            did, pid = keys[0]
            attach(h, did, pid, KIND_RANK.get(kind(keys[0]), 0), len(all_macs[keys[0]]), "itop")
            placed.add(id(h))

    def reason(h: dict) -> str:
        info = hyp.get(id(h))
        mac = normalize_mac(h.get("mac"))
        if info and len(info["hvs"]) > 1:
            return f"{info['label']} — Hypervisor nicht eindeutig, VM-MAC in keiner FDB"
        if info and info["hvs"]:
            return f"{info['label']} — Switchport des Servers unbekannt"
        if not mac:
            return "keine MAC bekannt"
        if mac in seen_uplink:
            return "nur an Uplinks/LAGs zwischen Switches gesehen"
        return "in keiner FDB"
    out["unplaced"] = [{"host": h, "reason": reason(h)} for h in hosts if id(h) not in placed]

    # Baum zur Firewall: Breitensuche ab den Switches an der Firewall, über
    # Switches (nicht über andere Firewalls). Host-Switches ziehen ihren Weg nach.
    roots = {str(ln.get("local_device_id")) for ln in lldp["links"]
             if str(ln.get("local_device_id") or "") in by_id
             and (is_me_name(ln.get("remote_hostname"))
                  or str(ln.get("remote_device_id") or "") in me_ids)}
    roots |= {str(ln.get("remote_device_id")) for ln in lldp["links"]
              if str(ln.get("local_device_id") or "") in me_ids
              and str(ln.get("remote_device_id") or "") in by_id}
    roots -= me_ids
    parent: dict[str, str | None] = {r: None for r in roots}
    depth: dict[str, int] = {r: 1 for r in roots}
    queue = deque(roots)
    while queue:
        cur = queue.popleft()
        for nxt in sorted(adj.get(cur, ())):
            if nxt in parent or nxt in me_ids or segments._is_firewall(by_id[nxt], fw_names):
                continue
            parent[nxt], depth[nxt] = cur, depth[cur] + 1
            queue.append(nxt)
    keep: dict[str, str] = {d: "hosts" for d in attached}
    for did in list(attached):
        cur = parent.get(did)
        while cur is not None:
            keep.setdefault(cur, "transit")
            cur = parent.get(cur)
    for did in keep:
        if did not in port_names and did in by_id:
            try:
                port_names[did] = {str(p.get("port_id")): _port_name(p) for p in await ports(did)}
            except Exception:
                port_names[did] = {}

    unknown = {did: len({m for key, macs in in_vlan.items()
                         if key[0] == did and kinds[key] in ("access", "edge")
                         for m in macs if m not in host_by_mac})
               for did in keep}
    for did, role in keep.items():
        d = by_id[did]
        out["switches"].append({
            "id": did, "name": d.get("sysName") or d.get("hostname") or did, "ip": d.get("ip"),
            "hardware": d.get("hardware"), "role": role,
            "level": depth.get(did), "parent": parent.get(did),
            "hosts": sorted(attached.get(did, []),
                            key=lambda r: (r["trunk"], _port_key(r["port"]))),
            "unknown": unknown.get(did, 0)})

    def pname(did: str, pid) -> str:
        return port_names.get(did, {}).get(str(pid), str(pid or "?"))

    seen: set[frozenset] = set()
    for ln in lldp["links"]:
        a, b = str(ln.get("local_device_id") or ""), str(ln.get("remote_device_id") or "")
        if a in keep and b in keep and a != b:
            pair = frozenset((a, b))
            if pair in seen:
                continue
            seen.add(pair)
            out["links"].append({"a": a, "b": b, "a_port": pname(a, ln.get("local_port_id")),
                                 "b_port": _remote_port(ln)})
        elif a in keep and (is_me_name(ln.get("remote_hostname")) or b in me_ids):
            out["fw_links"].append({"sw": a, "sw_port": pname(a, ln.get("local_port_id")),
                                    "fw_port": _remote_port(ln), "lldp": True})
        elif a in me_ids and b in keep:
            out["fw_links"].append({"sw": b, "sw_port": _remote_port(ln),
                                    "fw_port": "?", "lldp": True})
    # Je Switch EIN Uplink — LibreNMS meldet die Kante oft von beiden Seiten.
    uniq: dict[str, dict] = {}
    for fl in out["fw_links"]:
        if fl["sw"] not in uniq or uniq[fl["sw"]]["fw_port"] == "?":
            uniq[fl["sw"]] = fl
    out["fw_links"] = list(uniq.values())
    # Host-Switch ohne LLDP-Weg zur Firewall: gestrichelt anbinden, statt ihn
    # freischwebend zu lassen — aber als unbelegt kennzeichnen.
    linked = {fl["sw"] for fl in out["fw_links"]}
    for sw in out["switches"]:
        if sw["level"] is None and sw["id"] not in linked:
            out["fw_links"].append({"sw": sw["id"], "sw_port": None, "fw_port": None,
                                    "lldp": False})
    if not cands:
        warnings.append("Kein Switch am Standort führt das VLAN in LibreNMS — weder per LLDP an "
                        "der Firewall noch per Management-IP in einem Netz der Firewall.")
    elif not attached:
        warnings.append(f"{len(cands)} Switches führen das VLAN, aber in keiner FDB steht eine "
                        "MAC eines gezeichneten Hosts an einem Access-Port.")
    if out["unplaced"]:
        up_only = sum(1 for u in out["unplaced"] if u["reason"].startswith("nur an Uplinks"))
        warnings.append(f"{len(out['unplaced'])} Hosts ohne Platz im Plan — sie stehen mit Grund "
                        "in einer Liste daneben"
                        + (f"; {up_only} davon nur an Uplinks/LAGs gesehen (ihr Switch ist "
                           "vermutlich nicht in LibreNMS)" if up_only else "") + ".")
    guessed = sum(1 for rows in attached.values() for r in rows
                  if r["trunk"] and not r["hypervisor"])
    if guessed:
        warnings.append(f"{guessed} Hosts nur an Trunks ohne LLDP gesehen und im iTop keiner "
                        "VM zugeordnet — als „Hypervisor? (Trunk)“ gezeichnet.")
    by_itop = sum(1 for rows in attached.values() for r in rows if r["basis"] == "itop")
    if by_itop:
        warnings.append(f"{by_itop} VMs ohne eigenen FDB-Eintrag stehen am Switchport ihres "
                        "Hypervisor-Servers (laut iTop).")
    if any(fl["lldp"] is False for fl in out["fw_links"]):
        warnings.append("Für einige Switches ist der Weg zur Firewall per LLDP nicht belegt — "
                        "gestrichelt angebunden.")
    out["stats"] = _stats(out, hosts)
    return out


async def _hypervisors(hosts: list[dict], virt: dict | None, itop_hosts: list[dict],
                       mac_of) -> dict[int, dict]:
    """id(Host) → {label, hvs: [{name, server, ip, mac}]} für jede VM laut iTop.
    Der Virtual Host einer VM ist ein Hypervisor ODER eine Farm; bei einer
    Farm kommen alle ihre Hypervisoren in Frage."""
    if not virt or not virt.get("vms"):
        return {}
    hvs_all = virt.get("hypervisors") or {}
    by_id = {h.get("id"): h for h in itop_hosts if h.get("id")}
    out: dict[int, dict] = {}
    for h in hosts:
        vm = virt["vms"].get(h.get("itop_id") or "")
        if not vm or not vm["host_id"]:
            continue
        if vm["host_id"] in hvs_all:
            chosen = [hvs_all[vm["host_id"]]]
            label = chosen[0]["name"] or vm["host_name"]
        else:
            chosen = [hv for hv in hvs_all.values() if hv["farm_id"] == vm["host_id"]]
            label = f"Farm {vm['host_name']}"
        hvs = []
        for hv in chosen:
            server = by_id.get(hv["server_id"])
            hvs.append({"name": hv["name"] or hv["server_name"],
                        "server": hv["server_name"], "ip": (server or {}).get("ip")})
        out[id(h)] = {"label": label, "hvs": hvs}
    if mac_of is not None:
        ips = sorted({hv["ip"] for info in out.values() for hv in info["hvs"] if hv["ip"]})
        macs = dict(zip(ips, await asyncio.gather(*(mac_of(ip) for ip in ips[:MAX_SERVERS]),
                                                  return_exceptions=True)))
        for info in out.values():
            for hv in info["hvs"]:
                m = macs.get(hv["ip"])
                hv["mac"] = normalize_mac(m) if isinstance(m, str) else None
    return out


def _port_key(name: str) -> tuple:
    return tuple(int(p) if p.isdigit() else p for p in re.split(r"(\d+)", name or ""))


def _stats(out: dict, hosts: list[dict]) -> dict:
    return {"sites": 1, "segments": 1, "firewalls": 1,
            "switches": len(out["switches"]),
            "switches_transit": sum(1 for s in out["switches"] if s["role"] == "transit"),
            "hosts": len(hosts), "hosts_placed": len(hosts) - len(out["unplaced"]),
            "hosts_not_in_itop": sum(1 for h in hosts if not h.get("in_itop")),
            "hosts_not_in_service": sum(1 for h in hosts
                                        if service_view._foreign(h, set(out["service"]["ips"])))}


# ── Zeichnung ─────────────────────────────────────────────────────────────────

BLOCK_W = 300
ICON_COL = 96
NAME_LINE = 13
SW_W, SW_H = 44, 32
ROW = 17
HEAD = 44
LEVEL_GAP = 80
COL_GAP = 40
X0, Y0 = 40, 40
FW_W, FW_H = 530, 78
CLOUD_W, CLOUD_H = 200, 90

STYLE = {
    "block": "rounded=1;arcSize=4;html=1;fillColor=#f7f7f7;strokeColor=#bbbbbb;",
    "block-transit": "rounded=1;arcSize=4;html=1;fillColor=#ffffff;strokeColor=#cccccc;"
                     "dashed=1;",
    "switch": "shape={stencil};html=1;aspect=fixed;{paint}",
    "name": "text;html=1;align=left;verticalAlign=top;fontSize=10;whiteSpace=wrap;",
    "row": "text;html=1;align=left;verticalAlign=middle;fontSize=9;whiteSpace=nowrap;"
           "overflow=hidden;"
           "spacingLeft=2;",
    "row-icon": "shape={stencil};html=1;aspect=fixed;{paint}",
    "vm": "text;html=1;align=left;verticalAlign=middle;fontSize=8;whiteSpace=nowrap;"
          "overflow=hidden;spacingLeft=1;",
    "lldp": "edgeStyle=orthogonalEdgeStyle;rounded=1;html=1;endArrow=none;strokeWidth=2;"
            "strokeColor=#6c8ebf;fontSize=9;labelBackgroundColor=#ffffff;",
    "uplink": "edgeStyle=orthogonalEdgeStyle;rounded=1;html=1;endArrow=none;strokeWidth=2;"
              f"strokeColor={segments.GREEN};fontSize=9;labelBackgroundColor=#ffffff;",
    "uplink-guess": "edgeStyle=orthogonalEdgeStyle;rounded=1;html=1;endArrow=none;"
                    "strokeWidth=2;strokeColor=#999999;dashed=1;fontSize=9;"
                    "labelBackgroundColor=#ffffff;fontColor=#777777;",
    "unplaced": "rounded=0;html=1;whiteSpace=wrap;align=left;verticalAlign=top;fontSize=9;"
                "spacingLeft=6;spacingTop=4;fillColor=#fff8e1;strokeColor=#d6b656;",
}


PORT_ABBR = (("hundredgigabitethernet", "Hu"), ("hundredgige", "Hu"),
             ("fortygigabitethernet", "Fo"), ("fortygige", "Fo"),
             ("twentyfivegige", "Twe"), ("ten-gigabitethernet", "Te"),
             ("tengigabitethernet", "Te"), ("gigabitethernet", "Gi"),
             ("fastethernet", "Fa"), ("bridge-aggregation", "BAGG"), ("port-channel", "Po"))
VM_ROW = 14
VM_MAX = 20
GROUP_HEAD = 19


def short_port(name: str) -> str:
    """`Ten-GigabitEthernet1/0/44` → `Te1/0/44` — der volle Name steht im Tooltip."""
    low = (name or "").lower()
    for long, short in PORT_ABBR:
        if low.startswith(long):
            return short + name[len(long):]
    return name or "?"


def _name_lines(sw: dict) -> int:
    return 1 + len(sw["name"]) // 14 + (1 if sw.get("ip") else 0) + (sw["role"] == "transit")


def _items(sw: dict) -> tuple[list[dict], list[dict]]:
    """Zeilen für direkt angeschlossene Hosts, Gruppen je Hypervisor-Port für VMs."""
    rows, groups = [], {}
    for r in sw["hosts"]:
        if r.get("hypervisor") or r.get("trunk"):
            g = groups.setdefault((r["port"], r.get("hypervisor") or ""),
                                  {"port": r["port"], "hv": r.get("hypervisor"), "vms": []})
            g["vms"].append(r)
        else:
            rows.append(r)
    for g in groups.values():
        g["vms"].sort(key=lambda r: (r["host"].get("name") or "~", r["host"]["ip"]))
    return rows, sorted(groups.values(), key=lambda g: _port_key(g["port"]))


def _group_h(g: dict) -> float:
    n = min(len(g["vms"]), VM_MAX) + (1 if len(g["vms"]) > VM_MAX else 0)
    return GROUP_HEAD + n * VM_ROW + 6


def _block_h(sw: dict) -> float:
    rows, groups = _items(sw)
    n = min(len(rows), HOST_ROWS_MAX) + (1 if len(rows) > HOST_ROWS_MAX else 0)
    content = 10 + n * ROW + sum(_group_h(g) for g in groups) + (ROW if sw["unknown"] else 0) + 10
    return max(HEAD + 8, content, 8 + SW_H + 6 + _name_lines(sw) * NAME_LINE + 8)


def _color(h: dict, ips: set[str]) -> str:
    if not h.get("in_itop"):
        return f"color:{segments.RED};"
    if service_view._foreign(h, ips):
        return f"color:{segments.RED};font-weight:bold;"
    return ""


def _cut(text: str, n: int) -> str:
    return text if len(text) <= n else text[:n - 1] + "…"


def _row_label(r: dict, ips: set[str]) -> str:
    h = r["host"]
    name = esc(h.get("name") or "")
    via = f"<i>via {esc(_cut(r['via'], 18))}</i> · " if r.get("via") else ""
    text = f"<b>{esc(short_port(r['port']))}</b> · {via}" + (f"{name} " if name else "") \
        + esc(h["ip"])
    color = _color(h, ips)
    return f"<span style='{color}'>{text}</span>" if color else text


def _row_tip(r: dict, ips: set[str]) -> str:
    return (f"Port {r['port']}\n" + service_view._host_tooltip(r["host"], ips)
            + (f"\nhinter LLDP-Nachbar {r['via']}" if r.get("via") else "")
            + (f"\nVM auf {r['hypervisor']} (laut iTop)"
               + (" — Port des Servers, die VM-MAC selbst steht in keiner FDB"
                  if r.get("basis") == "itop" else "")
               if r.get("hypervisor") else "")
            + (f"\nvermutlich VM hinter einem Hypervisor-Trunk (Port ohne LLDP, "
               f"{r['trunk_macs']} MACs in {r['trunk_vlans']} VLANs)"
               if r.get("trunk") and not r.get("hypervisor") else "")
            + ("\nPort trägt mehrere MACs" if r["shared"] else ""))


def _draw_hosts(doc: Doc, bid: str, sw: dict, ips: set[str]) -> None:
    """Rechts im Switch-Kasten: Access-Hosts als Zeilen, VMs als Hypervisor-
    Symbol mit Port und den VM-Namen eingerückt darunter."""
    x0, w = ICON_COL + 12, BLOCK_W - ICON_COL - 14
    rows, groups = _items(sw)
    ry = 10
    for r in rows[:HOST_ROWS_MAX]:
        hshape, hpaint = drawio.SHAPES[drawio.host_shape(r["host"])]
        doc.vertex("", STYLE["row-icon"].format(stencil=hshape, paint=hpaint),
                   x0, ry + 2, 13, 13, parent=bid)
        doc.vertex(_row_label(r, ips), STYLE["row"], x0 + 16, ry, w - 16, ROW, parent=bid,
                   tooltip=_row_tip(r, ips))
        ry += ROW
    if len(rows) > HOST_ROWS_MAX:
        doc.vertex(esc(f"… +{len(rows) - HOST_ROWS_MAX} weitere"), STYLE["row"], x0 + 16, ry,
                   w - 16, ROW, parent=bid)
        ry += ROW
    sshape, spaint = drawio.SHAPES["server"]
    for g in groups:
        hv = g["hv"] or "Hypervisor?"
        tip = (f"{hv} an Port {g['port']}\n"
               + ("laut iTop" if g["hv"] else "nicht im iTop — nur an einem Trunk ohne LLDP gesehen")
               + f"\n{len(g['vms'])} VMs in diesem VLAN")
        doc.vertex("", STYLE["row-icon"].format(stencil=sshape, paint=spaint),
                   x0, ry + 1, 16, 16, parent=bid, tooltip=tip)
        doc.vertex(f"<b>{esc(_cut(hv, 22))}</b> · {esc(short_port(g['port']))}"
                   + ("" if g["hv"] else " <i>(Trunk)</i>"),
                   STYLE["row"], x0 + 19, ry, w - 19, GROUP_HEAD, parent=bid, tooltip=tip)
        vy = ry + GROUP_HEAD
        for r in g["vms"][:VM_MAX]:
            h = r["host"]
            vshape, vpaint = drawio.SHAPES[drawio.host_shape(h)]
            doc.vertex("", STYLE["row-icon"].format(stencil=vshape, paint=vpaint),
                       x0 + 20, vy + 2, 10, 10, parent=bid)
            label = esc(h.get("name") or h["ip"])
            color = _color(h, ips)
            doc.vertex(f"<span style='{color}'>{label}</span>" if color else label,
                       STYLE["vm"], x0 + 33, vy, w - 33, VM_ROW, parent=bid,
                       tooltip=_row_tip(r, ips))
            vy += VM_ROW
        if len(g["vms"]) > VM_MAX:
            doc.vertex(esc(f"… +{len(g['vms']) - VM_MAX} weitere VMs"), STYLE["vm"], x0 + 33, vy,
                       w - 33, VM_ROW, parent=bid)
        ry += _group_h(g)
    if sw["unknown"]:
        doc.vertex(f"<i>+ {sw['unknown']} MACs ohne bekannten Host</i>", STYLE["row"],
                   x0, ry, w, ROW, parent=bid)


def _levels(model: dict) -> list[list[dict]]:
    """Switches nach LLDP-Tiefe; ohne Weg zur Firewall in die erste Reihe.
    In jeder Reihe sortiert nach der Lage des Elternteils — weniger Kreuzungen."""
    rows: dict[int, list[dict]] = {}
    for sw in model["switches"]:
        rows.setdefault(sw["level"] or 1, []).append(sw)
    out, order = [], {}
    for lvl in sorted(rows):
        row = sorted(rows[lvl], key=lambda s: (order.get(s["parent"], -1), s["name"]))
        for i, s in enumerate(row):
            order[s["id"]] = i
        out.append(row)
    return out


def render(model: dict, title_block: dict | None = None) -> str:
    return render_pages([model], [title_block])


def render_pages(models: list[dict], title_blocks: list[dict | None]) -> str:
    """Eine Seite je VLAN in derselben Datei."""
    doc = Doc(_page_name(models[0]))
    for i, (m, tb) in enumerate(zip(models, title_blocks)):
        if i:
            doc.page(_page_name(m))
        _draw_page(doc, m, tb)
    return doc.to_xml()


def _page_name(model: dict) -> str:
    net = model["net"]
    vlan = f"VLAN {net['vlan']}" if net.get("vlan") is not None else net["cidr"]
    return f"{model['site']} · {vlan}"


def _draw_page(doc: Doc, model: dict, title_block: dict | None) -> None:
    ips = set(model["service"]["ips"])
    net, fw = model["net"], model["fw"]
    levels = _levels(model)
    width = max([len(r) * (BLOCK_W + COL_GAP) - COL_GAP for r in levels] + [FW_W + CLOUD_W + 80])

    # Oben: SD-WAN, darunter die Firewall mit Segment- und Router-VDOM.
    fx = X0 + (width - FW_W) / 2
    cloud_y = Y0
    fw_y = cloud_y + CLOUD_H + 50
    cloud = doc.vertex("SD-WAN", segments.STYLE["cloud"].replace("fontSize=16", "fontSize=13"),
                       fx + FW_W - CLOUD_W + 20, cloud_y, CLOUD_W, CLOUD_H)
    fid = doc.vertex("", segments.STYLE["fw"], fx, fw_y, FW_W, FW_H,
                     tooltip=f"FortiGate {fw['device']}")
    doc.vertex("", segments.STYLE["fw-icon"], 10, (FW_H - 40) / 2 - 8, 40, 40, parent=fid)
    ha = f" <span style='color:#3d6ea8'>HA {esc(fw['ha'].get('mode') or '')}</span>" \
        if fw.get("ha") else ""
    doc.vertex(f"<b>{esc(fw['device'])}</b>{ha}", segments.STYLE["fw-name"], 0, FW_H - 22, 120,
               18, parent=fid)
    seg_vdom = net["vdom"]
    router = fw.get("router")
    pill_w = 165
    seg_pill = doc.vertex(esc(f"VDOM {seg_vdom}") + f"<br><span style='font-size:8px'>"
                          f"{esc(net['interface'])} · GW {esc(net['fw_ip'])}</span>",
                          segments.STYLE["pill-router" if seg_vdom == router else "pill"],
                          130, (FW_H - 34) / 2, pill_w, 34, parent=fid)
    out_pill = seg_pill
    if router and router != seg_vdom:
        out_pill = doc.vertex(esc(f"VDOM {router}") + "<br><span style='font-size:8px'>Router"
                              "</span>", segments.STYLE["pill-router"], 130 + pill_w + 50,
                              (FW_H - 34) / 2, pill_w, 34, parent=fid)
        doc.edge(seg_pill, out_pill, esc(fw["links"].get(seg_vdom, "Inter-VDOM")),
                 segments.STYLE["link"] + "strokeColor=#888888;dashed=1;", parent=fid)
    up = fw["uplinks"].get(router or seg_vdom) or fw.get("uplink") or ""
    doc.edge(out_pill, cloud, esc(up), segments.STYLE["link"] + "strokeColor=#d4762c;"
             "exitX=0.5;exitY=0;")

    # Switches in Reihen nach LLDP-Tiefe.
    cells: dict[str, str] = {}
    y = fw_y + FW_H + LEVEL_GAP
    stencil, paint = drawio.SHAPES["switch"]
    for row in levels:
        row_w = len(row) * (BLOCK_W + COL_GAP) - COL_GAP
        x = X0 + (width - row_w) / 2
        row_h = max(_block_h(s) for s in row)
        for sw in row:
            h = _block_h(sw)
            transit = sw["role"] == "transit"
            tip = "\n".join(p for p in (
                f"Switch {sw['name']}", sw.get("ip"), sw.get("hardware"),
                "Transit — kein Host dieses VLANs direkt angeschlossen" if transit
                else f"{len(sw['hosts'])} Hosts direkt angeschlossen",
                f"{sw['unknown']} weitere MACs ohne bekannten Host" if sw["unknown"] else None)
                if p)
            bid = doc.vertex("", STYLE["block-transit" if transit else "block"], x, y, BLOCK_W, h,
                             tooltip=tip)
            # Leitungen setzen am Kasten an (über dem Symbol), nicht am Symbol —
            # sonst liefen sie durch den Namen darunter.
            cells[sw["id"]] = bid
            doc.vertex("", STYLE["switch"].format(stencil=stencil, paint=paint),
                       (ICON_COL - SW_W) / 2, 8, SW_W, SW_H, parent=bid, tooltip=tip)
            doc.vertex(f"<b>{esc(sw['name'])}</b>"
                       + (f"<br><span style='color:#777'>{esc(sw['ip'])}</span>" if sw.get("ip")
                          else "") + ("<br><i>Transit</i>" if transit else ""),
                       STYLE["name"], 4, SW_H + 12, ICON_COL - 4, _name_lines(sw) * NAME_LINE + 4,
                       parent=bid)
            _draw_hosts(doc, bid, sw, ips)
            x += BLOCK_W + COL_GAP
        y += row_h + LEVEL_GAP

    ex = f"{(ICON_COL / 2) / BLOCK_W:.3f}"
    for ln in model["links"]:
        a, b = model_switch(model, ln["a"]), model_switch(model, ln["b"])
        same = (a["level"] or 1) == (b["level"] or 1)
        top, low = (a, b) if (a["level"] or 1) <= (b["level"] or 1) else (b, a)
        tp, lp = (ln["a_port"], ln["b_port"]) if top is a else (ln["b_port"], ln["a_port"])
        doc.edge(cells[top["id"]], cells[low["id"]],
                 esc(f"{short_port(tp)} ↔ {short_port(lp)}"), STYLE["lldp"]
                 + (f"exitX={ex};exitY=0;entryX={ex};entryY=0;" if same
                    else f"exitX={ex};exitY=1;entryX={ex};entryY=0;"))
    for fl in model["fw_links"]:
        label = (f"{fl['fw_port']} ↔ {short_port(fl['sw_port'])}" if fl["lldp"]
                 else "Uplink per LLDP nicht belegt")
        doc.edge(fid, cells[fl["sw"]], esc(label),
                 STYLE["uplink" if fl["lldp"] else "uplink-guess"]
                 + f"exitX=0.15;exitY=1;entryX={ex};entryY=0;")

    # Hosts ohne Switchport und Legende rechts.
    lx = X0 + width + 60
    if model["unplaced"]:
        lines = [f"<b>{len(model['unplaced'])} Hosts ohne Access-Port</b>"]
        lines += [(f"{esc(u['host'].get('name') or '')} " if u["host"].get("name") else "")
                  + esc(u["host"]["ip"]) + f" <i style='color:#7a5c00'>– {esc(u['reason'])}</i>"
                  for u in model["unplaced"][:40]]
        if len(model["unplaced"]) > 40:
            lines.append(f"… +{len(model['unplaced']) - 40} weitere")
        doc.vertex("<br>".join(lines), STYLE["unplaced"], lx, Y0 + 180, 360,
                   30 + len(lines) * 12)
    vlan = f"VLAN {net['vlan']}" if net.get("vlan") is not None else net["interface"]
    legend = "<br>".join([
        f"<b>{esc(model['title'])}</b>",
        f"{esc(model['site'])} · {esc(net['cidr'])} · Servicefamilie {esc(model['family'])}",
        f"<span style='color:{segments.GREEN};font-weight:bold'>━ grün</span> = Uplink "
        "Firewall ↔ Switch (LLDP)",
        "<span style='color:#6c8ebf;font-weight:bold'>━ blau</span> = Switch ↔ Switch (LLDP), "
        "Ports an beiden Enden",
        f"Zeilen: Access-Port · Host — laut FDB in {esc(vlan)}; „via …“ = hinter einem "
        "LLDP-Nachbarn ohne Switch-Rolle",
        "Server-Symbol = Hypervisor (laut iTop) an seinem Port, darunter seine VMs; "
        "„Hypervisor? (Trunk)“ = Trunk ohne LLDP, im iTop keine VM",
        "gestrichelter Kasten = Transit-Switch ohne eigene Hosts",
        f"<span style='color:{segments.RED}'>rot</span> = nicht im iTop bzw. nicht am Service",
    ])
    doc.vertex(legend, segments.STYLE["legend"], lx, Y0, 360, 150)
    if title_block:
        tb_y = Y0 + 180 + (30 + (min(len(model["unplaced"]), 40) + 3) * 12 + 20
                           if model["unplaced"] else 0)
        titleblock.draw(doc, lx, tb_y, title_block)


def model_switch(model: dict, sid: str) -> dict:
    return next(s for s in model["switches"] if s["id"] == sid)
