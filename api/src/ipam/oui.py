"""Herkunft einer MAC am Präfix — nur die Fälle, die einen Befund erklären.

Kein vollständiges OUI-Register: gesucht sind virtuelle und geteilte MACs, an
denen ein „IP-Konflikt" meist gar keiner ist (VM, Cluster, VRRP/HSRP, NLB).
"""
from __future__ import annotations

# Präfix (klein, ohne Trenner) → (Bezeichnung, Art)
PREFIXES: list[tuple[str, str, str]] = [
    ("00005e0001", "VRRP (virtuelle Router-MAC)", "shared"),
    ("00005e0002", "VRRP IPv6 (virtuelle Router-MAC)", "shared"),
    ("00000c07ac", "Cisco HSRP v1 (virtuelle MAC)", "shared"),
    ("00000c9ff", "Cisco HSRP v2 (virtuelle MAC)", "shared"),
    ("0007b4", "Cisco GLBP (virtuelle MAC)", "shared"),
    ("02bf", "Windows NLB Unicast (Cluster-MAC)", "shared"),
    ("03bf", "Windows NLB Multicast (Cluster-MAC)", "shared"),
    ("00155d", "Microsoft Hyper-V (virtuelle NIC)", "virtual"),
    ("0003ff", "Microsoft Virtual PC/Hyper-V (alt)", "virtual"),
    ("005056", "VMware (virtuelle NIC)", "virtual"),
    ("000c29", "VMware (virtuelle NIC)", "virtual"),
    ("000569", "VMware (virtuelle NIC)", "virtual"),
    ("001c14", "VMware (virtuelle NIC)", "virtual"),
    ("080027", "VirtualBox (virtuelle NIC)", "virtual"),
    ("525400", "QEMU/KVM (virtuelle NIC)", "virtual"),
    ("00163e", "Xen (virtuelle NIC)", "virtual"),
    ("001dd8", "Microsoft (u. a. Hyper-V)", "virtual"),
    ("00090f", "Fortinet", "device"),
    ("04d590", "Fortinet", "device"),
    ("e81cba", "Fortinet", "device"),
    ("906cac", "Fortinet", "device"),
    ("704ca5", "Fortinet", "device"),
]


def vendor(mac: str | None) -> dict | None:
    m = "".join(c for c in (mac or "").lower() if c in "0123456789abcdef")
    for prefix, label, kind in PREFIXES:
        if m.startswith(prefix):
            return {"label": label, "kind": kind}
    if len(m) == 12 and int(m[1], 16) & 2:
        return {"label": "lokal verwaltete MAC (oft virtuell oder zufällig)", "kind": "virtual"}
    return None
