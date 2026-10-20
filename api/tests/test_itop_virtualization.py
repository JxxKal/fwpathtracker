"""iTop-Virtualisierung: VM → Hypervisor/Farm → Server, robust gegen fehlende Klassen."""
from __future__ import annotations

from resolver import itop_source

CFG = {"base_url": "https://itop.example.net", "user": "u", "password": "p"}


async def test_vms_and_hypervisors_are_indexed(monkeypatch):
    calls = []

    async def fake(client, base, user, pwd, cls, fields, oql=None):
        calls.append(cls)
        if cls == "VirtualMachine":
            return [{"_key": 11, "name": "vm-a", "virtualhost_id": 7, "virtualhost_name": "esx-07"}]
        return [{"_key": 7, "name": "esx-07", "server_id": 70, "server_name": "srv-esx-07",
                 "farm_id": 0, "farm_name": ""}]

    monkeypatch.setattr(itop_source, "_core_get", fake)
    monkeypatch.setattr(itop_source, "guard_egress_url", lambda *a: None)
    src = itop_source.ItopSource()
    out = await src.virtualization(CFG)
    assert out["vms"]["11"] == {"name": "vm-a", "host_id": "7", "host_name": "esx-07"}
    assert out["hypervisors"]["7"]["server_id"] == "70"
    await src.virtualization(CFG)                                   # gecacht
    assert calls == ["VirtualMachine", "Hypervisor"]


async def test_a_missing_class_leaves_the_rest_intact(monkeypatch):
    async def fake(client, base, user, pwd, cls, fields, oql=None):
        if cls == "Hypervisor":
            raise RuntimeError("Unknown class")
        return [{"_key": 11, "name": "vm-a", "virtualhost_id": 7, "virtualhost_name": "x"}]

    monkeypatch.setattr(itop_source, "_core_get", fake)
    monkeypatch.setattr(itop_source, "guard_egress_url", lambda *a: None)
    out = await itop_source.ItopSource().virtualization(CFG)
    assert "11" in out["vms"] and out["hypervisors"] == {}
    assert out["errors"] and out["errors"][0].startswith("Hypervisor")
