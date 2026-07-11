"""Regression: SyncManager._sync_adom muss ALLE Geräte/VDOMs/Packages
persistieren.

Der ursprüngliche Bug: _store() löscht pro (adom, kind) alle Altzeilen und
wurde in Schleifen (pro Gerät für interface/route, pro Package für policy)
aufgerufen — dadurch überlebte nur der letzte Durchlauf. Gegen den Simulator
fiel auf, dass fw-a komplett fehlte. Dieser Test reproduziert das ohne DB über
einen In-Memory-Fake-Pool.
"""
from __future__ import annotations

import pytest

from inventory.sync import SyncManager


class FakeConn:
    def __init__(self, store: dict):
        self._store = store

    def transaction(self):
        conn = self

        class _Tx:
            async def __aenter__(self_):
                return conn

            async def __aexit__(self_, *exc):
                return False
        return _Tx()

    async def execute(self, sql: str, *args):
        if sql.strip().startswith("DELETE"):
            adom, kind = args[0], args[1]
            for k in [k for k in self._store if k[0] == adom and k[1] == kind]:
                del self._store[k]
        elif "INSERT" in sql:
            adom, kind, key, data = args[0], args[1], args[2], args[3]
            self._store[(adom, kind, key)] = data


class FakePool:
    def __init__(self):
        self.store: dict = {}

    def acquire(self):
        conn = FakeConn(self.store)

        class _Acq:
            async def __aenter__(self_):
                return conn

            async def __aexit__(self_, *exc):
                return False
        return _Acq()


class FakeClient:
    """Antwortet auf die exakten URLs, die _sync_adom abfragt."""

    def __init__(self, responses: dict):
        self._responses = responses

    async def rpc(self, method: str, url: str, data=None):
        return self._responses.get(url, [])


def _responses() -> dict:
    return {
        "/dvmdb/adom/corp/device": [
            {"name": "fw-a", "vdom": [{"name": "root"}]},
            {"name": "fw-b", "vdom": [{"name": "root"}]},
        ],
        "/pm/pkg/adom/corp": [
            {"name": "pkg-a", "scope member": [{"name": "fw-a", "vdom": "root"}]},
            {"name": "pkg-b", "scope member": [{"name": "fw-b", "vdom": "root"}]},
        ],
        "/pm/config/adom/corp/pkg/pkg-a/firewall/policy": [{"policyid": 100}],
        "/pm/config/adom/corp/pkg/pkg-b/firewall/policy": [{"policyid": 200}],
        "/pm/config/adom/corp/obj/firewall/address": [],
        "/pm/config/adom/corp/obj/firewall/addrgrp": [],
        "/pm/config/adom/corp/obj/firewall/service/custom": [],
        "/pm/config/adom/corp/obj/firewall/service/group": [],
        "/pm/config/adom/corp/obj/firewall/vip": [],
        "/pm/config/adom/corp/obj/dynamic/interface": [],
        "/pm/config/device/fw-a/global/system/interface": [{"name": "lan1"}],
        "/pm/config/device/fw-b/global/system/interface": [{"name": "lan1"}],
        "/pm/config/device/fw-a/vdom/root/router/static": [{"dst": ["10.1.0.0", "255.255.240.0"]}],
        "/pm/config/device/fw-b/vdom/root/router/static": [{"dst": ["10.2.0.0", "255.255.240.0"]}],
    }


@pytest.mark.asyncio
async def test_sync_persists_all_devices_and_packages():
    pool = FakePool()
    mgr = SyncManager()
    await mgr._sync_adom(pool, FakeClient(_responses()), "corp", {})

    store = pool.store
    interfaces = {k[2] for k in store if k[1] == "interface"}
    routes = {k[2] for k in store if k[1] == "route"}
    policies = {k[2] for k in store if k[1] == "policy"}

    # Beide Geräte, beide VDOM-Routen, beide Packages müssen überleben —
    # nicht nur das jeweils letzte.
    assert interfaces == {"fw-a", "fw-b"}
    assert routes == {"fw-a|root", "fw-b|root"}
    assert policies == {"pkg-a", "pkg-b"}
