"""FAC-REST-Client und Userliste."""
from __future__ import annotations

import base64

import httpx
import pytest

from webdrive.fac import PAGE, FacClient, FacError, FacNotConfigured
from webdrive.state import build, user_list
from webdrive_fixtures import IDENTITIES, NOW, SINCE, reference_events

CFG = {"fac_url": "https://10.0.17.38/api/v1/", "fac_user": "a38", "fac_api_key": "key"}


def fac_user(name, **kw):
    return {"username": name, "dn": f"CN={name},OU=Webdrive,DC=example", "email": f"{name}@example.com",
            "first_name": "Vor", "last_name": "Nach", "active": True, **kw}


def mock(users, status=200):
    seen = []

    def handler(request):
        seen.append(request)
        if status != 200:
            return httpx.Response(status, text="nope")
        off, lim = int(request.url.params["offset"]), int(request.url.params["limit"])
        return httpx.Response(200, json={"meta": {"total_count": len(users)}, "objects": users[off:off + lim]})

    return FacClient(transport=httpx.MockTransport(handler)), seen


async def test_pages_and_auth():
    users = [fac_user(f"u{i}") for i in range(PAGE + 5)]
    client, seen = mock(users)
    out = await client.ldapusers(CFG)
    assert len(out) == PAGE + 5
    assert seen[0].url.path == "/api/v1/ldapusers/"
    assert seen[0].headers["authorization"] == "Basic " + base64.b64encode(b"a38:key").decode()


async def test_cached_until_invalidated():
    client, seen = mock([fac_user("u1")])
    await client.ldapusers(CFG)
    await client.ldapusers(CFG)
    assert len(seen) == 1
    client.invalidate()
    await client.ldapusers(CFG)
    assert len(seen) == 2


async def test_errors():
    client, _ = mock([], status=401)
    with pytest.raises(FacError, match="API-Key"):
        await client.test(CFG)
    with pytest.raises(FacNotConfigured):
        await client.test({**CFG, "fac_api_key": ""})


def test_user_list_flags_missing_attributes_and_state():
    model = build(reference_events(), IDENTITIES, NOW, SINCE)
    users = [fac_user("user-a.ra"), fac_user("user-b.ra"), fac_user("user-e.ra"),
             fac_user("user-n.ra", last_name=""), fac_user("user-x.ot", dn="CN=x,OU=Other,DC=example")]
    rows = {r["username"]: r for r in user_list(users, IDENTITIES, model)}
    assert rows["user-n.ra"]["missing"] == ["Nachname"]
    assert rows["user-n.ra"]["status"] == "never"
    assert rows["user-b.ra"]["status"] == "problem"
    assert rows["user-a.ra"]["status"] == "active"
    assert rows["user-e.ra"]["status"] == "inactive"
    assert list(rows)[0] == "user-n.ra"                         # fehlende Attribute zuerst
    assert "user-x.ot" not in {r["username"] for r in user_list(users, IDENTITIES, model, "ou=webdrive")}
