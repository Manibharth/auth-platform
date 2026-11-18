"""Admin endpoints and the audit log (spec test 11)."""

from __future__ import annotations

import uuid

from tests.conftest import count_rows


async def test_role_change_writes_exactly_one_audit_row(client, container, admin, user):
    resp = await client.patch(
        f"/v1/admin/users/{user.id}/roles",
        json={"roles": ["user", "auditor"]},
        headers=admin.headers,
    )
    assert resp.status_code == 200 and resp.json()["roles"] == ["auditor", "user"]
    log = await client.get(
        "/v1/admin/audit-log", params={"action": "user.roles_changed"}, headers=admin.headers
    )
    items = log.json()["items"]
    assert len(items) == 1
    entry = items[0]
    assert entry["actor_id"] == str(admin.id) and entry["target_id"] == str(user.id)
    assert entry["metadata"] == {"old": ["user"], "new": ["auditor", "user"]}
    # setting the same roles again is a no-op, no extra audit row
    await client.patch(
        f"/v1/admin/users/{user.id}/roles",
        json={"roles": ["auditor", "user"]},
        headers=admin.headers,
    )
    assert (
        await count_rows(
            container, "SELECT count(*) FROM audit_log WHERE action='user.roles_changed'"
        )
        == 1
    )


async def test_role_change_validation(client, admin, user):
    unknown = await client.patch(
        f"/v1/admin/users/{user.id}/roles", json={"roles": ["god"]}, headers=admin.headers
    )
    assert unknown.status_code == 422 and unknown.json()["code"] == "unknown_role"
    missing = await client.patch(
        f"/v1/admin/users/{uuid.uuid4()}/roles", json={"roles": ["user"]}, headers=admin.headers
    )
    assert missing.status_code == 404
    self_demote = await client.patch(
        f"/v1/admin/users/{admin.id}/roles", json={"roles": ["user"]}, headers=admin.headers
    )
    assert self_demote.status_code == 409


async def test_disable_revokes_sessions(client, admin, user):
    resp = await client.post(f"/v1/admin/users/{user.id}/disable", headers=admin.headers)
    assert resp.status_code == 200 and resp.json()["is_active"] is False
    assert (await client.get("/v1/users/me", headers=user.headers)).status_code == 401
    login = await client.post(
        "/v1/auth/login", json={"email": user.email, "password": user.password}
    )
    assert login.status_code == 403 and login.json()["code"] == "account_disabled"
    assert (
        await client.post(f"/v1/admin/users/{admin.id}/disable", headers=admin.headers)
    ).status_code == 409
    assert (
        await client.post(f"/v1/admin/users/{uuid.uuid4()}/disable", headers=admin.headers)
    ).status_code == 404


async def test_search_users_and_paginate(client, admin, make_user):
    for i in range(3):
        await make_user(email=f"findme-{i}@corp.example", login=False)
    resp = await client.get(
        "/v1/admin/users", params={"q": "findme", "limit": 2}, headers=admin.headers
    )
    body = resp.json()
    assert len(body["items"]) == 2 and body["next_cursor"]
    rest = await client.get(
        "/v1/admin/users",
        params={"q": "findme", "limit": 2, "cursor": body["next_cursor"]},
        headers=admin.headers,
    )
    assert len(rest.json()["items"]) == 1
    by_role = await client.get(
        "/v1/admin/users", params={"role": "admin", "is_active": True}, headers=admin.headers
    )
    assert [u["email"] for u in by_role.json()["items"]] == [admin.email]
    one = await client.get(f"/v1/admin/users/{admin.id}", headers=admin.headers)
    assert one.json()["email"] == admin.email
    assert (
        await client.get(f"/v1/admin/users/{uuid.uuid4()}", headers=admin.headers)
    ).status_code == 404


async def test_audit_log_filters(client, auditor, user):
    await client.post(
        "/v1/auth/login", json={"email": user.email, "password": "wrong-password-xyz"}
    )
    resp = await client.get(
        "/v1/admin/audit-log", params={"actor_id": str(user.id)}, headers=auditor.headers
    )
    actions = {e["action"] for e in resp.json()["items"]}
    assert {"auth.login", "auth.login_failed"} <= actions
    assert all(e["ip"] for e in resp.json()["items"])
    window = await client.get(
        "/v1/admin/audit-log",
        params={"from": "2000-01-01T00:00:00Z", "to": "2000-01-02T00:00:00Z"},
        headers=auditor.headers,
    )
    assert window.json()["items"] == []
    paged = await client.get("/v1/admin/audit-log", params={"limit": 1}, headers=auditor.headers)
    assert len(paged.json()["items"]) == 1 and paged.json()["next_cursor"]
    nxt = await client.get(
        "/v1/admin/audit-log",
        params={"limit": 1, "cursor": paged.json()["next_cursor"]},
        headers=auditor.headers,
    )
    assert nxt.json()["items"][0]["id"] != paged.json()["items"][0]["id"]
