"""Spec tests 3 and 4: refresh rotation, reuse detection and the row lock."""

from __future__ import annotations

import asyncio

from tests.conftest import count_rows


async def test_rotation_issues_new_pair(client, user):
    resp = await client.post("/v1/auth/refresh", json={"refresh_token": user.refresh})
    assert resp.status_code == 200
    body = resp.json()
    assert body["refresh_token"] != user.refresh and body["access_token"] != user.access
    me = await client.get(
        "/v1/users/me", headers={"Authorization": f"Bearer {body['access_token']}"}
    )
    assert me.status_code == 200


async def test_reuse_revokes_whole_family(client, container, user):
    first = await client.post("/v1/auth/refresh", json={"refresh_token": user.refresh})
    newest = first.json()["refresh_token"]
    second = await client.post("/v1/auth/refresh", json={"refresh_token": newest})
    newest = second.json()["refresh_token"]

    # The attacker replays the original token.
    replay = await client.post("/v1/auth/refresh", json={"refresh_token": user.refresh})
    assert replay.status_code == 401
    assert replay.json()["code"] == "refresh_token_reused"

    # The newest token in the chain stops working too.
    after = await client.post("/v1/auth/refresh", json={"refresh_token": newest})
    assert after.status_code == 401
    assert (
        await count_rows(
            container,
            "SELECT count(*) FROM refresh_tokens WHERE user_id = :u AND revoked_at IS NULL",
            u=user.id,
        )
        == 0
    )
    assert (
        await count_rows(
            container, "SELECT count(*) FROM audit_log WHERE action = 'auth.refresh_reuse_detected'"
        )
        == 1
    )


async def test_reuse_does_not_touch_other_sessions(client, make_user):
    u = await make_user()
    other = await client.post("/v1/auth/login", json={"email": u.email, "password": u.password})
    other_refresh = other.json()["refresh_token"]
    await client.post("/v1/auth/refresh", json={"refresh_token": u.refresh})
    await client.post("/v1/auth/refresh", json={"refresh_token": u.refresh})  # reuse
    ok = await client.post("/v1/auth/refresh", json={"refresh_token": other_refresh})
    assert ok.status_code == 200


async def test_parallel_refresh_exactly_one_succeeds(client, user):
    results = await asyncio.gather(
        *[client.post("/v1/auth/refresh", json={"refresh_token": user.refresh}) for _ in range(5)]
    )
    codes = sorted(r.status_code for r in results)
    assert codes.count(200) == 1, codes
    assert all(c == 401 for c in codes if c != 200)


async def test_unknown_and_missing_refresh_token(client):
    assert (
        await client.post("/v1/auth/refresh", json={"refresh_token": "x" * 43})
    ).status_code == 401
    assert (await client.post("/v1/auth/refresh")).status_code == 401


async def test_refresh_via_cookie(client, user):
    client.cookies.set("refresh_token", user.refresh)
    resp = await client.post("/v1/auth/refresh")
    assert resp.status_code == 200
    assert "httponly" in resp.headers["set-cookie"].lower()
    assert "samesite=strict" in resp.headers["set-cookie"].lower()
    client.cookies.clear()


async def test_disabled_user_cannot_refresh(client, admin, user):
    await client.post(f"/v1/admin/users/{user.id}/disable", headers=admin.headers)
    assert (
        await client.post("/v1/auth/refresh", json={"refresh_token": user.refresh})
    ).status_code == 401
