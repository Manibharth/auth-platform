"""Projects CRUD, cursor pagination, idempotent creates (spec test 10)."""

from __future__ import annotations

import asyncio

from tests.conftest import count_rows


async def test_crud(client, user):
    created = await client.post(
        "/v1/projects", json={"name": "Alpha", "description": "first"}, headers=user.headers
    )
    assert created.status_code == 201
    pid = created.json()["id"]
    assert created.headers["Location"] == f"/v1/projects/{pid}"
    assert (await client.get(f"/v1/projects/{pid}", headers=user.headers)).json()["name"] == "Alpha"
    patched = await client.patch(
        f"/v1/projects/{pid}", json={"description": "changed"}, headers=user.headers
    )
    assert patched.json()["description"] == "changed" and patched.json()["name"] == "Alpha"
    assert (
        await client.patch(f"/v1/projects/{pid}", json={"name": None}, headers=user.headers)
    ).status_code == 422
    assert (await client.delete(f"/v1/projects/{pid}", headers=user.headers)).status_code == 204
    assert (await client.get(f"/v1/projects/{pid}", headers=user.headers)).status_code == 404


async def test_cursor_pagination_is_stable_under_writes(client, user):
    for i in range(5):
        await client.post("/v1/projects", json={"name": f"p{i}"}, headers=user.headers)
    page1 = (await client.get("/v1/projects", params={"limit": 2}, headers=user.headers)).json()
    assert [p["name"] for p in page1["items"]] == ["p4", "p3"]
    # a new row arrives between page fetches; it must not shift the next page
    await client.post("/v1/projects", json={"name": "late"}, headers=user.headers)
    page2 = (
        await client.get(
            "/v1/projects",
            params={"limit": 2, "cursor": page1["next_cursor"]},
            headers=user.headers,
        )
    ).json()
    assert [p["name"] for p in page2["items"]] == ["p2", "p1"]
    page3 = (
        await client.get(
            "/v1/projects",
            params={"limit": 2, "cursor": page2["next_cursor"]},
            headers=user.headers,
        )
    ).json()
    assert [p["name"] for p in page3["items"]] == ["p0"] and page3["next_cursor"] is None


async def test_bad_cursor_and_limit(client, user):
    resp = await client.get("/v1/projects", params={"cursor": "garbage!!"}, headers=user.headers)
    assert resp.status_code == 400 and resp.json()["code"] == "invalid_cursor"
    assert (
        await client.get("/v1/projects", params={"limit": 1000}, headers=user.headers)
    ).status_code == 422


async def test_idempotent_replay_returns_first_response(client, container, user):
    headers = {**user.headers, "Idempotency-Key": "create-alpha-1"}
    first = await client.post("/v1/projects", json={"name": "Alpha"}, headers=headers)
    second = await client.post("/v1/projects", json={"name": "Alpha"}, headers=headers)
    assert first.status_code == second.status_code == 201
    assert first.json() == second.json()
    assert (
        first.headers["Idempotent-Replayed"] == "false"
        and second.headers["Idempotent-Replayed"] == "true"
    )
    assert await count_rows(container, "SELECT count(*) FROM projects") == 1


async def test_idempotency_key_with_different_body(client, user):
    headers = {**user.headers, "Idempotency-Key": "k-1"}
    await client.post("/v1/projects", json={"name": "Alpha"}, headers=headers)
    resp = await client.post("/v1/projects", json={"name": "Beta"}, headers=headers)
    assert resp.status_code == 422 and resp.json()["code"] == "idempotency_key_mismatch"


async def test_idempotency_keys_are_per_user(client, make_user, container):
    a, b = await make_user(), await make_user()
    for u in (a, b):
        r = await client.post(
            "/v1/projects",
            json={"name": "same"},
            headers={**u.headers, "Idempotency-Key": "shared"},
        )
        assert r.status_code == 201
    assert await count_rows(container, "SELECT count(*) FROM projects") == 2


async def test_concurrent_idempotent_creates_make_one_row(client, container, user):
    headers = {**user.headers, "Idempotency-Key": "race-1"}
    results = await asyncio.gather(
        *[client.post("/v1/projects", json={"name": "race"}, headers=headers) for _ in range(5)]
    )
    assert {r.status_code for r in results} == {201}
    assert len({r.json()["id"] for r in results}) == 1
    assert await count_rows(container, "SELECT count(*) FROM projects") == 1


async def test_expired_idempotency_key_allows_new_create(client, container, user):
    from sqlalchemy import text

    headers = {**user.headers, "Idempotency-Key": "old"}
    await client.post("/v1/projects", json={"name": "one"}, headers=headers)
    async with container.engine.begin() as conn:
        await conn.execute(
            text("UPDATE idempotency_keys SET created_at = now() - interval '25 hours'")
        )
    again = await client.post("/v1/projects", json={"name": "two"}, headers=headers)
    assert again.status_code == 201 and again.headers["Idempotent-Replayed"] == "false"
    assert await count_rows(container, "SELECT count(*) FROM projects") == 2


async def test_invalid_idempotency_key_header(client, user):
    resp = await client.post(
        "/v1/projects", json={"name": "x"}, headers={**user.headers, "Idempotency-Key": "bad key!"}
    )
    assert resp.status_code == 422
