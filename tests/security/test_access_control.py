"""Every endpoint gets an access test: one allowed caller, one denied caller.

Spec tests 6 and 7: a normal user on admin routes gets 403, anonymous gets 401,
and user B gets 404 on everything of user A's.
"""

from __future__ import annotations

import uuid

import pytest

# (method, path, json body, allowed role, denied role -> expected status)
# "{project}" / "{target}" are filled in per test.
PROTECTED = [
    ("POST", "/v1/auth/logout", None, "user", None),
    ("POST", "/v1/auth/logout-all", None, "user", None),
    (
        "POST",
        "/v1/auth/password/change",
        {"current_password": "correct-Horse-battery-42", "new_password": "brand-New-passphrase-77"},
        "user",
        None,
    ),
    ("POST", "/v1/auth/mfa/enroll", None, "user", None),
    ("GET", "/v1/users/me", None, "user", None),
    ("PATCH", "/v1/users/me", {"full_name": "New Name"}, "user", None),
    ("DELETE", "/v1/users/me", None, "user", None),
    ("POST", "/v1/projects", {"name": "p"}, "user", "auditor"),
    ("GET", "/v1/projects", None, "user", "nobody"),
    ("GET", "/v1/projects/{project}", None, "owner", "user"),
    ("PATCH", "/v1/projects/{project}", {"name": "x"}, "owner", "user"),
    ("DELETE", "/v1/projects/{project}", None, "owner", "user"),
    ("GET", "/v1/admin/users", None, "admin", "user"),
    ("GET", "/v1/admin/users/{target}", None, "admin", "user"),
    ("PATCH", "/v1/admin/users/{target}/roles", {"roles": ["user", "auditor"]}, "admin", "user"),
    ("POST", "/v1/admin/users/{target}/disable", None, "admin", "user"),
    ("GET", "/v1/admin/audit-log", None, "auditor", "user"),
]

DENIED_STATUS = {"user": 403, "auditor": 403, "nobody": 403}


@pytest.fixture
async def world(client, make_user):
    users = {
        "user": await make_user(["user"]),
        "owner": await make_user(["user"]),
        "admin": await make_user(["admin"]),
        "auditor": await make_user(["auditor"]),
        "nobody": await make_user([]),
        "target": await make_user(["user"]),
    }
    resp = await client.post("/v1/projects", json={"name": "owned"}, headers=users["owner"].headers)
    assert resp.status_code == 201
    return users, resp.json()["id"]


def _fill(path: str, users, project_id) -> str:
    return path.format(project=project_id, target=users["target"].id)


@pytest.mark.parametrize(
    ("method", "path", "body", "allowed", "denied"),
    PROTECTED,
    ids=[f"{m} {p}" for m, p, *_ in PROTECTED],
)
async def test_anonymous_gets_401(client, world, method, path, body, allowed, denied):
    users, project_id = world
    resp = await client.request(method, _fill(path, users, project_id), json=body)
    assert resp.status_code == 401
    assert resp.json()["code"] == "not_authenticated"


@pytest.mark.parametrize(
    ("method", "path", "body", "allowed", "denied"),
    PROTECTED,
    ids=[f"{m} {p}" for m, p, *_ in PROTECTED],
)
async def test_allowed_role_succeeds(client, world, method, path, body, allowed, denied):
    users, project_id = world
    resp = await client.request(
        method, _fill(path, users, project_id), json=body, headers=users[allowed].headers
    )
    assert resp.status_code < 300, resp.text


DENIED = [row for row in PROTECTED if row[4] is not None]


@pytest.mark.parametrize(
    ("method", "path", "body", "allowed", "denied"), DENIED, ids=[f"{m} {p}" for m, p, *_ in DENIED]
)
async def test_denied_role_rejected(client, world, method, path, body, allowed, denied):
    users, project_id = world
    resp = await client.request(
        method, _fill(path, users, project_id), json=body, headers=users[denied].headers
    )
    expected = 404 if "{project}" in path else DENIED_STATUS[denied]
    assert resp.status_code == expected, resp.text


async def test_user_b_gets_404_on_user_a_project(client, make_user):
    a, b = await make_user(), await make_user()
    pid = (await client.post("/v1/projects", json={"name": "A's"}, headers=a.headers)).json()["id"]
    for method, body in (("GET", None), ("PATCH", {"name": "pwned"}), ("DELETE", None)):
        resp = await client.request(method, f"/v1/projects/{pid}", json=body, headers=b.headers)
        assert resp.status_code == 404
        assert resp.json()["code"] == "not_found"
    # identical to a project that never existed
    ghost = await client.get(f"/v1/projects/{uuid.uuid4()}", headers=b.headers)
    assert ghost.status_code == 404
    # and A's project is untouched
    mine = await client.get(f"/v1/projects/{pid}", headers=a.headers)
    assert mine.json()["name"] == "A's"
    # B's list never contains it
    assert (await client.get("/v1/projects", headers=b.headers)).json()["items"] == []


async def test_admin_can_manage_any_project(client, make_user):
    a, admin = await make_user(), await make_user(["admin"])
    pid = (await client.post("/v1/projects", json={"name": "A's"}, headers=a.headers)).json()["id"]
    assert (await client.get(f"/v1/projects/{pid}", headers=admin.headers)).status_code == 200
    assert (await client.delete(f"/v1/projects/{pid}", headers=admin.headers)).status_code == 204


async def test_demoted_admin_loses_admin_access_immediately(client, make_user):
    boss, other = await make_user(["admin"]), await make_user(["admin"])
    assert (await client.get("/v1/admin/users", headers=other.headers)).status_code == 200
    resp = await client.patch(
        f"/v1/admin/users/{other.id}/roles", json={"roles": ["user"]}, headers=boss.headers
    )
    assert resp.status_code == 200
    # other's token still says "admin", but admin routes re-read roles from the DB
    assert (await client.get("/v1/admin/users", headers=other.headers)).status_code == 403


async def test_demo_account_is_read_only(client, container, make_user):
    container.settings.demo_read_only = True
    container.settings.demo_email = "demo@example.com"
    demo = await make_user(["user"], email="demo@example.com")
    assert (await client.get("/v1/projects", headers=demo.headers)).status_code == 200
    resp = await client.post("/v1/projects", json={"name": "x"}, headers=demo.headers)
    assert resp.status_code == 403 and resp.json()["code"] == "demo_read_only"
    assert (await client.delete("/v1/users/me", headers=demo.headers)).status_code == 403
