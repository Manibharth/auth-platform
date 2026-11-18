"""Security headers, CORS, injection payloads, append-only audit log."""

from __future__ import annotations

import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError

from app.main import create_app

PATHS = [
    "/healthz",
    "/v1/users/me",
    "/v1/projects/not-a-uuid",
    "/nope",
    "/.well-known/jwks.json",
    "/docs",
]


@pytest.mark.parametrize("path", PATHS)
async def test_security_headers_on_every_response(client, path):
    resp = await client.get(path)
    assert resp.headers["X-Content-Type-Options"] == "nosniff"
    assert resp.headers["Referrer-Policy"] == "no-referrer"
    assert "frame-ancestors 'none'" in resp.headers["Content-Security-Policy"]
    assert resp.headers["X-Request-ID"]


async def test_hsts_in_production_like_envs(settings, container):
    from httpx import ASGITransport, AsyncClient

    s = settings.model_copy(update={"environment": "staging"})
    app = create_app(s, container)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
        resp = await c.get("/healthz")
    assert resp.headers["Strict-Transport-Security"].startswith("max-age=")


async def test_request_id_is_propagated_or_generated(client):
    resp = await client.get("/healthz", headers={"X-Request-ID": "trace-abc-12345"})
    assert resp.headers["X-Request-ID"] == "trace-abc-12345"
    bad = await client.get("/healthz", headers={"X-Request-ID": "<script>"})
    assert bad.headers["X-Request-ID"] != "<script>"


async def test_cors_allow_list_never_wildcard(settings, container):
    from httpx import ASGITransport, AsyncClient

    s = settings.model_copy(update={"cors_origins": ["https://app.example"]})
    app = create_app(s, container)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
        ok = await c.options(
            "/v1/users/me",
            headers={"Origin": "https://app.example", "Access-Control-Request-Method": "GET"},
        )
        evil = await c.options(
            "/v1/users/me",
            headers={"Origin": "https://evil.example", "Access-Control-Request-Method": "GET"},
        )
    assert ok.headers["access-control-allow-origin"] == "https://app.example"
    assert ok.headers["access-control-allow-credentials"] == "true"
    assert "access-control-allow-origin" not in evil.headers


SQLI = [
    "' OR '1'='1",
    "'; DROP TABLE users; --",
    '" OR 1=1 --',
    "%' OR email LIKE '%",
    "\\x00",
    "😀" * 50,
]


@pytest.mark.parametrize("payload", SQLI)
async def test_sql_injection_payloads_are_inert(client, admin, payload):
    calls = [
        client.post("/v1/auth/login", json={"email": payload, "password": payload}),
        client.post("/v1/auth/login", json={"email": "a@example.com", "password": payload}),
        client.post(
            "/v1/projects", json={"name": payload, "description": payload}, headers=admin.headers
        ),
        client.get(
            "/v1/admin/users", params={"q": payload, "role": payload}, headers=admin.headers
        ),
        client.get("/v1/admin/audit-log", params={"action": payload}, headers=admin.headers),
        client.get("/v1/projects", params={"cursor": payload}, headers=admin.headers),
        client.post("/v1/auth/verify-email", json={"token": payload}),
    ]
    for coro in calls:
        resp = await coro
        assert resp.status_code < 500, resp.text
    # users table still there and the injected search matched nothing extra
    resp = await client.get("/v1/admin/users", params={"q": "%"}, headers=admin.headers)
    assert resp.status_code == 200
    assert all("%" in u["email"] for u in resp.json()["items"])


async def test_validation_errors_never_echo_passwords(client):
    resp = await client.post(
        "/v1/auth/login", json={"email": "not-an-email", "password": "s3cret-value"}
    )
    assert resp.status_code == 422
    assert "s3cret-value" not in resp.text
    assert resp.headers["content-type"].startswith("application/problem+json")


async def test_unknown_fields_rejected(client):
    resp = await client.post(
        "/v1/auth/register",
        json={"email": "x@example.com", "password": "correct-Horse-battery-42", "is_admin": True},
    )
    assert resp.status_code == 422


async def test_audit_log_is_append_only_in_the_database(client, container, user):
    async with container.engine.connect() as conn:
        count = (await conn.execute(text("SELECT count(*) FROM audit_log"))).scalar_one()
    assert count >= 1
    for stmt in ("UPDATE audit_log SET action = 'x'", "DELETE FROM audit_log"):
        with pytest.raises(DBAPIError, match="append-only"):
            async with container.engine.begin() as conn:
                await conn.execute(text(stmt))
