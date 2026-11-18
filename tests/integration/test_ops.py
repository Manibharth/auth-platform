"""Health, readiness, metrics, JWKS, error format."""

from __future__ import annotations


async def test_healthz(client):
    resp = await client.get("/healthz")
    assert resp.status_code == 200 and resp.json() == {"status": "ok"}


async def test_readyz_ok(client):
    resp = await client.get("/readyz")
    assert resp.status_code == 200 and resp.json()["checks"] == {"database": "ok", "redis": "ok"}


async def test_readyz_reports_redis_down(client, container, monkeypatch):
    async def boom():
        raise ConnectionError("down")

    monkeypatch.setattr(container.redis, "ping", boom)
    resp = await client.get("/readyz")
    assert resp.status_code == 503 and resp.json()["checks"]["redis"] == "unavailable"


async def test_metrics_allowed_from_private_network(client, user):
    await client.get("/v1/users/me", headers=user.headers)
    resp = await client.get("/metrics")
    assert resp.status_code == 200
    body = resp.text
    assert 'http_requests_total{method="GET",route="/v1/users/me",status="200"}' in body
    assert "auth_login_success_total" in body and "db_pool_connections_in_use" in body


async def test_metrics_hidden_from_public_networks(client, container):
    container.settings.metrics_allowed_cidrs = ["10.0.0.0/8"]
    assert (await client.get("/metrics")).status_code == 404


async def test_metrics_bearer_token(client, container):
    from pydantic import SecretStr

    container.settings.metrics_bearer_token = SecretStr("scrape-me")
    assert (await client.get("/metrics")).status_code == 404
    ok = await client.get("/metrics", headers={"Authorization": "Bearer scrape-me"})
    assert ok.status_code == 200


async def test_jwks(client, container):
    resp = await client.get("/.well-known/jwks.json")
    assert resp.status_code == 200
    assert resp.json()["keys"][0]["kid"] == container.keyring.kid
    assert "max-age" in resp.headers["Cache-Control"]


async def test_problem_details_for_unknown_route_and_method(client):
    resp = await client.get("/does-not-exist")
    assert resp.status_code == 404
    body = resp.json()
    assert resp.headers["content-type"].startswith("application/problem+json")
    assert (
        body["code"] == "not_found"
        and body["status"] == 404
        and body["type"].endswith("/not_found")
    )
    assert body["request_id"] == resp.headers["X-Request-ID"]
    assert (await client.delete("/healthz")).status_code == 405


async def test_global_rate_limit(client, container):
    container.settings.global_rate_limit = 3
    codes = [(await client.get("/.well-known/jwks.json")).status_code for _ in range(4)]
    assert codes == [200, 200, 200, 429]
    assert (await client.get("/healthz")).status_code == 200  # exempt


async def test_unhandled_error_is_problem_json(app, monkeypatch, user):
    from httpx import ASGITransport, AsyncClient

    from app.services.user_service import UserService

    async def explode(self, user_id):
        raise RuntimeError("boom secret detail")

    monkeypatch.setattr(UserService, "get_active", explode)
    transport = ASGITransport(app=app, raise_app_exceptions=False)
    async with AsyncClient(transport=transport, base_url="http://testserver") as c:
        resp = await c.get("/v1/users/me", headers=user.headers)
    assert resp.status_code == 500 and resp.json()["code"] == "internal_error"
    assert "boom" not in resp.text
