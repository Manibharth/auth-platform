"""Spec test 8 and the identification-failure controls."""

from __future__ import annotations

from tests.conftest import PASSWORD


async def _login(client, email, password):
    return await client.post("/v1/auth/login", json={"email": email, "password": password})


async def test_lockout_after_failures_refuses_correct_password(client, container, make_user):
    container.settings.login_rate_limit = 100  # isolate lockout from the rate limit
    u = await make_user(login=False)
    for _ in range(6):
        resp = await _login(client, u.email, "wrong-password-xyz")
        assert resp.status_code == 401
        assert resp.json()["code"] == "invalid_credentials"
    locked = await _login(client, u.email, PASSWORD)
    assert locked.status_code == 401
    assert locked.json()["code"] == "invalid_credentials"  # generic, no "locked" hint


async def test_lock_expires_and_counter_resets(client, container, make_user):
    container.settings.login_rate_limit = 100
    container.settings.lockout_base_seconds = 0  # lock is immediately over
    u = await make_user(login=False)
    for _ in range(5):
        await _login(client, u.email, "wrong-password-xyz")
    assert (await _login(client, u.email, PASSWORD)).status_code == 200


async def test_unknown_email_and_wrong_password_look_identical(client, user):
    a = await _login(client, user.email, "wrong-password-xyz")
    b = await _login(client, "nobody-here@example.com", "wrong-password-xyz")
    assert a.status_code == b.status_code == 401
    strip = lambda r: {k: v for k, v in r.json().items() if k != "request_id"}  # noqa: E731
    assert strip(a) == strip(b)


async def test_login_rate_limit_returns_429(client, container, make_user):
    user = await make_user(login=False)
    container.settings.login_rate_limit = 3
    codes = [(await _login(client, user.email, "wrong-password-xyz")).status_code for _ in range(5)]
    assert codes[:3] == [401, 401, 401]
    assert codes[3:] == [429, 429]
    last = await _login(client, user.email, "wrong-password-xyz")
    assert int(last.headers["Retry-After"]) >= 1


async def test_ip_failure_limit_blocks_credential_stuffing(client, container):
    container.settings.login_rate_limit = 1000
    container.settings.login_ip_failure_limit = 4
    codes = [
        (await _login(client, f"victim{i}@example.com", "wrong-password-xyz")).status_code
        for i in range(6)
    ]
    assert codes[:4] == [401] * 4 and codes[4:] == [429, 429]


async def test_login_fails_closed_when_redis_down(client, container, user, monkeypatch):
    from redis.exceptions import ConnectionError as RedisConnectionError

    async def boom(*_a, **_k):
        raise RedisConnectionError("down")

    monkeypatch.setattr(container.limiter, "hit", boom)
    resp = await _login(client, user.email, PASSWORD)
    assert resp.status_code == 503
    # ...but authenticated reads keep working (global limiter fails open)
    assert (await client.get("/v1/users/me", headers=user.headers)).status_code == 200
