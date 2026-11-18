"""Register, verify, login, logout, password reset/change, MFA, Google sign-in."""

from __future__ import annotations

import re
from datetime import UTC, datetime, timedelta

import pyotp
import pytest
from sqlalchemy import text

from tests.conftest import PASSWORD, count_rows

NEW_PASSWORD = "brand-New-passphrase-77"


def _token_from(outbox, subject_fragment: str) -> str:
    mail = next(m for m in reversed(outbox.outbox) if subject_fragment in m.subject)
    match = re.search(r"token=([A-Za-z0-9_\-]+)", mail.body)
    assert match
    return match.group(1)


async def _register(client, email="new@example.com", password=PASSWORD):
    return await client.post(
        "/v1/auth/register", json={"email": email, "password": password, "full_name": "New"}
    )


# ---------------------------------------------------------------- registration
async def test_register_verify_login(client, outbox, container):
    resp = await _register(client)
    assert resp.status_code == 202
    login = await client.post(
        "/v1/auth/login", json={"email": "new@example.com", "password": PASSWORD}
    )
    assert login.status_code == 403 and login.json()["code"] == "email_not_verified"

    token = _token_from(outbox, "Verify")
    assert (await client.post("/v1/auth/verify-email", json={"token": token})).status_code == 200
    assert (
        await client.post("/v1/auth/verify-email", json={"token": token})
    ).status_code == 400  # single use

    login = await client.post(
        "/v1/auth/login", json={"email": "NEW@example.com", "password": PASSWORD}
    )
    assert login.status_code == 200  # citext: case-insensitive email
    me = await client.get(
        "/v1/users/me", headers={"Authorization": f"Bearer {login.json()['access_token']}"}
    )
    assert me.json()["roles"] == ["user"] and me.json()["is_verified"] is True
    # nothing stored raw
    assert (
        await count_rows(
            container, "SELECT count(*) FROM one_time_tokens WHERE token_hash = :t", t=token
        )
        == 0
    )


async def test_duplicate_email_answered_like_new_signup(client, outbox, user):
    """Spec test 1 (hidden-existence variant): same response, warning email to the owner."""
    first = await _register(client, email="fresh@example.com")
    dup = await _register(client, email=user.email.upper())
    assert first.status_code == dup.status_code == 202
    assert first.json() == dup.json()
    assert any("tried to sign up" in m.subject and m.to == user.email for m in outbox.outbox)


@pytest.mark.parametrize("password", ["short", "password1234", "aaaaaaaaaaaaaaaa"])
async def test_register_rejects_weak_passwords(client, password):
    resp = await _register(client, password=password)
    assert resp.status_code == 422 and resp.json()["code"] == "weak_password"


async def test_register_is_rate_limited(client, container):
    container.settings.register_rate_limit = 2
    codes = [(await _register(client, email=f"r{i}@example.com")).status_code for i in range(3)]
    assert codes == [202, 202, 429]


async def test_expired_verification_token(client, outbox, container):
    await _register(client)
    token = _token_from(outbox, "Verify")
    async with container.engine.begin() as conn:
        await conn.execute(
            text("UPDATE one_time_tokens SET expires_at = now() - interval '1 second'")
        )
    assert (await client.post("/v1/auth/verify-email", json={"token": token})).status_code == 400


# ---------------------------------------------------------------- logout
async def test_logout_all_revokes_every_session(client, user):
    second = await client.post(
        "/v1/auth/login", json={"email": user.email, "password": user.password}
    )
    other_access = second.json()["access_token"]
    assert (await client.post("/v1/auth/logout-all", headers=user.headers)).status_code == 204
    for token in (user.access, other_access):
        resp = await client.get("/v1/users/me", headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 401
    for refresh in (user.refresh, second.json()["refresh_token"]):
        assert (
            await client.post("/v1/auth/refresh", json={"refresh_token": refresh})
        ).status_code == 401
    # a fresh login still works
    assert (
        await client.post("/v1/auth/login", json={"email": user.email, "password": user.password})
    ).status_code == 200


# ---------------------------------------------------------------- password reset (spec test 9)
async def test_password_reset_works_once_and_revokes_sessions(client, outbox, user):
    resp = await client.post("/v1/auth/password/forgot", json={"email": user.email})
    assert resp.status_code == 202
    token = _token_from(outbox, "Reset")
    ok = await client.post(
        "/v1/auth/password/reset", json={"token": token, "new_password": NEW_PASSWORD}
    )
    assert ok.status_code == 200
    again = await client.post(
        "/v1/auth/password/reset", json={"token": token, "new_password": "another-Pass-9999"}
    )
    assert again.status_code == 400

    assert (await client.get("/v1/users/me", headers=user.headers)).status_code == 401
    assert (
        await client.post("/v1/auth/refresh", json={"refresh_token": user.refresh})
    ).status_code == 401
    old = await client.post("/v1/auth/login", json={"email": user.email, "password": PASSWORD})
    assert old.status_code == 401
    new = await client.post("/v1/auth/login", json={"email": user.email, "password": NEW_PASSWORD})
    assert new.status_code == 200


async def test_password_reset_token_expires(client, outbox, container, user):
    await client.post("/v1/auth/password/forgot", json={"email": user.email})
    token = _token_from(outbox, "Reset")
    async with container.engine.begin() as conn:
        await conn.execute(
            text("UPDATE one_time_tokens SET expires_at = :t"),
            {"t": datetime.now(UTC) - timedelta(seconds=1)},
        )
    resp = await client.post(
        "/v1/auth/password/reset", json={"token": token, "new_password": NEW_PASSWORD}
    )
    assert resp.status_code == 400


async def test_new_reset_link_invalidates_older_one(client, outbox, user):
    await client.post("/v1/auth/password/forgot", json={"email": user.email})
    first = _token_from(outbox, "Reset")
    await client.post("/v1/auth/password/forgot", json={"email": user.email})
    resp = await client.post(
        "/v1/auth/password/reset", json={"token": first, "new_password": NEW_PASSWORD}
    )
    assert resp.status_code == 400


async def test_forgot_password_unknown_email_still_202(client, outbox):
    resp = await client.post("/v1/auth/password/forgot", json={"email": "ghost@example.com"})
    assert resp.status_code == 202
    assert outbox.outbox == []


async def test_reset_unlocks_account(client, container, outbox, make_user):
    container.settings.login_rate_limit = 100
    u = await make_user(login=False)
    for _ in range(5):
        await client.post(
            "/v1/auth/login", json={"email": u.email, "password": "wrong-password-xyz"}
        )
    await client.post("/v1/auth/password/forgot", json={"email": u.email})
    await client.post(
        "/v1/auth/password/reset",
        json={"token": _token_from(outbox, "Reset"), "new_password": NEW_PASSWORD},
    )
    assert (
        await client.post("/v1/auth/login", json={"email": u.email, "password": NEW_PASSWORD})
    ).status_code == 200


# ---------------------------------------------------------------- password change
async def test_change_password(client, user):
    bad = await client.post(
        "/v1/auth/password/change",
        headers=user.headers,
        json={"current_password": "nope-nope-nope", "new_password": NEW_PASSWORD},
    )
    assert bad.status_code == 400
    same = await client.post(
        "/v1/auth/password/change",
        headers=user.headers,
        json={"current_password": PASSWORD, "new_password": PASSWORD},
    )
    assert same.status_code == 422
    ok = await client.post(
        "/v1/auth/password/change",
        headers=user.headers,
        json={"current_password": PASSWORD, "new_password": NEW_PASSWORD},
    )
    assert ok.status_code == 200
    new_headers = {"Authorization": f"Bearer {ok.json()['access_token']}"}
    assert (await client.get("/v1/users/me", headers=new_headers)).status_code == 200
    assert (
        await client.get("/v1/users/me", headers=user.headers)
    ).status_code == 401  # old session gone


async def test_bcrypt_hash_upgraded_on_login(client, container, make_user):
    import bcrypt

    u = await make_user(login=False)
    legacy = bcrypt.hashpw(PASSWORD.encode(), bcrypt.gensalt(rounds=4)).decode()
    async with container.engine.begin() as conn:
        await conn.execute(
            text("UPDATE users SET password_hash = :h WHERE id = :id"), {"h": legacy, "id": u.id}
        )
    assert (
        await client.post("/v1/auth/login", json={"email": u.email, "password": PASSWORD})
    ).status_code == 200
    async with container.engine.connect() as conn:
        stored = (
            await conn.execute(text("SELECT password_hash FROM users WHERE id = :id"), {"id": u.id})
        ).scalar_one()
    assert stored.startswith("$argon2id$")


# ---------------------------------------------------------------- profile
async def test_update_and_delete_me(client, user):
    resp = await client.patch(
        "/v1/users/me", headers=user.headers, json={"full_name": "  Ada Lovelace  "}
    )
    assert resp.status_code == 200 and resp.json()["full_name"] == "Ada Lovelace"
    assert (await client.delete("/v1/users/me", headers=user.headers)).status_code == 204
    login = await client.post(
        "/v1/auth/login", json={"email": user.email, "password": user.password}
    )
    assert login.status_code == 401


# ---------------------------------------------------------------- MFA (stretch)
async def test_mfa_enroll_and_two_step_login(client, user, container):
    enroll = await client.post("/v1/auth/mfa/enroll", headers=user.headers)
    assert enroll.status_code == 200
    totp = pyotp.TOTP(enroll.json()["secret"])
    assert (
        await client.post("/v1/auth/mfa/verify", headers=user.headers, json={"code": "000000"})
    ).status_code == 400
    assert (
        await client.post("/v1/auth/mfa/verify", headers=user.headers, json={"code": totp.now()})
    ).status_code == 200
    assert (await client.post("/v1/auth/mfa/enroll", headers=user.headers)).status_code == 409

    step1 = await client.post(
        "/v1/auth/login", json={"email": user.email, "password": user.password}
    )
    assert step1.status_code == 200 and step1.json()["mfa_required"] is True
    mfa_token = step1.json()["mfa_token"]
    # the MFA token is not an access token
    assert (
        await client.get("/v1/users/me", headers={"Authorization": f"Bearer {mfa_token}"})
    ).status_code == 401

    await container.redis.flushdb()  # forget the code used during enrollment (replay guard)
    code = totp.now()
    step2 = await client.post("/v1/auth/login/mfa", json={"mfa_token": mfa_token, "code": code})
    assert step2.status_code == 200 and "access_token" in step2.json()
    replay = await client.post("/v1/auth/login/mfa", json={"mfa_token": mfa_token, "code": code})
    assert replay.status_code == 401  # each code works once

    headers = {"Authorization": f"Bearer {step2.json()['access_token']}"}
    assert (
        await client.post("/v1/auth/login/mfa", json={"mfa_token": "x" * 40, "code": "123456"})
    ).status_code == 401
    await container.redis.flushdb()
    resp = await client.post("/v1/auth/mfa/disable", headers=headers, json={"code": totp.now()})
    assert resp.status_code == 200
    assert (
        await client.post("/v1/auth/mfa/disable", headers=headers, json={"code": totp.now()})
    ).status_code == 409


async def test_mfa_verify_without_enroll(client, user):
    resp = await client.post("/v1/auth/mfa/verify", headers=user.headers, json={"code": "123456"})
    assert resp.status_code == 409


# ---------------------------------------------------------------- Google sign-in (stretch)
async def test_google_disabled_by_default(client):
    assert (await client.get("/v1/auth/oauth/google/authorize")).status_code == 404


async def test_google_pkce_flow(client, container, monkeypatch):
    from urllib.parse import parse_qs, urlparse

    from app.services.oauth_service import GoogleOAuthService

    container.settings.google_client_id = "client-123"
    container.settings.google_client_secret = "secret"  # type: ignore[assignment]
    from pydantic import SecretStr

    container.settings.google_client_secret = SecretStr("secret")
    container.settings.google_redirect_uri = "http://testserver/v1/auth/oauth/google/callback"

    start = await client.get("/v1/auth/oauth/google/authorize")
    assert start.status_code == 200
    q = parse_qs(urlparse(start.json()["authorization_url"]).query)
    assert q["code_challenge_method"] == ["S256"] and len(q["code_challenge"][0]) == 43
    state = start.json()["state"]

    async def fake_exchange(self, code, verifier):
        assert code == "auth-code" and len(verifier) >= 43
        return {"id_token": "stub"}

    def fake_verify(self, id_token, nonce):
        assert nonce == q["nonce"][0]
        return {"email": "googler@example.com", "email_verified": True, "name": "G User"}

    monkeypatch.setattr(GoogleOAuthService, "_exchange_code", fake_exchange)
    monkeypatch.setattr(GoogleOAuthService, "_verify_id_token", fake_verify)
    done = await client.get(
        "/v1/auth/oauth/google/callback", params={"code": "auth-code", "state": state}
    )
    assert done.status_code == 200, done.text
    me = await client.get(
        "/v1/users/me", headers={"Authorization": f"Bearer {done.json()['access_token']}"}
    )
    assert me.json()["email"] == "googler@example.com" and me.json()["is_verified"]
    # state is single use
    again = await client.get(
        "/v1/auth/oauth/google/callback", params={"code": "auth-code", "state": state}
    )
    assert again.status_code == 400
    # the OAuth-only account has no usable password
    pw = await client.post(
        "/v1/auth/login", json={"email": "googler@example.com", "password": "anything-long-1"}
    )
    assert pw.status_code == 401
    redirect = await client.get("/v1/auth/oauth/google/authorize", params={"redirect": True})
    assert redirect.status_code == 302
