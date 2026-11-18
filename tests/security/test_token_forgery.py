"""Spec test 2 and 5: forged, expired, tampered or revoked tokens return 401."""

from __future__ import annotations

import base64
import json
import time
import uuid

import jwt
import pytest
from cryptography.hazmat.primitives import serialization

from app.core.security import generate_private_key_pem


def _b64(data: dict) -> str:
    return base64.urlsafe_b64encode(json.dumps(data).encode()).rstrip(b"=").decode()


def _claims(container, user_id, **overrides):
    now = int(time.time())
    claims = {
        "iss": container.settings.jwt_issuer,
        "aud": container.settings.jwt_audience,
        "sub": str(user_id),
        "iat": now,
        "nbf": now,
        "exp": now + 600,
        "jti": uuid.uuid4().hex,
        "typ": "access",
        "roles": ["admin"],
    }
    claims.update(overrides)
    return claims


async def _status(client, token: str) -> int:
    resp = await client.get("/v1/users/me", headers={"Authorization": f"Bearer {token}"})
    return resp.status_code


async def test_valid_token_accepted(client, user):
    assert await _status(client, user.access) == 200


async def test_expired_token(client, container, user):
    token, _ = container.keyring.create_access_token(user.id, ["user"], None, -5)
    assert await _status(client, token) == 401


async def test_wrong_signature_same_kid(client, container, user):
    forged = jwt.encode(
        _claims(container, user.id),
        generate_private_key_pem(),
        algorithm="RS256",
        headers={"kid": container.keyring.kid},
    )
    assert await _status(client, forged) == 401


async def test_tampered_role_claim(client, container, user):
    header, payload, sig = user.access.split(".")
    claims = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
    claims["roles"] = ["admin"]
    tampered = f"{header}.{_b64(claims)}.{sig}"
    assert await _status(client, tampered) == 401
    resp = await client.get("/v1/admin/users", headers={"Authorization": f"Bearer {tampered}"})
    assert resp.status_code == 401


async def test_alg_none(client, container, user):
    token = f"{_b64({'alg': 'none', 'typ': 'JWT', 'kid': container.keyring.kid})}.{_b64(_claims(container, user.id))}."
    assert await _status(client, token) == 401


async def test_hs256_signed_with_public_key(client, container, user):
    import hashlib
    import hmac

    public_pem = container.keyring._private_key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    signing_input = f"{_b64({'alg': 'HS256', 'typ': 'JWT', 'kid': container.keyring.kid})}.{_b64(_claims(container, user.id))}"
    sig = base64.urlsafe_b64encode(
        hmac.new(public_pem, signing_input.encode(), hashlib.sha256).digest()
    ).rstrip(b"=")
    assert await _status(client, f"{signing_input}.{sig.decode()}") == 401


async def test_wrong_kid(client, container, user):
    token = jwt.encode(
        _claims(container, user.id),
        container.keyring._private_key,
        algorithm="RS256",
        headers={"kid": "not-a-real-kid"},
    )
    assert await _status(client, token) == 401


@pytest.mark.parametrize("override", [{"aud": "other-service"}, {"iss": "evil"}, {"typ": "mfa"}])
async def test_wrong_audience_issuer_or_type(client, container, user, override):
    token = jwt.encode(
        _claims(container, user.id, **override),
        container.keyring._private_key,
        algorithm="RS256",
        headers={"kid": container.keyring.kid},
    )
    assert await _status(client, token) == 401


@pytest.mark.parametrize("header", ["", "Bearer", "Basic abc", "Bearer not.a.jwt"])
async def test_missing_or_malformed_header(client, header):
    resp = await client.get("/v1/users/me", headers={"Authorization": header} if header else {})
    assert resp.status_code == 401
    assert resp.headers["content-type"].startswith("application/problem+json")
    assert resp.json()["code"] == "not_authenticated"


async def test_logged_out_token_rejected_before_expiry(client, user):
    """Spec test 5: the jti denylist kills the token immediately."""
    assert (await client.post("/v1/auth/logout", headers=user.headers)).status_code == 204
    assert await _status(client, user.access) == 401
    # and its refresh family is revoked
    resp = await client.post("/v1/auth/refresh", json={"refresh_token": user.refresh})
    assert resp.status_code == 401


async def test_token_for_deleted_user_rejected(client, user):
    assert (await client.delete("/v1/users/me", headers=user.headers)).status_code == 204
    assert await _status(client, user.access) == 401
