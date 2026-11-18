"""Unit tests: hashing, password policy, JWT signing/verification, helpers."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

import bcrypt
import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from app.core.errors import ProblemError
from app.core.logging import mask_email, redact
from app.core.security import (
    UNUSABLE_PASSWORD,
    KeyRing,
    PasswordHasher,
    SecretBox,
    TokenError,
    generate_opaque_token,
    generate_private_key_pem,
    hash_token,
    password_problems,
)
from app.services.pagination import decode_cursor, encode_cursor
from app.services.project_service import request_fingerprint

FAST = PasswordHasher(time_cost=1, memory_cost_kib=1024, parallelism=1)


# ---------------------------------------------------------------- hashing
@settings(max_examples=25, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(st.text(min_size=1, max_size=64))
def test_argon2_round_trip(password: str) -> None:
    h = FAST.hash(password)
    assert h.startswith("$argon2id$")
    assert FAST.verify(h, password) == (True, False)
    assert FAST.verify(h, password + "x")[0] is False


def test_hash_is_salted() -> None:
    assert FAST.hash("same-password-123") != FAST.hash("same-password-123")


def test_bcrypt_hash_verifies_and_requests_upgrade() -> None:
    legacy = bcrypt.hashpw(b"legacy-password-1", bcrypt.gensalt(rounds=4)).decode()
    assert FAST.verify(legacy, "legacy-password-1") == (True, True)
    assert FAST.verify(legacy, "wrong") == (False, False)


def test_weaker_params_need_rehash() -> None:
    stronger = PasswordHasher(time_cost=2, memory_cost_kib=2048, parallelism=1)
    h = FAST.hash("pw-123456789012")
    assert stronger.verify(h, "pw-123456789012") == (True, True)


def test_garbage_hash_never_matches() -> None:
    assert FAST.verify("not-a-hash", "x") == (False, False)
    assert FAST.verify(UNUSABLE_PASSWORD, "x") == (False, False)
    FAST.dummy_verify("anything")  # must not raise


# ---------------------------------------------------------------- password policy
@pytest.mark.parametrize(
    ("password", "fragment"),
    [
        ("short", "at least 12"),
        ("password1234", "too common"),
        ("aaaaaaaaaaaaaa", "distinct"),
        ("alice-is-great-99", "email"),
        ("x" * 200 + "abcd", "at most"),
    ],
)
def test_password_policy_rejects(password: str, fragment: str) -> None:
    problems = password_problems(password, "alice@example.com", 12, 128)
    assert any(fragment in p for p in problems), problems


@given(
    st.text(alphabet=st.characters(min_codepoint=33, max_codepoint=126), min_size=0, max_size=11)
)
def test_short_passwords_always_rejected(password: str) -> None:
    assert password_problems(password, "bob@example.com", 12, 128)


def test_strong_password_accepted() -> None:
    assert password_problems("correct-Horse-battery-42", "bob@example.com", 12, 128) == []


# ---------------------------------------------------------------- opaque tokens
def test_opaque_tokens_are_256_bit_and_hashed() -> None:
    t = generate_opaque_token()
    assert len(t) >= 43 and t != generate_opaque_token()
    assert len(hash_token(t)) == 64 and hash_token(t) == hash_token(t) and hash_token(t) != t


# ---------------------------------------------------------------- JWT
@pytest.fixture(scope="module")
def ring() -> KeyRing:
    return KeyRing(private_pem=generate_private_key_pem())


def test_access_token_round_trip(ring: KeyRing) -> None:
    uid, sid = uuid.uuid4(), uuid.uuid4()
    token, issued = ring.create_access_token(uid, ["user", "admin"], sid, 900)
    claims = ring.decode_access_token(token)
    assert claims.sub == uid and claims.sid == sid
    assert claims.roles == ("admin", "user")
    assert claims.exp - claims.iat == 900 and claims.jti == issued.jti
    assert claims.iat_ms >= claims.iat * 1000


def test_expired_token_rejected(ring: KeyRing) -> None:
    token, _ = ring.create_access_token(uuid.uuid4(), [], None, -10)
    with pytest.raises(TokenError, match="expired"):
        ring.decode_access_token(token)


def test_mfa_token_is_not_an_access_token(ring: KeyRing) -> None:
    mfa = ring.create_mfa_token(uuid.uuid4(), 60)
    with pytest.raises(TokenError, match="type"):
        ring.decode_access_token(mfa)
    access, _ = ring.create_access_token(uuid.uuid4(), [], None, 60)
    with pytest.raises(TokenError):
        ring.decode_mfa_token(access)


def test_previous_key_still_verifies_after_rotation(ring: KeyRing) -> None:
    from cryptography.hazmat.primitives import serialization

    old_pub = (
        ring._private_key.public_key()
        .public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        .decode()
    )
    token, _ = ring.create_access_token(uuid.uuid4(), ["user"], None, 60)
    rotated = KeyRing(private_pem=generate_private_key_pem(), previous_public_pems=[old_pub])
    assert rotated.decode_access_token(token).roles == ("user",)
    kids = {k["kid"] for k in rotated.jwks()["keys"]}
    assert kids == {rotated.kid, ring.kid}
    # A ring without the old key refuses it.
    with pytest.raises(TokenError, match="kid"):
        KeyRing(private_pem=generate_private_key_pem()).decode_access_token(token)


def test_jwks_has_public_parts_only(ring: KeyRing) -> None:
    (key,) = ring.jwks()["keys"]
    assert key["kty"] == "RSA" and key["alg"] == "RS256" and key["use"] == "sig"
    assert "d" not in key and "p" not in key


@given(st.text(max_size=200))
def test_garbage_never_decodes(garbage: str) -> None:
    ring = _shared_ring()
    with pytest.raises(TokenError):
        ring.decode_access_token(garbage)


_RING: KeyRing | None = None


def _shared_ring() -> KeyRing:
    global _RING
    if _RING is None:
        _RING = KeyRing(private_pem=generate_private_key_pem())
    return _RING


# ---------------------------------------------------------------- helpers
def test_secret_box_round_trip() -> None:
    box = SecretBox(None)
    assert box.decrypt(box.encrypt("JBSWY3DPEHPK3PXP")) == "JBSWY3DPEHPK3PXP"
    assert SecretBox(None).decrypt(box.encrypt("x")) is None  # different key


@given(st.datetimes(timezones=st.just(UTC)), st.uuids())
def test_cursor_round_trip(ts: datetime, row_id: uuid.UUID) -> None:
    assert decode_cursor(encode_cursor(ts, row_id)) == (ts, row_id)


@given(st.text(max_size=100))
def test_bad_cursor_is_a_400_never_a_crash(cursor: str) -> None:
    try:
        decode_cursor(cursor)
    except ProblemError as exc:
        assert exc.status == 400


def test_request_fingerprint_is_order_independent() -> None:
    assert request_fingerprint({"a": 1, "b": 2}) == request_fingerprint({"b": 2, "a": 1})
    assert request_fingerprint({"a": 1}) != request_fingerprint({"a": 2})


def test_logs_redact_secrets_and_mask_emails() -> None:
    event = redact(
        None,
        "info",
        {
            "event": "x",
            "password": "hunter2",
            "refresh_token": "abc",
            "note": "Bearer eyJabc.def.ghi from alice@example.com",
            "nested": {"api_key": "k"},
        },
    )
    assert event["password"] == "[REDACTED]" and event["refresh_token"] == "[REDACTED]"
    assert "eyJ" not in event["note"] and "alice@" not in event["note"]
    assert event["nested"]["api_key"] == "[REDACTED]"
    assert mask_email("alice@example.com") == "a***@example.com"
