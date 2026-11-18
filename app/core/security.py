"""Password hashing, opaque token helpers, and RS256 JWT signing/verification."""

from __future__ import annotations

import base64
import contextlib
import hashlib
import hmac
import json
import secrets
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from functools import cached_property
from importlib import resources
from typing import Any, cast

import bcrypt
import jwt
from argon2 import PasswordHasher as Argon2Hasher
from argon2 import Type
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt.algorithms import RSAAlgorithm

from app.core.config import Settings

ALGORITHM = "RS256"
UNUSABLE_PASSWORD = "!unusable"  # noqa: S105 - marker, never matches a hash


# ====================================================================== passwords
class PasswordHasher:
    """Argon2id hasher that also verifies legacy bcrypt hashes (migration path)."""

    def __init__(self, time_cost: int, memory_cost_kib: int, parallelism: int) -> None:
        self._argon = Argon2Hasher(
            time_cost=time_cost,
            memory_cost=memory_cost_kib,
            parallelism=parallelism,
            type=Type.ID,
        )
        # Precomputed hash used to burn the same CPU time for unknown accounts.
        self._dummy_hash = self._argon.hash(secrets.token_urlsafe(16))

    @classmethod
    def from_settings(cls, settings: Settings) -> PasswordHasher:
        return cls(
            settings.argon2_time_cost, settings.argon2_memory_cost_kib, settings.argon2_parallelism
        )

    def hash(self, password: str) -> str:
        return self._argon.hash(password)

    def verify(self, password_hash: str, password: str) -> tuple[bool, bool]:
        """Return (matches, needs_rehash)."""
        if password_hash.startswith(("$2a$", "$2b$", "$2y$")):
            ok = bcrypt.checkpw(password.encode(), password_hash.encode())
            return ok, ok  # always upgrade bcrypt to Argon2id after a good login
        try:
            self._argon.verify(password_hash, password)
        except (VerifyMismatchError, VerificationError, InvalidHashError):
            return False, False
        return True, self._argon.check_needs_rehash(password_hash)

    def dummy_verify(self, password: str) -> None:
        """Equalise timing when the account does not exist or is locked."""
        with contextlib.suppress(VerificationError):
            self._argon.verify(self._dummy_hash, password)


def _load_common_passwords() -> frozenset[str]:
    text = resources.files("app.core").joinpath("common_passwords.txt").read_text()
    return frozenset(line.strip().lower() for line in text.splitlines() if line.strip())


COMMON_PASSWORDS = _load_common_passwords()


def password_problems(password: str, email: str, min_len: int, max_len: int) -> list[str]:
    problems: list[str] = []
    if len(password) < min_len:
        problems.append(f"must be at least {min_len} characters")
    if len(password) > max_len:
        problems.append(f"must be at most {max_len} characters")
    lowered = password.lower()
    if lowered in COMMON_PASSWORDS:
        problems.append("is too common")
    if len(set(password)) < 4:
        problems.append("has too few distinct characters")
    local_part = email.split("@", 1)[0].lower()
    if len(local_part) >= 4 and local_part in lowered:
        problems.append("must not contain your email address")
    return problems


# ====================================================================== opaque tokens
def generate_opaque_token() -> str:
    """256 bits of randomness, URL-safe."""
    return secrets.token_urlsafe(32)


def hash_token(token: str) -> str:
    """SHA-256 so a database leak does not leak usable tokens."""
    return hashlib.sha256(token.encode()).hexdigest()


def constant_time_equals(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode(), b.encode())


# ====================================================================== MFA secret encryption
class SecretBox:
    """Fernet (AES-128-CBC + HMAC) wrapper for TOTP secrets at rest."""

    def __init__(self, key: str | None) -> None:
        self._fernet = Fernet(key.encode()) if key else Fernet(Fernet.generate_key())

    def encrypt(self, plaintext: str) -> str:
        return self._fernet.encrypt(plaintext.encode()).decode()

    def decrypt(self, ciphertext: str) -> str | None:
        try:
            return self._fernet.decrypt(ciphertext.encode()).decode()
        except InvalidToken:
            return None


# ====================================================================== JWT keys
def generate_private_key_pem() -> str:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _public_jwk(public_key: rsa.RSAPublicKey) -> dict[str, Any]:
    jwk = cast(dict[str, Any], json.loads(RSAAlgorithm.to_jwk(public_key)))
    # RFC 7638 thumbprint as a stable key id.
    canonical = json.dumps(
        {"e": jwk["e"], "kty": "RSA", "n": jwk["n"]}, separators=(",", ":"), sort_keys=True
    )
    jwk["kid"] = _b64url(hashlib.sha256(canonical.encode()).digest())
    jwk["use"] = "sig"
    jwk["alg"] = ALGORITHM
    return jwk


class TokenError(Exception):
    """Any reason a token is not acceptable. The message is for logs, never for clients."""


@dataclass(frozen=True)
class AccessClaims:
    sub: uuid.UUID
    jti: str
    sid: uuid.UUID | None
    roles: tuple[str, ...]
    iat: int
    exp: int
    demo: bool = False
    iat_ms: int = 0  # millisecond issue time, for exact 'revoked before' comparisons


@dataclass
class KeyRing:
    """Current signing key plus previous public keys that are still accepted."""

    private_pem: str
    previous_public_pems: list[str] = field(default_factory=list)
    issuer: str = "auth-platform"
    audience: str = "auth-platform-api"

    @cached_property
    def _private_key(self) -> rsa.RSAPrivateKey:
        key = serialization.load_pem_private_key(self.private_pem.encode(), password=None)
        if not isinstance(key, rsa.RSAPrivateKey):
            raise ValueError("JWT private key must be RSA")
        return key

    @cached_property
    def current_jwk(self) -> dict[str, Any]:
        return _public_jwk(self._private_key.public_key())

    @property
    def kid(self) -> str:
        return str(self.current_jwk["kid"])

    @cached_property
    def _verification_keys(self) -> dict[str, rsa.RSAPublicKey]:
        keys = {self.kid: self._private_key.public_key()}
        for pem in self.previous_public_pems:
            pub = serialization.load_pem_public_key(pem.encode())
            if isinstance(pub, rsa.RSAPublicKey):
                keys[str(_public_jwk(pub)["kid"])] = pub
        return keys

    def jwks(self) -> dict[str, list[dict[str, Any]]]:
        return {"keys": [_public_jwk(k) for k in self._verification_keys.values()]}

    @classmethod
    def from_settings(cls, settings: Settings) -> KeyRing:
        pem = settings.load_private_key_pem()
        if pem is None:
            if settings.is_production_like:  # pragma: no cover - guarded by Settings too
                raise RuntimeError("JWT signing key is not configured")
            pem = generate_private_key_pem()  # ephemeral key for local/test only
        return cls(
            private_pem=pem,
            previous_public_pems=list(settings.jwt_previous_public_keys),
            issuer=settings.jwt_issuer,
            audience=settings.jwt_audience,
        )

    # ------------------------------------------------------------------ signing
    def _encode(self, claims: dict[str, Any]) -> str:
        return jwt.encode(claims, self._private_key, algorithm=ALGORITHM, headers={"kid": self.kid})

    def create_access_token(
        self,
        user_id: uuid.UUID,
        roles: list[str],
        session_id: uuid.UUID | None,
        ttl_seconds: int,
        *,
        demo: bool = False,
    ) -> tuple[str, AccessClaims]:
        now = datetime.now(UTC)
        iat = int(now.timestamp())
        iat_ms = int(now.timestamp() * 1000)
        exp = int((now + timedelta(seconds=ttl_seconds)).timestamp())
        jti = uuid.uuid4().hex
        claims: dict[str, Any] = {
            "iss": self.issuer,
            "aud": self.audience,
            "sub": str(user_id),
            "iat": iat,
            "nbf": iat,
            "exp": exp,
            "jti": jti,
            "typ": "access",
            "roles": sorted(roles),
            "iat_ms": iat_ms,
        }
        if session_id is not None:
            claims["sid"] = str(session_id)
        if demo:
            claims["demo"] = True
        token = self._encode(claims)
        return token, AccessClaims(
            user_id, jti, session_id, tuple(sorted(roles)), iat, exp, demo, iat_ms
        )

    def create_mfa_token(self, user_id: uuid.UUID, ttl_seconds: int) -> str:
        now = int(datetime.now(UTC).timestamp())
        return self._encode(
            {
                "iss": self.issuer,
                "aud": self.audience,
                "sub": str(user_id),
                "iat": now,
                "exp": now + ttl_seconds,
                "jti": uuid.uuid4().hex,
                "typ": "mfa",
            }
        )

    # ------------------------------------------------------------------ verification
    def _decode(self, token: str, expected_typ: str) -> dict[str, Any]:
        try:
            header = jwt.get_unverified_header(token)
        except jwt.PyJWTError as exc:
            raise TokenError("malformed token") from exc
        if header.get("alg") != ALGORITHM:
            raise TokenError(f"unexpected alg {header.get('alg')!r}")
        kid = header.get("kid")
        if not isinstance(kid, str) or kid not in self._verification_keys:
            raise TokenError("unknown kid")
        try:
            claims: dict[str, Any] = jwt.decode(
                token,
                self._verification_keys[kid],
                algorithms=[ALGORITHM],
                audience=self.audience,
                issuer=self.issuer,
                options={"require": ["exp", "iat", "sub", "jti", "typ"]},
            )
        except jwt.ExpiredSignatureError as exc:
            raise TokenError("expired") from exc
        except jwt.PyJWTError as exc:
            raise TokenError(f"invalid: {type(exc).__name__}") from exc
        if claims.get("typ") != expected_typ:
            raise TokenError("wrong token type")
        return claims

    def decode_access_token(self, token: str) -> AccessClaims:
        claims = self._decode(token, "access")
        try:
            roles = claims.get("roles", [])
            if not isinstance(roles, list) or not all(isinstance(r, str) for r in roles):
                raise TokenError("bad roles claim")
            sid = claims.get("sid")
            return AccessClaims(
                sub=uuid.UUID(claims["sub"]),
                jti=str(claims["jti"]),
                sid=uuid.UUID(sid) if sid else None,
                roles=tuple(roles),
                iat=int(claims["iat"]),
                exp=int(claims["exp"]),
                demo=bool(claims.get("demo", False)),
                iat_ms=int(claims.get("iat_ms", int(claims["iat"]) * 1000)),
            )
        except (ValueError, TypeError) as exc:
            raise TokenError("bad claims") from exc

    def decode_mfa_token(self, token: str) -> uuid.UUID:
        claims = self._decode(token, "mfa")
        try:
            return uuid.UUID(claims["sub"])
        except (ValueError, TypeError) as exc:
            raise TokenError("bad claims") from exc
