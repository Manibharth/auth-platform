"""Google sign-in with OAuth 2.0 authorization code + PKCE (stretch goal).

The server keeps the PKCE verifier in Redis keyed by an unguessable `state`, so
the flow needs no server-side session. Only fixed Google URLs are fetched (no
user-supplied URLs, so no SSRF surface).
"""

from __future__ import annotations

import base64
import hashlib
import secrets
from dataclasses import dataclass
from typing import Any, cast
from urllib.parse import urlencode

import anyio
import httpx
import jwt
from redis.asyncio import Redis

from app.core.config import Settings
from app.core.errors import ProblemError

GOOGLE_AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"  # noqa: S105 - public endpoint
GOOGLE_JWKS_URL = "https://www.googleapis.com/oauth2/v3/certs"
GOOGLE_ISSUERS = ("https://accounts.google.com", "accounts.google.com")
STATE_TTL_SECONDS = 600


@dataclass(frozen=True)
class ExternalIdentity:
    email: str
    name: str | None


def pkce_pair() -> tuple[str, str]:
    verifier = secrets.token_urlsafe(64)[:96]
    challenge = (
        base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    )
    return verifier, challenge


def oauth_failed(detail: str) -> ProblemError:
    return ProblemError(400, "oauth_failed", "Sign-in with Google failed", detail)


class GoogleOAuthService:
    _jwks_client: jwt.PyJWKClient | None = None

    def __init__(self, settings: Settings, redis: Redis) -> None:
        self.settings = settings
        self.redis = redis

    def _require_configured(self) -> tuple[str, str, str]:
        s = self.settings
        if not (s.google_client_id and s.google_client_secret and s.google_redirect_uri):
            raise ProblemError(
                404, "feature_disabled", "Feature disabled", "Google sign-in is not configured"
            )
        return s.google_client_id, s.google_client_secret.get_secret_value(), s.google_redirect_uri

    async def start(self) -> tuple[str, str]:
        client_id, _, redirect_uri = self._require_configured()
        state = secrets.token_urlsafe(32)
        nonce = secrets.token_urlsafe(16)
        verifier, challenge = pkce_pair()
        await self.redis.set(f"oauth_state:{state}", f"{verifier} {nonce}", ex=STATE_TTL_SECONDS)
        params = {
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "response_type": "code",
            "scope": "openid email profile",
            "state": state,
            "nonce": nonce,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "prompt": "select_account",
        }
        return f"{GOOGLE_AUTH_URL}?{urlencode(params)}", state

    async def _exchange_code(self, code: str, verifier: str) -> dict[str, Any]:
        client_id, client_secret, redirect_uri = self._require_configured()
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.post(
                GOOGLE_TOKEN_URL,
                data={
                    "grant_type": "authorization_code",
                    "code": code,
                    "code_verifier": verifier,
                    "client_id": client_id,
                    "client_secret": client_secret,
                    "redirect_uri": redirect_uri,
                },
            )
        if resp.status_code != 200:
            raise oauth_failed("Authorization code was rejected")
        return cast(dict[str, Any], resp.json())

    def _verify_id_token(self, id_token: str, nonce: str) -> dict[str, Any]:
        client_id, _, _ = self._require_configured()
        if GoogleOAuthService._jwks_client is None:
            GoogleOAuthService._jwks_client = jwt.PyJWKClient(GOOGLE_JWKS_URL, cache_keys=True)
        try:
            key = GoogleOAuthService._jwks_client.get_signing_key_from_jwt(id_token)
            claims: dict[str, Any] = jwt.decode(
                id_token,
                key.key,
                algorithms=["RS256"],
                audience=client_id,
                options={"require": ["exp", "iat", "iss", "aud", "sub"]},
            )
        except jwt.PyJWTError as exc:
            raise oauth_failed("Invalid ID token") from exc
        if claims.get("iss") not in GOOGLE_ISSUERS or claims.get("nonce") != nonce:
            raise oauth_failed("Invalid ID token")
        return claims

    async def complete(self, code: str, state: str) -> ExternalIdentity:
        self._require_configured()
        stored = await self.redis.getdel(f"oauth_state:{state}")  # single use
        if not stored:
            raise oauth_failed("Unknown or expired state")
        verifier, nonce = str(stored).split(" ", 1)
        tokens = await self._exchange_code(code, verifier)
        id_token = tokens.get("id_token")
        if not isinstance(id_token, str):
            raise oauth_failed("No ID token returned")
        # PyJWKClient fetches Google's keys with blocking I/O; keep it off the loop.
        claims = await anyio.to_thread.run_sync(self._verify_id_token, id_token, nonce)
        email = claims.get("email")
        if not isinstance(email, str) or claims.get("email_verified") is not True:
            raise oauth_failed("Google account email is not verified")
        name = claims.get("name")
        return ExternalIdentity(email=email, name=name if isinstance(name, str) else None)
