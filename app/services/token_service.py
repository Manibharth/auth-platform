"""Access tokens, rotating refresh tokens with reuse detection, and early revocation.

Refresh rotation:
  1. Login creates refresh token A in a new family F.
  2. /refresh hashes A, loads the row with SELECT ... FOR UPDATE and checks it is
     unexpired, unused and unrevoked.
  3. A is marked used; B is issued in family F.
  4. If A is ever presented again, the whole family is revoked (theft signal).
"""

from __future__ import annotations

import time
import uuid
from datetime import UTC, datetime, timedelta

import structlog
from redis.asyncio import Redis
from redis.exceptions import RedisError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core import metrics
from app.core.config import Settings
from app.core.errors import ProblemError
from app.core.security import AccessClaims, KeyRing, generate_opaque_token, hash_token
from app.models import RefreshToken, User
from app.repositories.tokens import RefreshTokenRepository
from app.schemas import TokenPair
from app.services import RequestContext
from app.services.audit_service import AuditService

log = structlog.get_logger(__name__)


def invalid_refresh(detail: str = "Refresh token is invalid or expired") -> ProblemError:
    return ProblemError(401, "invalid_refresh_token", "Invalid refresh token", detail)


class RevocationStore:
    """Redis-backed early revocation of access tokens.

    * denylist:{jti}      -> set at logout until the token's own exp.
    * revoked_before:{u}  -> unix time (ms); tokens issued at or before it are rejected
                             (logout-all, password reset, account disable).

    If Redis is down the check degrades to the short token lifetime (fail open,
    logged), because refusing every request would turn a cache outage into a
    full outage. Login rate limits fail closed instead.
    """

    def __init__(self, redis: Redis, settings: Settings) -> None:
        self.redis = redis
        self.settings = settings

    async def deny_jti(self, jti: str, exp: int) -> None:
        ttl = max(1, exp - int(time.time()))
        await self.redis.set(f"denylist:{jti}", "1", ex=ttl)

    async def revoke_user_tokens(self, user_id: uuid.UUID) -> None:
        # Keep the marker for one access-token lifetime: older tokens are dead by then.
        await self.redis.set(
            f"revoked_before:{user_id}",
            str(int(time.time() * 1000)),
            ex=self.settings.access_token_ttl_seconds + 60,
        )

    async def is_revoked(self, claims: AccessClaims) -> bool:
        try:
            denied, before = await self.redis.mget(
                f"denylist:{claims.jti}", f"revoked_before:{claims.sub}"
            )
        except RedisError:
            log.warning("revocation_check_degraded")
            return False
        if denied:
            return True
        return before is not None and claims.iat_ms <= int(before)


class TokenService:
    def __init__(
        self, session: AsyncSession, keyring: KeyRing, redis: Redis, settings: Settings
    ) -> None:
        self.session = session
        self.keyring = keyring
        self.settings = settings
        self.repo = RefreshTokenRepository(session)
        self.revocations = RevocationStore(redis, settings)
        self.audit = AuditService(session)

    def _is_demo(self, user: User) -> bool:
        return bool(
            self.settings.demo_read_only
            and self.settings.demo_email
            and user.email.lower() == self.settings.demo_email.lower()
        )

    async def issue_pair(
        self, user: User, ctx: RequestContext, family_id: uuid.UUID | None = None
    ) -> tuple[TokenPair, RefreshToken]:
        """Create a refresh token (new family unless given) plus an access token. Flushes only."""
        now = datetime.now(UTC)
        family = family_id or uuid.uuid4()
        raw = generate_opaque_token()
        ttl = timedelta(days=self.settings.refresh_token_ttl_days)
        row = await self.repo.add(
            RefreshToken(
                user_id=user.id,
                family_id=family,
                token_hash=hash_token(raw),
                issued_at=now,
                expires_at=now + ttl,
                user_agent=(ctx.user_agent or "")[:400] or None,
                ip=ctx.ip,
            )
        )
        access, _ = self.keyring.create_access_token(
            user.id,
            user.role_names,
            family,
            self.settings.access_token_ttl_seconds,
            demo=self._is_demo(user),
        )
        pair = TokenPair(
            access_token=access,
            expires_in=self.settings.access_token_ttl_seconds,
            refresh_token=raw,
            refresh_expires_in=int(ttl.total_seconds()),
        )
        return pair, row

    async def rotate(self, raw_token: str, ctx: RequestContext) -> TokenPair:
        now = datetime.now(UTC)
        row = await self.repo.get_by_hash_for_update(hash_token(raw_token))
        if row is None:
            raise invalid_refresh()
        if row.revoked_at is not None:
            raise invalid_refresh("Session has been revoked; sign in again")
        if row.used_at is not None:
            # Reuse of a rotated token: assume theft and kill the whole chain.
            revoked = await self.repo.revoke_family(row.family_id, now)
            await self.audit.record(
                "auth.refresh_reuse_detected",
                actor_id=row.user_id,
                ctx=ctx,
                target_type="refresh_family",
                target_id=row.family_id,
                metadata={"revoked_tokens": revoked},
            )
            await self.session.commit()
            metrics.REFRESH_REUSE.inc()
            log.warning("refresh_reuse_detected", user_id=str(row.user_id))
            raise ProblemError(
                401,
                "refresh_token_reused",
                "Refresh token reuse detected",
                "This session was revoked for your safety; sign in again",
            )
        if row.expires_at <= now:
            raise invalid_refresh()

        user = await self.session.get(User, row.user_id)
        if user is None or not user.is_active or user.deleted_at is not None:
            await self.repo.revoke_family(row.family_id, now)
            await self.session.commit()
            raise invalid_refresh()
        await self.session.refresh(user, ["roles"])  # roles fresh from the database

        pair, new_row = await self.issue_pair(user, ctx, family_id=row.family_id)
        row.used_at = now
        row.replaced_by = new_row.id
        await self.session.commit()
        return pair

    async def revoke_session(self, user_id: uuid.UUID, family_id: uuid.UUID | None) -> None:
        if family_id is None:
            return
        if await self.repo.family_owner(family_id) == user_id:
            await self.repo.revoke_family(family_id, datetime.now(UTC))

    async def revoke_all(self, user_id: uuid.UUID) -> int:
        count = await self.repo.revoke_all_for_user(user_id, datetime.now(UTC))
        try:
            await self.revocations.revoke_user_tokens(user_id)
        except RedisError:
            log.warning("revoke_user_tokens_degraded", user_id=str(user_id))
        return count

    async def deny_access_token(self, claims: AccessClaims) -> None:
        try:
            await self.revocations.deny_jti(claims.jti, claims.exp)
        except RedisError:
            log.warning("denylist_write_degraded")
