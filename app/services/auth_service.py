"""Registration, email verification, login with lockout, password flows and TOTP MFA."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import anyio
import pyotp
import structlog
from redis.asyncio import Redis
from sqlalchemy.ext.asyncio import AsyncSession

from app.core import metrics
from app.core.config import Settings
from app.core.errors import ProblemError
from app.core.logging import mask_email
from app.core.security import (
    UNUSABLE_PASSWORD,
    AccessClaims,
    KeyRing,
    PasswordHasher,
    SecretBox,
    TokenError,
    generate_opaque_token,
    hash_token,
    password_problems,
)
from app.db.seed import DEFAULT_ROLE
from app.models import OneTimeToken, User
from app.repositories.tokens import OneTimeTokenRepository
from app.repositories.users import RoleRepository, UserRepository
from app.schemas import MfaChallenge, TokenPair
from app.services import RequestContext
from app.services.audit_service import AuditService
from app.services.email_service import (
    Email,
    duplicate_signup_email,
    reset_email,
    verification_email,
)
from app.services.token_service import TokenService

log = structlog.get_logger(__name__)

VERIFY_EMAIL = "verify_email"
RESET_PASSWORD = "reset_password"  # noqa: S105 - purpose label, not a secret


def invalid_credentials() -> ProblemError:
    # One response for unknown email, wrong password and locked account.
    return ProblemError(
        401, "invalid_credentials", "Invalid credentials", "Email or password is incorrect"
    )


def invalid_one_time_token() -> ProblemError:
    return ProblemError(
        400, "invalid_token", "Invalid or expired token", "The link is invalid or has expired"
    )


def weak_password(problems: list[str]) -> ProblemError:
    return ProblemError(
        422,
        "weak_password",
        "Password does not meet the policy",
        "Password " + "; ".join(problems),
        extra={"problems": problems},
    )


class AuthService:
    def __init__(
        self,
        session: AsyncSession,
        *,
        settings: Settings,
        hasher: PasswordHasher,
        keyring: KeyRing,
        redis: Redis,
        secret_box: SecretBox,
    ) -> None:
        self.session = session
        self.settings = settings
        self.hasher = hasher
        self.keyring = keyring
        self.redis = redis
        self.secret_box = secret_box
        self.users = UserRepository(session)
        self.roles = RoleRepository(session)
        self.otts = OneTimeTokenRepository(session)
        self.tokens = TokenService(session, keyring, redis, settings)
        self.audit = AuditService(session)

    # ------------------------------------------------------------------ helpers
    async def _hash(self, password: str) -> str:
        # Argon2 is CPU-bound by design; keep it off the event loop.
        return await anyio.to_thread.run_sync(self.hasher.hash, password)

    async def _verify(self, password_hash: str, password: str) -> tuple[bool, bool]:
        if password_hash == UNUSABLE_PASSWORD:
            await anyio.to_thread.run_sync(self.hasher.dummy_verify, password)
            return False, False
        return await anyio.to_thread.run_sync(self.hasher.verify, password_hash, password)

    async def _dummy_verify(self, password: str) -> None:
        await anyio.to_thread.run_sync(self.hasher.dummy_verify, password)

    def _check_policy(self, password: str, email: str) -> None:
        problems = password_problems(
            password, email, self.settings.password_min_length, self.settings.password_max_length
        )
        if problems:
            raise weak_password(problems)

    def _link(self, path: str, token: str) -> str:
        return f"{self.settings.public_base_url.rstrip('/')}{path}?token={token}"

    async def _new_one_time_token(self, user: User, purpose: str, ttl: timedelta) -> str:
        now = datetime.now(UTC)
        await self.otts.invalidate_outstanding(user.id, purpose, now)
        raw = generate_opaque_token()
        await self.otts.add(
            OneTimeToken(
                user_id=user.id, purpose=purpose, token_hash=hash_token(raw), expires_at=now + ttl
            )
        )
        return raw

    async def _consume_one_time_token(self, raw: str, purpose: str) -> OneTimeToken:
        now = datetime.now(UTC)
        row = await self.otts.get_by_hash_for_update(hash_token(raw), purpose)
        if row is None or row.consumed_at is not None or row.expires_at <= now:
            raise invalid_one_time_token()
        row.consumed_at = now
        return row

    # ------------------------------------------------------------------ register
    async def register(
        self, email: str, password: str, full_name: str | None, ctx: RequestContext
    ) -> Email:
        """Always answers the same way; returns the email to send (in the background)."""
        self._check_policy(password, email)
        existing = await self.users.get_by_email(email, include_deleted=True)
        if existing is not None:
            # Hide which emails exist: burn the same CPU, warn the real owner instead.
            await self._dummy_verify(password)
            log.info("register_duplicate", email=mask_email(email))
            return duplicate_signup_email(existing.email, f"{self.settings.public_base_url}/docs")

        password_hash = await self._hash(password)
        roles = await self.roles.by_names([DEFAULT_ROLE])
        user = await self.users.add(
            User(email=email, password_hash=password_hash, full_name=full_name, roles=roles)
        )
        raw = await self._new_one_time_token(
            user, VERIFY_EMAIL, timedelta(hours=self.settings.verify_email_ttl_hours)
        )
        await self.audit.record(
            "user.register", actor_id=user.id, ctx=ctx, target_type="user", target_id=user.id
        )
        await self.session.commit()
        return verification_email(
            user.email,
            self._link("/v1/auth/verify-email", raw),
            self.settings.verify_email_ttl_hours,
        )

    async def verify_email(self, raw: str, ctx: RequestContext) -> None:
        row = await self._consume_one_time_token(raw, VERIFY_EMAIL)
        user = await self.users.get_for_update(row.user_id)
        if user is None:
            raise invalid_one_time_token()
        user.is_verified = True
        await self.audit.record(
            "user.email_verified", actor_id=user.id, ctx=ctx, target_type="user", target_id=user.id
        )
        await self.session.commit()

    # ------------------------------------------------------------------ login
    def _lock_duration(self, failures: int) -> timedelta:
        over = failures - self.settings.lockout_threshold
        seconds = min(
            self.settings.lockout_base_seconds * (2**over), self.settings.lockout_max_seconds
        )
        return timedelta(seconds=seconds)

    async def _record_failure(self, user: User, ctx: RequestContext, reason: str) -> None:
        metrics.LOGIN_FAILURES.labels(reason=reason).inc()
        await self.audit.record(
            "auth.login_failed",
            actor_id=user.id,
            ctx=ctx,
            target_type="user",
            target_id=user.id,
            metadata={"reason": reason, "failed_logins": user.failed_logins},
        )
        await self.session.commit()

    async def login(
        self, email: str, password: str, ctx: RequestContext
    ) -> TokenPair | MfaChallenge:
        now = datetime.now(UTC)
        user = await self.users.get_by_email(email)
        if user is None:
            await self._dummy_verify(password)
            metrics.LOGIN_FAILURES.labels(reason="unknown_email").inc()
            raise invalid_credentials()

        user = await self.users.get_for_update(user.id)
        if user is None:  # pragma: no cover - deleted between the two reads
            raise invalid_credentials()

        if user.locked_until is not None and user.locked_until > now:
            # Locked: refuse even the right password, with the generic error.
            await self._dummy_verify(password)
            await self._record_failure(user, ctx, "locked")
            raise invalid_credentials()

        ok, needs_rehash = await self._verify(user.password_hash, password)
        if not ok:
            user.failed_logins += 1
            if user.failed_logins >= self.settings.lockout_threshold:
                user.locked_until = now + self._lock_duration(user.failed_logins)
                await self.audit.record(
                    "auth.account_locked",
                    actor_id=user.id,
                    ctx=ctx,
                    target_type="user",
                    target_id=user.id,
                    metadata={"until": user.locked_until.isoformat()},
                )
            await self._record_failure(user, ctx, "bad_password")
            raise invalid_credentials()

        # Correct password from here on; specific errors no longer leak anything.
        if not user.is_active:
            await self.session.rollback()
            raise ProblemError(
                403, "account_disabled", "Account disabled", "This account has been disabled"
            )
        if self.settings.require_verified_email and not user.is_verified:
            await self.session.rollback()
            raise ProblemError(
                403, "email_not_verified", "Email not verified", "Verify your email address first"
            )

        user.failed_logins = 0
        user.locked_until = None
        if needs_rehash:
            user.password_hash = await self._hash(password)

        if user.mfa_enabled:
            await self.session.commit()
            return MfaChallenge(
                mfa_token=self.keyring.create_mfa_token(
                    user.id, self.settings.mfa_token_ttl_seconds
                ),
                expires_in=self.settings.mfa_token_ttl_seconds,
            )

        pair, _ = await self.tokens.issue_pair(user, ctx)
        await self.audit.record(
            "auth.login", actor_id=user.id, ctx=ctx, target_type="user", target_id=user.id
        )
        await self.session.commit()
        metrics.LOGIN_SUCCESS.inc()
        return pair

    # ------------------------------------------------------------------ logout
    async def logout(self, claims: AccessClaims, ctx: RequestContext) -> None:
        await self.tokens.revoke_session(claims.sub, claims.sid)
        await self.tokens.deny_access_token(claims)
        await self.audit.record(
            "auth.logout",
            actor_id=claims.sub,
            ctx=ctx,
            target_type="refresh_family",
            target_id=claims.sid,
        )
        await self.session.commit()

    async def logout_all(self, claims: AccessClaims, ctx: RequestContext) -> None:
        count = await self.tokens.revoke_all(claims.sub)
        await self.tokens.deny_access_token(claims)
        await self.audit.record(
            "auth.logout_all",
            actor_id=claims.sub,
            ctx=ctx,
            target_type="user",
            target_id=claims.sub,
            metadata={"revoked_tokens": count},
        )
        await self.session.commit()

    # ------------------------------------------------------------------ passwords
    async def forgot_password(self, email: str, ctx: RequestContext) -> Email | None:
        user = await self.users.get_by_email(email)
        if user is None or not user.is_active:
            return None
        raw = await self._new_one_time_token(
            user, RESET_PASSWORD, timedelta(minutes=self.settings.password_reset_ttl_minutes)
        )
        await self.audit.record(
            "auth.password_reset_requested",
            actor_id=user.id,
            ctx=ctx,
            target_type="user",
            target_id=user.id,
        )
        await self.session.commit()
        return reset_email(
            user.email,
            self._link("/v1/auth/password/reset", raw),
            self.settings.password_reset_ttl_minutes,
        )

    async def reset_password(self, raw: str, new_password: str, ctx: RequestContext) -> None:
        row = await self._consume_one_time_token(raw, RESET_PASSWORD)
        user = await self.users.get_for_update(row.user_id)
        if user is None or not user.is_active:
            raise invalid_one_time_token()
        self._check_policy(new_password, user.email)
        user.password_hash = await self._hash(new_password)
        user.failed_logins = 0
        user.locked_until = None
        user.is_verified = True  # they proved control of the mailbox
        count = await self.tokens.revoke_all(user.id)
        await self.audit.record(
            "auth.password_reset",
            actor_id=user.id,
            ctx=ctx,
            target_type="user",
            target_id=user.id,
            metadata={"revoked_tokens": count},
        )
        await self.session.commit()

    async def change_password(
        self, claims: AccessClaims, current: str, new: str, ctx: RequestContext
    ) -> TokenPair:
        user = await self.users.get_for_update(claims.sub)
        if user is None or not user.is_active:
            raise ProblemError(401, "not_authenticated", "Authentication required")
        ok, _ = await self._verify(user.password_hash, current)
        if not ok:
            raise ProblemError(400, "invalid_current_password", "Current password is incorrect")
        self._check_policy(new, user.email)
        if current == new:
            raise ProblemError(
                422, "password_unchanged", "New password must differ from the current one"
            )
        user.password_hash = await self._hash(new)
        # Sign out every other session, then hand this client a fresh pair.
        count = await self.tokens.revoke_all(user.id)
        pair, _ = await self.tokens.issue_pair(user, ctx)
        await self.audit.record(
            "auth.password_changed",
            actor_id=user.id,
            ctx=ctx,
            target_type="user",
            target_id=user.id,
            metadata={"revoked_tokens": count},
        )
        await self.session.commit()
        return pair

    # ------------------------------------------------------------------ MFA (TOTP)
    def _mfa_available(self) -> None:
        if self.settings.is_production_like and self.settings.mfa_encryption_key is None:
            raise ProblemError(404, "feature_disabled", "Feature disabled", "MFA is not configured")

    async def mfa_enroll(self, claims: AccessClaims) -> tuple[str, str]:
        self._mfa_available()
        user = await self.users.get_for_update(claims.sub)
        if user is None:
            raise ProblemError(401, "not_authenticated", "Authentication required")
        if user.mfa_enabled:
            raise ProblemError(409, "mfa_already_enabled", "MFA is already enabled")
        secret = pyotp.random_base32()
        user.mfa_secret_enc = self.secret_box.encrypt(secret)
        await self.session.commit()
        uri = pyotp.TOTP(secret).provisioning_uri(
            name=user.email, issuer_name=self.settings.mfa_issuer
        )
        return secret, uri

    async def _check_totp(self, user: User, code: str) -> bool:
        if not user.mfa_secret_enc:
            return False
        secret = self.secret_box.decrypt(user.mfa_secret_enc)
        if secret is None or not pyotp.TOTP(secret).verify(code, valid_window=1):
            return False
        # Each code works once (replay protection across its 90 s validity).
        return bool(await self.redis.set(f"mfa_used:{user.id}:{code}", "1", ex=90, nx=True))

    async def mfa_verify(self, claims: AccessClaims, code: str, ctx: RequestContext) -> None:
        self._mfa_available()
        user = await self.users.get_for_update(claims.sub)
        if user is None:
            raise ProblemError(401, "not_authenticated", "Authentication required")
        if not user.mfa_secret_enc:
            raise ProblemError(409, "mfa_not_enrolled", "Start MFA enrollment first")
        if not await self._check_totp(user, code):
            raise ProblemError(400, "invalid_mfa_code", "Invalid MFA code")
        user.mfa_enabled = True
        await self.audit.record(
            "auth.mfa_enabled", actor_id=user.id, ctx=ctx, target_type="user", target_id=user.id
        )
        await self.session.commit()

    async def mfa_disable(self, claims: AccessClaims, code: str, ctx: RequestContext) -> None:
        user = await self.users.get_for_update(claims.sub)
        if user is None:
            raise ProblemError(401, "not_authenticated", "Authentication required")
        if not user.mfa_enabled:
            raise ProblemError(409, "mfa_not_enrolled", "MFA is not enabled")
        if not await self._check_totp(user, code):
            raise ProblemError(400, "invalid_mfa_code", "Invalid MFA code")
        user.mfa_enabled = False
        user.mfa_secret_enc = None
        await self.audit.record(
            "auth.mfa_disabled", actor_id=user.id, ctx=ctx, target_type="user", target_id=user.id
        )
        await self.session.commit()

    async def login_mfa(self, mfa_token: str, code: str, ctx: RequestContext) -> TokenPair:
        try:
            user_id = self.keyring.decode_mfa_token(mfa_token)
        except TokenError as exc:
            raise ProblemError(
                401, "invalid_mfa_token", "MFA session expired; sign in again"
            ) from exc
        user = await self.users.get_for_update(user_id)
        if user is None or not user.is_active or not user.mfa_enabled:
            raise ProblemError(401, "invalid_mfa_token", "MFA session expired; sign in again")
        if not await self._check_totp(user, code):
            metrics.LOGIN_FAILURES.labels(reason="bad_mfa_code").inc()
            await self.audit.record(
                "auth.mfa_failed", actor_id=user.id, ctx=ctx, target_type="user", target_id=user.id
            )
            await self.session.commit()
            raise ProblemError(401, "invalid_mfa_code", "Invalid MFA code")
        pair, _ = await self.tokens.issue_pair(user, ctx)
        await self.audit.record(
            "auth.login",
            actor_id=user.id,
            ctx=ctx,
            target_type="user",
            target_id=user.id,
            metadata={"mfa": True},
        )
        await self.session.commit()
        metrics.LOGIN_SUCCESS.inc()
        return pair

    # ------------------------------------------------------------------ external identity (Google)
    async def login_external(
        self, email: str, full_name: str | None, provider: str, ctx: RequestContext
    ) -> TokenPair:
        user = await self.users.get_by_email(email)
        if user is None:
            roles = await self.roles.by_names([DEFAULT_ROLE])
            user = await self.users.add(
                User(
                    email=email,
                    password_hash=UNUSABLE_PASSWORD,
                    full_name=full_name,
                    is_verified=True,
                    roles=roles,
                )
            )
            await self.audit.record(
                "user.register",
                actor_id=user.id,
                ctx=ctx,
                target_type="user",
                target_id=user.id,
                metadata={"provider": provider},
            )
        elif not user.is_active:
            raise ProblemError(
                403, "account_disabled", "Account disabled", "This account has been disabled"
            )
        else:
            user.is_verified = True
        pair, _ = await self.tokens.issue_pair(user, ctx)
        await self.audit.record(
            "auth.login",
            actor_id=user.id,
            ctx=ctx,
            target_type="user",
            target_id=user.id,
            metadata={"provider": provider},
        )
        await self.session.commit()
        metrics.LOGIN_SUCCESS.inc()
        return pair
