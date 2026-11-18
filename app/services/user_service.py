"""Self-service profile and admin user management."""

from __future__ import annotations

import uuid
from collections.abc import Sequence
from datetime import UTC, datetime

from redis.asyncio import Redis
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings
from app.core.errors import ProblemError, not_found
from app.core.security import AccessClaims, KeyRing
from app.models import User
from app.repositories.users import RoleRepository, UserRepository
from app.services import RequestContext
from app.services.audit_service import AuditService
from app.services.pagination import decode_cursor, encode_cursor
from app.services.rbac_service import ADMIN_ROLE
from app.services.token_service import TokenService


class UserService:
    def __init__(
        self, session: AsyncSession, *, settings: Settings, keyring: KeyRing, redis: Redis
    ) -> None:
        self.session = session
        self.users = UserRepository(session)
        self.roles = RoleRepository(session)
        self.audit = AuditService(session)
        self.tokens = TokenService(session, keyring, redis, settings)

    async def get_active(self, user_id: uuid.UUID) -> User:
        user = await self.users.get(user_id)
        if user is None or not user.is_active:
            raise ProblemError(
                401, "not_authenticated", "Authentication required", "Account is not active"
            )
        return user

    async def update_me(
        self, user_id: uuid.UUID, full_name: str | None, ctx: RequestContext
    ) -> User:
        user = await self.users.get_for_update(user_id)
        if user is None or not user.is_active:
            raise ProblemError(401, "not_authenticated", "Authentication required")
        user.full_name = full_name
        await self.audit.record(
            "user.profile_updated", actor_id=user.id, ctx=ctx, target_type="user", target_id=user.id
        )
        await self.session.commit()
        await self.session.refresh(user)
        return user

    async def delete_me(self, claims: AccessClaims, ctx: RequestContext) -> None:
        user = await self.users.get_for_update(claims.sub)
        if user is None:
            raise ProblemError(401, "not_authenticated", "Authentication required")
        now = datetime.now(UTC)
        user.deleted_at = now
        user.is_active = False
        await self.tokens.revoke_all(user.id)
        await self.tokens.deny_access_token(claims)
        await self.audit.record(
            "user.deleted", actor_id=user.id, ctx=ctx, target_type="user", target_id=user.id
        )
        await self.session.commit()

    # ------------------------------------------------------------------ admin
    async def search(
        self,
        *,
        query: str | None,
        is_active: bool | None,
        role: str | None,
        cursor: str | None,
        limit: int,
    ) -> tuple[Sequence[User], str | None]:
        rows = await self.users.search(
            query=query,
            is_active=is_active,
            role=role,
            after=decode_cursor(cursor),
            limit=limit + 1,
        )
        next_cursor = (
            encode_cursor(rows[limit - 1].created_at, rows[limit - 1].id)
            if len(rows) > limit
            else None
        )
        return rows[:limit], next_cursor

    async def get_any(self, user_id: uuid.UUID) -> User:
        user = await self.users.get(user_id)
        if user is None:
            raise not_found("User")
        return user

    async def set_roles(
        self, actor_id: uuid.UUID, target_id: uuid.UUID, role_names: list[str], ctx: RequestContext
    ) -> User:
        wanted = sorted(set(role_names))
        roles = await self.roles.by_names(wanted)
        unknown = sorted(set(wanted) - {r.name for r in roles})
        if unknown:
            raise ProblemError(
                422, "unknown_role", "Unknown role", f"Unknown roles: {', '.join(unknown)}"
            )
        user = await self.users.get_for_update(target_id)
        if user is None:
            raise not_found("User")
        if actor_id == target_id and ADMIN_ROLE not in wanted:
            raise ProblemError(409, "cannot_demote_self", "You cannot remove your own admin role")
        old = user.role_names
        if old == wanted:
            return user
        user.roles = roles
        await self.audit.record(
            "user.roles_changed",
            actor_id=actor_id,
            ctx=ctx,
            target_type="user",
            target_id=user.id,
            metadata={"old": old, "new": wanted},
        )
        await self.session.commit()
        return user

    async def disable(self, actor_id: uuid.UUID, target_id: uuid.UUID, ctx: RequestContext) -> User:
        if actor_id == target_id:
            raise ProblemError(409, "cannot_disable_self", "You cannot disable your own account")
        user = await self.users.get_for_update(target_id)
        if user is None:
            raise not_found("User")
        user.is_active = False
        count = await self.tokens.revoke_all(user.id)
        await self.audit.record(
            "user.disabled",
            actor_id=actor_id,
            ctx=ctx,
            target_type="user",
            target_id=user.id,
            metadata={"revoked_tokens": count},
        )
        await self.session.commit()
        return user
