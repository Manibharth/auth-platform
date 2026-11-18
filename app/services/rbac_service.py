"""Roles and permissions.

Ordinary routes trust the roles inside the access token (at most 15 minutes
stale). Admin permissions are re-read from the database on every request, so
a demoted admin loses access immediately.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterable

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.container import PermissionCache
from app.repositories.users import RoleRepository

ADMIN_ROLE = "admin"
# Permissions that are always checked against the database, never the token.
SENSITIVE_PERMISSIONS = frozenset({"user:manage", "audit:read"})


class RbacService:
    def __init__(self, session: AsyncSession, cache: PermissionCache) -> None:
        self.roles = RoleRepository(session)
        self.cache = cache

    async def role_permission_map(self) -> dict[str, frozenset[str]]:
        cached = self.cache.get()
        if cached is not None:
            return cached
        value = await self.roles.role_permission_map()
        self.cache.set(value)
        return value

    async def permissions_for(self, role_names: Iterable[str]) -> frozenset[str]:
        mapping = await self.role_permission_map()
        perms: set[str] = set()
        for name in role_names:
            perms |= mapping.get(name, frozenset())
        return frozenset(perms)

    async def db_roles(self, user_id: uuid.UUID) -> list[str]:
        return await self.roles.role_names_for_user(user_id)

    async def has_permission(
        self, user_id: uuid.UUID, token_roles: Iterable[str], permission: str
    ) -> bool:
        roles = (
            await self.db_roles(user_id)
            if permission in SENSITIVE_PERMISSIONS
            else list(token_roles)
        )
        return permission in await self.permissions_for(roles)

    async def is_admin(self, user_id: uuid.UUID) -> bool:
        return ADMIN_ROLE in await self.db_roles(user_id)
