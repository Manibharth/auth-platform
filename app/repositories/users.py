from __future__ import annotations

import uuid
from collections.abc import Sequence
from datetime import datetime

from sqlalchemy import and_, or_, select, tuple_
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import Permission, Role, User, role_permissions, user_roles


def _escape_like(value: str) -> str:
    return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


class UserRepository:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def get(self, user_id: uuid.UUID, *, include_deleted: bool = False) -> User | None:
        stmt = select(User).where(User.id == user_id)
        if not include_deleted:
            stmt = stmt.where(User.deleted_at.is_(None))
        return await self.session.scalar(stmt)

    async def get_for_update(self, user_id: uuid.UUID) -> User | None:
        return await self.session.scalar(
            select(User).where(User.id == user_id, User.deleted_at.is_(None)).with_for_update()
        )

    async def get_by_email(self, email: str, *, include_deleted: bool = False) -> User | None:
        stmt = select(User).where(User.email == email)
        if not include_deleted:
            stmt = stmt.where(User.deleted_at.is_(None))
        return await self.session.scalar(stmt)

    async def add(self, user: User) -> User:
        self.session.add(user)
        await self.session.flush()
        return user

    async def search(
        self,
        *,
        query: str | None,
        is_active: bool | None,
        role: str | None,
        after: tuple[datetime, uuid.UUID] | None,
        limit: int,
    ) -> Sequence[User]:
        stmt = select(User).where(User.deleted_at.is_(None))
        if query:
            pattern = f"%{_escape_like(query)}%"
            stmt = stmt.where(
                or_(
                    User.email.ilike(pattern, escape="\\"),
                    User.full_name.ilike(pattern, escape="\\"),
                )
            )
        if is_active is not None:
            stmt = stmt.where(User.is_active.is_(is_active))
        if role:
            stmt = stmt.where(
                User.id.in_(
                    select(user_roles.c.user_id)
                    .join(Role, Role.id == user_roles.c.role_id)
                    .where(Role.name == role)
                )
            )
        if after is not None:
            stmt = stmt.where(tuple_(User.created_at, User.id) < tuple_(after[0], after[1]))
        stmt = stmt.order_by(User.created_at.desc(), User.id.desc()).limit(limit)
        return (await self.session.scalars(stmt)).all()


class RoleRepository:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def by_names(self, names: Sequence[str]) -> list[Role]:
        return list((await self.session.scalars(select(Role).where(Role.name.in_(names)))).all())

    async def role_permission_map(self) -> dict[str, frozenset[str]]:
        rows = await self.session.execute(
            select(Role.name, Permission.code)
            .select_from(Role)
            .join(role_permissions, role_permissions.c.role_id == Role.id, isouter=True)
            .join(Permission, Permission.id == role_permissions.c.permission_id, isouter=True)
        )
        out: dict[str, set[str]] = {}
        for role_name, code in rows:
            out.setdefault(role_name, set())
            if code:
                out[role_name].add(code)
        return {k: frozenset(v) for k, v in out.items()}

    async def role_names_for_user(self, user_id: uuid.UUID) -> list[str]:
        rows = await self.session.scalars(
            select(Role.name)
            .join(user_roles, user_roles.c.role_id == Role.id)
            .join(User, and_(User.id == user_roles.c.user_id))
            .where(
                user_roles.c.user_id == user_id,
                User.deleted_at.is_(None),
                User.is_active.is_(True),
            )
        )
        return sorted(rows.all())
