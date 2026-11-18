"""Seed data: roles, permissions, and optional demo accounts. Idempotent."""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import PasswordHasher
from app.models import Permission, Project, Role, User

PERMISSIONS: dict[str, str] = {
    "project:read": "Read own projects",
    "project:write": "Create, update and delete own projects",
    "user:manage": "List, inspect, disable users and change their roles",
    "audit:read": "Read the audit log",
}

ROLE_PERMISSIONS: dict[str, list[str]] = {
    "user": ["project:read", "project:write"],
    "auditor": ["project:read", "audit:read"],
    "admin": ["project:read", "project:write", "user:manage", "audit:read"],
}

DEFAULT_ROLE = "user"


async def ensure_roles(session: AsyncSession) -> dict[str, Role]:
    perms = {p.code: p for p in (await session.scalars(select(Permission))).all()}
    for code, desc in PERMISSIONS.items():
        if code not in perms:
            perms[code] = Permission(code=code, description=desc)
            session.add(perms[code])
    roles = {r.name: r for r in (await session.scalars(select(Role))).all()}
    for name, codes in ROLE_PERMISSIONS.items():
        role = roles.get(name)
        if role is None:
            role = Role(name=name, description=f"{name} role", permissions=[])
            session.add(role)
            roles[name] = role
        role.permissions = [perms[c] for c in codes]
    await session.flush()
    return roles


async def ensure_user(
    session: AsyncSession,
    hasher: PasswordHasher,
    email: str,
    password: str,
    role_names: list[str],
    full_name: str | None = None,
) -> User:
    roles = await ensure_roles(session)
    user = await session.scalar(select(User).where(User.email == email))
    if user is None:
        user = User(
            email=email,
            password_hash=hasher.hash(password),
            full_name=full_name,
            is_verified=True,
            roles=[roles[n] for n in role_names],
        )
        session.add(user)
    else:
        user.password_hash = hasher.hash(password)
        user.roles = [roles[n] for n in role_names]
        user.is_active = True
        user.is_verified = True
        user.deleted_at = None
        user.failed_logins = 0
        user.locked_until = None
    await session.flush()
    return user


async def ensure_demo_projects(session: AsyncSession, owner: User) -> None:
    existing = await session.scalar(select(Project).where(Project.owner_id == owner.id).limit(1))
    if existing is not None:
        return
    for i, (name, desc) in enumerate(
        [
            ("Payments gateway", "PCI-scoped service behind the API gateway"),
            ("Mobile app backend", "BFF for iOS and Android clients"),
            ("Data platform", "Batch and streaming pipelines"),
        ]
    ):
        session.add(Project(owner_id=owner.id, name=f"{i + 1}. {name}", description=desc))
    await session.flush()
