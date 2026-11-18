"""Seed roles and permissions (frozen copy; later changes get their own migration).

Revision ID: 0002
Revises: 0001
Create Date: 2026-11-18
"""

import uuid
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0002"
down_revision: str | None = "0001"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

PERMISSIONS = {
    "project:read": "Read own projects",
    "project:write": "Create, update and delete own projects",
    "user:manage": "List, inspect, disable users and change their roles",
    "audit:read": "Read the audit log",
}
ROLES = {
    "user": ["project:read", "project:write"],
    "auditor": ["project:read", "audit:read"],
    "admin": ["project:read", "project:write", "user:manage", "audit:read"],
}

permissions_t = sa.table(
    "permissions", sa.column("id", sa.Uuid()), sa.column("code", sa.String), sa.column("description", sa.String)
)
roles_t = sa.table(
    "roles", sa.column("id", sa.Uuid()), sa.column("name", sa.String), sa.column("description", sa.String)
)
role_permissions_t = sa.table(
    "role_permissions", sa.column("role_id", sa.Uuid()), sa.column("permission_id", sa.Uuid())
)


def upgrade() -> None:
    perm_ids = {code: uuid.uuid4() for code in PERMISSIONS}
    role_ids = {name: uuid.uuid4() for name in ROLES}
    op.bulk_insert(
        permissions_t,
        [{"id": perm_ids[c], "code": c, "description": d} for c, d in PERMISSIONS.items()],
    )
    op.bulk_insert(
        roles_t, [{"id": role_ids[n], "name": n, "description": f"{n} role"} for n in ROLES]
    )
    op.bulk_insert(
        role_permissions_t,
        [
            {"role_id": role_ids[n], "permission_id": perm_ids[c]}
            for n, codes in ROLES.items()
            for c in codes
        ],
    )


def downgrade() -> None:
    op.execute(
        roles_t.delete().where(roles_t.c.name.in_(list(ROLES)))
    )
    op.execute(
        permissions_t.delete().where(permissions_t.c.code.in_(list(PERMISSIONS)))
    )
