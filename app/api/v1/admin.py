"""Admin endpoints. Permissions here are re-read from the database on every call."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, Query

from app.api.deps import CtxDep, DbDep, UserServiceDep, require_permission, writable_claims
from app.core.security import AccessClaims
from app.models import User
from app.schemas import (
    AdminUserOut,
    AuditEntryOut,
    Page,
    UpdateRolesRequest,
    problem_responses,
)
from app.services.audit_service import AuditService

router = APIRouter(prefix="/v1/admin", tags=["admin"])

ManageClaims = Annotated[AccessClaims, Depends(require_permission("user:manage"))]
AuditClaims = Annotated[AccessClaims, Depends(require_permission("audit:read"))]
ERRORS = problem_responses(401, 403, 404)


def to_admin_out(user: User) -> AdminUserOut:
    return AdminUserOut(
        id=user.id,
        email=user.email,
        full_name=user.full_name,
        is_verified=user.is_verified,
        mfa_enabled=user.mfa_enabled,
        roles=user.role_names,
        created_at=user.created_at,
        is_active=user.is_active,
        failed_logins=user.failed_logins,
        locked_until=user.locked_until,
        updated_at=user.updated_at,
    )


@router.get(
    "/users", response_model=Page[AdminUserOut], responses=ERRORS, summary="Search and list users"
)
async def list_users(
    _: ManageClaims,
    svc: UserServiceDep,
    q: Annotated[
        str | None, Query(max_length=200, description="Substring of email or name")
    ] = None,
    is_active: bool | None = None,
    role: Annotated[str | None, Query(max_length=50)] = None,
    cursor: Annotated[str | None, Query(max_length=512)] = None,
    limit: Annotated[int, Query(ge=1, le=100)] = 20,
) -> Page[AdminUserOut]:
    rows, next_cursor = await svc.search(
        query=q, is_active=is_active, role=role, cursor=cursor, limit=limit
    )
    return Page[AdminUserOut](items=[to_admin_out(u) for u in rows], next_cursor=next_cursor)


@router.get(
    "/users/{user_id}", response_model=AdminUserOut, responses=ERRORS, summary="Read one user"
)
async def get_user(user_id: uuid.UUID, _: ManageClaims, svc: UserServiceDep) -> AdminUserOut:
    return to_admin_out(await svc.get_any(user_id))


@router.patch(
    "/users/{user_id}/roles",
    response_model=AdminUserOut,
    responses={**ERRORS, **problem_responses(409, 422)},
    dependencies=[Depends(writable_claims)],
    summary="Replace a user's roles (audited)",
)
async def set_roles(
    user_id: uuid.UUID,
    body: UpdateRolesRequest,
    claims: ManageClaims,
    svc: UserServiceDep,
    ctx: CtxDep,
) -> AdminUserOut:
    return to_admin_out(await svc.set_roles(claims.sub, user_id, body.roles, ctx))


@router.post(
    "/users/{user_id}/disable",
    response_model=AdminUserOut,
    responses={**ERRORS, **problem_responses(409)},
    dependencies=[Depends(writable_claims)],
    summary="Disable an account and revoke its sessions",
)
async def disable_user(
    user_id: uuid.UUID, claims: ManageClaims, svc: UserServiceDep, ctx: CtxDep
) -> AdminUserOut:
    return to_admin_out(await svc.disable(claims.sub, user_id, ctx))


@router.get(
    "/audit-log",
    response_model=Page[AuditEntryOut],
    responses=ERRORS,
    summary="Filter the audit log by actor, action, target and date",
)
async def audit_log(
    _: AuditClaims,
    db: DbDep,
    actor_id: uuid.UUID | None = None,
    action: Annotated[str | None, Query(max_length=64)] = None,
    target_id: Annotated[str | None, Query(max_length=64)] = None,
    since: Annotated[datetime | None, Query(alias="from")] = None,
    until: Annotated[datetime | None, Query(alias="to")] = None,
    cursor: Annotated[str | None, Query(max_length=512)] = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
) -> Page[AuditEntryOut]:
    rows, next_cursor = await AuditService(db).search(
        actor_id=actor_id,
        action=action,
        target_id=target_id,
        since=since,
        until=until,
        cursor=cursor,
        limit=limit,
    )
    return Page[AuditEntryOut](
        items=[AuditEntryOut.model_validate(r) for r in rows], next_cursor=next_cursor
    )
