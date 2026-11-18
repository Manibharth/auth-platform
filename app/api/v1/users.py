from __future__ import annotations

from fastapi import APIRouter, Response, status

from app.api.deps import ClaimsDep, CtxDep, UserServiceDep, WritableClaimsDep
from app.models import User
from app.schemas import Problem, UpdateMeRequest, UserOut

router = APIRouter(prefix="/v1/users", tags=["users"])


def to_user_out(user: User) -> UserOut:
    return UserOut(
        id=user.id,
        email=user.email,
        full_name=user.full_name,
        is_verified=user.is_verified,
        mfa_enabled=user.mfa_enabled,
        roles=user.role_names,
        created_at=user.created_at,
    )


@router.get(
    "/me",
    response_model=UserOut,
    responses={401: {"model": Problem}},
    summary="Current profile and roles",
)
async def get_me(claims: ClaimsDep, svc: UserServiceDep) -> UserOut:
    return to_user_out(await svc.get_active(claims.sub))


@router.patch(
    "/me", response_model=UserOut, responses={401: {"model": Problem}}, summary="Update own profile"
)
async def update_me(
    body: UpdateMeRequest, claims: WritableClaimsDep, svc: UserServiceDep, ctx: CtxDep
) -> UserOut:
    return to_user_out(await svc.update_me(claims.sub, body.full_name, ctx))


@router.delete(
    "/me",
    status_code=status.HTTP_204_NO_CONTENT,
    response_class=Response,
    responses={401: {"model": Problem}},
    summary="Soft-delete own account and revoke every session",
)
async def delete_me(claims: WritableClaimsDep, svc: UserServiceDep, ctx: CtxDep) -> Response:
    await svc.delete_me(claims, ctx)
    return Response(status_code=status.HTTP_204_NO_CONTENT)
