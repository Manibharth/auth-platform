"""FastAPI dependencies: database session, current principal, permissions, rate limits."""

from __future__ import annotations

import hashlib
from collections.abc import AsyncIterator, Awaitable, Callable
from typing import Annotated

import structlog
from fastapi import Depends, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from redis.exceptions import RedisError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.container import Container
from app.core.errors import (
    ProblemError,
    forbidden,
    not_authenticated,
    rate_limited,
    service_unavailable,
)
from app.core.security import AccessClaims, TokenError
from app.services import RequestContext
from app.services.auth_service import AuthService
from app.services.project_service import ProjectService
from app.services.rbac_service import RbacService
from app.services.token_service import RevocationStore, TokenService
from app.services.user_service import UserService

log = structlog.get_logger(__name__)

bearer_scheme = HTTPBearer(auto_error=False, description="Access token from /v1/auth/login")


def get_container(request: Request) -> Container:
    container: Container = request.app.state.container
    return container


ContainerDep = Annotated[Container, Depends(get_container)]


async def get_db(container: ContainerDep) -> AsyncIterator[AsyncSession]:
    async with container.sessionmaker() as session:
        try:
            yield session
        finally:
            if session.in_transaction():
                await session.rollback()


DbDep = Annotated[AsyncSession, Depends(get_db)]


def get_request_context(request: Request) -> RequestContext:
    return RequestContext(
        ip=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent"),
    )


CtxDep = Annotated[RequestContext, Depends(get_request_context)]


# ---------------------------------------------------------------- authentication
async def get_claims(
    container: ContainerDep,
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer_scheme)],
) -> AccessClaims:
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise not_authenticated("Missing bearer token")
    try:
        claims = container.keyring.decode_access_token(credentials.credentials)
    except TokenError as exc:
        log.info("token_rejected", reason=str(exc))
        raise not_authenticated() from exc
    if await RevocationStore(container.redis, container.settings).is_revoked(claims):
        raise not_authenticated("Token has been revoked")
    return claims


ClaimsDep = Annotated[AccessClaims, Depends(get_claims)]


def require_permission(permission: str) -> Callable[..., Awaitable[AccessClaims]]:
    """Reject the request before the route runs unless the caller holds `permission`."""

    async def _dependency(claims: ClaimsDep, db: DbDep, container: ContainerDep) -> AccessClaims:
        rbac = RbacService(db, container.permission_cache)
        if not await rbac.has_permission(claims.sub, claims.roles, permission):
            raise forbidden(f"Requires permission {permission}")
        return claims

    _dependency.__name__ = f"require_{permission.replace(':', '_')}"
    return _dependency


async def writable_claims(claims: ClaimsDep) -> AccessClaims:
    """The public demo account is read-only in production."""
    if claims.demo:
        raise ProblemError(403, "demo_read_only", "Demo account is read-only")
    return claims


WritableClaimsDep = Annotated[AccessClaims, Depends(writable_claims)]


# ---------------------------------------------------------------- rate limiting
async def enforce_rate_limit(
    container: Container,
    scope: str,
    identifier: str,
    limit: int,
    window_seconds: int,
    *,
    fail_closed: bool,
) -> None:
    if not container.settings.rate_limit_enabled:
        return
    try:
        result = await container.limiter.hit(scope, identifier, limit, window_seconds)
    except RedisError as exc:
        log.error("rate_limiter_unavailable", scope=scope)
        if fail_closed:
            raise service_unavailable("Sign-in is temporarily unavailable") from exc
        return
    if not result.allowed:
        raise rate_limited(result.retry_after_seconds)


def hashed_identifier(value: str) -> str:
    """Keep raw emails out of Redis keys."""
    return hashlib.sha256(value.strip().lower().encode()).hexdigest()[:32]


def ip_rate_limit(
    scope: str, limit_attr: str, window_attr: str, *, fail_closed: bool = False
) -> Callable[..., Awaitable[None]]:
    async def _dependency(container: ContainerDep, ctx: CtxDep) -> None:
        s = container.settings
        await enforce_rate_limit(
            container,
            scope,
            ctx.ip or "unknown",
            getattr(s, limit_attr),
            getattr(s, window_attr),
            fail_closed=fail_closed,
        )

    _dependency.__name__ = f"rate_limit_{scope}"
    return _dependency


# ---------------------------------------------------------------- services
def get_auth_service(db: DbDep, c: ContainerDep) -> AuthService:
    return AuthService(
        db,
        settings=c.settings,
        hasher=c.hasher,
        keyring=c.keyring,
        redis=c.redis,
        secret_box=c.secret_box,
    )


def get_token_service(db: DbDep, c: ContainerDep) -> TokenService:
    return TokenService(db, c.keyring, c.redis, c.settings)


def get_user_service(db: DbDep, c: ContainerDep) -> UserService:
    return UserService(db, settings=c.settings, keyring=c.keyring, redis=c.redis)


def get_project_service(db: DbDep, c: ContainerDep) -> ProjectService:
    return ProjectService(db, settings=c.settings, cache=c.permission_cache)


AuthServiceDep = Annotated[AuthService, Depends(get_auth_service)]
TokenServiceDep = Annotated[TokenService, Depends(get_token_service)]
UserServiceDep = Annotated[UserService, Depends(get_user_service)]
ProjectServiceDep = Annotated[ProjectService, Depends(get_project_service)]
