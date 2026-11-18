from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, BackgroundTasks, Depends, Query, Request, Response, status
from fastapi.responses import RedirectResponse

from app.api.deps import (
    AuthServiceDep,
    ClaimsDep,
    ContainerDep,
    CtxDep,
    TokenServiceDep,
    WritableClaimsDep,
    enforce_rate_limit,
    hashed_identifier,
    ip_rate_limit,
)
from app.core.config import Settings
from app.core.errors import ProblemError
from app.schemas import (
    ChangePasswordRequest,
    ForgotPasswordRequest,
    LoginMfaRequest,
    LoginRequest,
    Message,
    MfaChallenge,
    MfaCodeRequest,
    MfaEnrollResponse,
    OAuthStartResponse,
    OneTimeTokenRequest,
    RefreshRequest,
    RegisterRequest,
    ResetPasswordRequest,
    TokenPair,
    problem_responses,
)
from app.services.email_service import Email
from app.services.oauth_service import GoogleOAuthService

router = APIRouter(prefix="/v1/auth", tags=["auth"])

P400 = problem_responses(400)
P401 = problem_responses(401)
P403 = problem_responses(403)
P422 = problem_responses(422)
P429 = problem_responses(429)


def _set_refresh_cookie(response: Response, settings: Settings, pair: TokenPair) -> None:
    response.set_cookie(
        settings.refresh_cookie_name,
        pair.refresh_token,
        max_age=pair.refresh_expires_in,
        path=settings.refresh_cookie_path,
        httponly=True,
        secure=settings.refresh_cookie_secure,
        samesite="strict",
    )


def _send_later(background: BackgroundTasks, container: ContainerDep, email: Email | None) -> None:
    if email is not None:
        background.add_task(container.email.send, email)


# ---------------------------------------------------------------- registration
@router.post(
    "/register",
    status_code=status.HTTP_202_ACCEPTED,
    response_model=Message,
    dependencies=[
        Depends(ip_rate_limit("register", "register_rate_limit", "register_rate_window_seconds"))
    ],
    responses={**P422, **P429},
    summary="Create an account and send a verification email",
)
async def register(
    body: RegisterRequest,
    svc: AuthServiceDep,
    ctx: CtxDep,
    container: ContainerDep,
    background: BackgroundTasks,
) -> Message:
    """Answers 202 whether or not the email is already registered, so the endpoint
    cannot be used to discover accounts. The existing owner gets a warning email."""
    email = await svc.register(body.email, body.password, body.full_name, ctx)
    _send_later(background, container, email)
    return Message(message="Check your inbox to verify your email address")


@router.post(
    "/verify-email", response_model=Message, responses=P400, summary="Mark the email as verified"
)
async def verify_email(body: OneTimeTokenRequest, svc: AuthServiceDep, ctx: CtxDep) -> Message:
    await svc.verify_email(body.token, ctx)
    return Message(message="Email verified")


# ---------------------------------------------------------------- login / refresh / logout
@router.post(
    "/login",
    response_model=TokenPair | MfaChallenge,
    dependencies=[
        Depends(
            ip_rate_limit(
                "login", "login_rate_limit", "login_rate_window_seconds", fail_closed=True
            )
        )
    ],
    responses={**P401, **P403, **P429},
    summary="Exchange email and password for an access and refresh token",
)
async def login(
    body: LoginRequest,
    svc: AuthServiceDep,
    ctx: CtxDep,
    container: ContainerDep,
    response: Response,
) -> TokenPair | MfaChallenge:
    s = container.settings
    # Per-account attempt limit (covers unknown emails too, without revealing which exist).
    await enforce_rate_limit(
        container,
        "login_email",
        hashed_identifier(body.email),
        s.login_rate_limit,
        s.login_rate_window_seconds,
        fail_closed=True,
    )
    # Too many failures from this IP across accounts (credential stuffing).
    ip = ctx.ip or "unknown"
    if s.rate_limit_enabled:
        failures = await container.limiter.peek(
            "login_fail_ip", ip, s.login_ip_failure_limit, s.login_ip_failure_window_seconds
        )
        if not failures.allowed:
            raise ProblemError(
                429,
                "rate_limited",
                "Too many requests",
                headers={"Retry-After": str(failures.retry_after_seconds)},
            )
    try:
        result = await svc.login(body.email, body.password, ctx)
    except ProblemError as exc:
        if exc.code == "invalid_credentials" and s.rate_limit_enabled:
            await container.limiter.hit(
                "login_fail_ip", ip, s.login_ip_failure_limit, s.login_ip_failure_window_seconds
            )
        raise
    if isinstance(result, MfaChallenge):
        return result  # second factor required
    _set_refresh_cookie(response, s, result)
    return result


@router.post(
    "/login/mfa",
    response_model=TokenPair,
    dependencies=[
        Depends(
            ip_rate_limit(
                "login", "login_rate_limit", "login_rate_window_seconds", fail_closed=True
            )
        )
    ],
    responses={**P401, **P429},
    summary="Second login step when TOTP MFA is enabled",
)
async def login_mfa(
    body: LoginMfaRequest,
    svc: AuthServiceDep,
    ctx: CtxDep,
    container: ContainerDep,
    response: Response,
) -> TokenPair:
    pair = await svc.login_mfa(body.mfa_token, body.code, ctx)
    _set_refresh_cookie(response, container.settings, pair)
    return pair


@router.post(
    "/refresh", response_model=TokenPair, responses=P401, summary="Rotate the refresh token"
)
async def refresh(
    tokens: TokenServiceDep,
    ctx: CtxDep,
    container: ContainerDep,
    response: Response,
    request: Request,
    body: RefreshRequest | None = None,
) -> TokenPair:
    raw = (body.refresh_token if body else None) or request.cookies.get(
        container.settings.refresh_cookie_name
    )
    if not raw:
        raise ProblemError(
            401, "invalid_refresh_token", "Invalid refresh token", "No refresh token supplied"
        )
    pair = await tokens.rotate(raw, ctx)
    _set_refresh_cookie(response, container.settings, pair)
    return pair


@router.post(
    "/logout",
    status_code=status.HTTP_204_NO_CONTENT,
    response_class=Response,
    responses=P401,
    summary="Revoke this session and denylist the access token",
)
async def logout(
    claims: ClaimsDep, svc: AuthServiceDep, ctx: CtxDep, container: ContainerDep
) -> Response:
    await svc.logout(claims, ctx)
    response = Response(status_code=status.HTTP_204_NO_CONTENT)
    response.delete_cookie(
        container.settings.refresh_cookie_name, path=container.settings.refresh_cookie_path
    )
    return response


@router.post(
    "/logout-all",
    status_code=status.HTTP_204_NO_CONTENT,
    response_class=Response,
    responses=P401,
    summary="Revoke every session for this user",
)
async def logout_all(
    claims: ClaimsDep, svc: AuthServiceDep, ctx: CtxDep, container: ContainerDep
) -> Response:
    await svc.logout_all(claims, ctx)
    response = Response(status_code=status.HTTP_204_NO_CONTENT)
    response.delete_cookie(
        container.settings.refresh_cookie_name, path=container.settings.refresh_cookie_path
    )
    return response


# ---------------------------------------------------------------- passwords
@router.post(
    "/password/forgot",
    status_code=status.HTTP_202_ACCEPTED,
    response_model=Message,
    dependencies=[
        Depends(ip_rate_limit("forgot", "forgot_rate_limit", "forgot_rate_window_seconds"))
    ],
    responses={**P422, **P429},
    summary="Send a password-reset link (always answers 202)",
)
async def forgot_password(
    body: ForgotPasswordRequest,
    svc: AuthServiceDep,
    ctx: CtxDep,
    container: ContainerDep,
    background: BackgroundTasks,
) -> Message:
    s = container.settings
    await enforce_rate_limit(
        container,
        "forgot_email",
        hashed_identifier(body.email),
        s.forgot_rate_limit,
        s.forgot_rate_window_seconds,
        fail_closed=False,
    )
    _send_later(background, container, await svc.forgot_password(body.email, ctx))
    return Message(message="If that account exists, a reset link is on its way")


@router.post(
    "/password/reset",
    response_model=Message,
    responses={**P400, **P422},
    summary="Set a new password with a reset token; revokes every session",
)
async def reset_password(body: ResetPasswordRequest, svc: AuthServiceDep, ctx: CtxDep) -> Message:
    await svc.reset_password(body.token, body.new_password, ctx)
    return Message(message="Password updated; sign in again")


@router.post(
    "/password/change",
    response_model=TokenPair,
    responses={**P400, **P401, **P422},
    summary="Change password; signs out other sessions and returns a fresh token pair",
)
async def change_password(
    body: ChangePasswordRequest,
    claims: WritableClaimsDep,
    svc: AuthServiceDep,
    ctx: CtxDep,
    container: ContainerDep,
    response: Response,
) -> TokenPair:
    pair = await svc.change_password(claims, body.current_password, body.new_password, ctx)
    _set_refresh_cookie(response, container.settings, pair)
    return pair


# ---------------------------------------------------------------- MFA (stretch)
@router.post(
    "/mfa/enroll",
    response_model=MfaEnrollResponse,
    responses={**P401, **problem_responses(409)},
    summary="Start TOTP enrollment",
)
async def mfa_enroll(claims: WritableClaimsDep, svc: AuthServiceDep) -> MfaEnrollResponse:
    secret, uri = await svc.mfa_enroll(claims)
    return MfaEnrollResponse(secret=secret, otpauth_uri=uri)


@router.post(
    "/mfa/verify",
    response_model=Message,
    responses={**P400, **P401},
    summary="Confirm TOTP enrollment with a code from the authenticator app",
)
async def mfa_verify(
    body: MfaCodeRequest, claims: WritableClaimsDep, svc: AuthServiceDep, ctx: CtxDep
) -> Message:
    await svc.mfa_verify(claims, body.code, ctx)
    return Message(message="MFA enabled")


@router.post(
    "/mfa/disable", response_model=Message, responses={**P400, **P401}, summary="Turn TOTP MFA off"
)
async def mfa_disable(
    body: MfaCodeRequest, claims: WritableClaimsDep, svc: AuthServiceDep, ctx: CtxDep
) -> Message:
    await svc.mfa_disable(claims, body.code, ctx)
    return Message(message="MFA disabled")


# ---------------------------------------------------------------- Google sign-in (stretch)
@router.get(
    "/oauth/google/authorize",
    response_model=OAuthStartResponse,
    responses=problem_responses(404),
    summary="Start Google sign-in (OAuth 2.0 + PKCE)",
)
async def google_authorize(
    container: ContainerDep, redirect: Annotated[bool, Query()] = False
) -> Any:
    url, state = await GoogleOAuthService(container.settings, container.redis).start()
    if redirect:
        return RedirectResponse(url, status_code=status.HTTP_302_FOUND)
    return OAuthStartResponse(authorization_url=url, state=state)


@router.get(
    "/oauth/google/callback",
    response_model=TokenPair,
    responses={**P400, **problem_responses(404)},
    summary="Google redirects here; returns a token pair",
)
async def google_callback(
    code: Annotated[str, Query(max_length=2048)],
    state: Annotated[str, Query(max_length=256)],
    svc: AuthServiceDep,
    ctx: CtxDep,
    container: ContainerDep,
    response: Response,
) -> TokenPair:
    identity = await GoogleOAuthService(container.settings, container.redis).complete(code, state)
    pair = await svc.login_external(identity.email, identity.name, "google", ctx)
    _set_refresh_cookie(response, container.settings, pair)
    return pair
