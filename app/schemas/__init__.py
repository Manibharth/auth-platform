"""Pydantic v2 request and response models."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, EmailStr, Field, StringConstraints, field_validator

Password = Annotated[str, Field(min_length=1, max_length=256)]
Token = Annotated[
    str, StringConstraints(min_length=16, max_length=512, pattern=r"^[A-Za-z0-9_\-]+$")
]
TotpCode = Annotated[str, StringConstraints(pattern=r"^\d{6}$")]
Name = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=200)]


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


# ====================================================================== common
class Message(BaseModel):
    message: str


class Page[T](BaseModel):
    items: list[T]
    next_cursor: str | None = Field(
        None, description="Opaque cursor; pass as ?cursor= to fetch the next page"
    )


class Problem(BaseModel):
    """RFC 9457 problem details."""

    type: str
    title: str
    status: int
    code: str
    detail: str | None = None
    instance: str | None = None
    request_id: str | None = None


# ====================================================================== auth
class RegisterRequest(StrictModel):
    email: EmailStr
    password: Password
    full_name: Name | None = None


class LoginRequest(StrictModel):
    email: EmailStr
    password: Password


class TokenPair(BaseModel):
    token_type: Literal["Bearer"] = "Bearer"  # noqa: S105 - scheme name
    access_token: str
    expires_in: int = Field(description="Access-token lifetime in seconds")
    refresh_token: str
    refresh_expires_in: int


class MfaChallenge(BaseModel):
    mfa_required: Literal[True] = True
    mfa_token: str
    expires_in: int


class LoginMfaRequest(StrictModel):
    mfa_token: Annotated[str, StringConstraints(min_length=16, max_length=4096)]
    code: TotpCode


class RefreshRequest(StrictModel):
    refresh_token: Token | None = Field(
        None, description="Omit to use the httpOnly refresh cookie instead"
    )


class OneTimeTokenRequest(StrictModel):
    token: Token


class ForgotPasswordRequest(StrictModel):
    email: EmailStr


class ResetPasswordRequest(StrictModel):
    token: Token
    new_password: Password


class ChangePasswordRequest(StrictModel):
    current_password: Password
    new_password: Password


class MfaEnrollResponse(BaseModel):
    secret: str
    otpauth_uri: str


class MfaCodeRequest(StrictModel):
    code: TotpCode


class OAuthStartResponse(BaseModel):
    authorization_url: str
    state: str


# ====================================================================== users
class UserOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    email: EmailStr
    full_name: str | None
    is_verified: bool
    mfa_enabled: bool
    roles: list[str]
    created_at: datetime


class AdminUserOut(UserOut):
    is_active: bool
    failed_logins: int
    locked_until: datetime | None
    updated_at: datetime


class UpdateMeRequest(StrictModel):
    full_name: Name | None = None


class UpdateRolesRequest(StrictModel):
    roles: Annotated[
        list[Annotated[str, StringConstraints(max_length=50)]], Field(min_length=1, max_length=10)
    ]


# ====================================================================== projects
class ProjectCreate(StrictModel):
    name: Name
    description: Annotated[str, StringConstraints(max_length=5000)] | None = None


class ProjectUpdate(StrictModel):
    name: Name | None = None
    description: Annotated[str, StringConstraints(max_length=5000)] | None = None


class ProjectOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    owner_id: uuid.UUID
    name: str
    description: str | None
    created_at: datetime
    updated_at: datetime


# ====================================================================== audit
class AuditEntryOut(BaseModel):
    model_config = ConfigDict(from_attributes=True, populate_by_name=True)

    id: uuid.UUID
    actor_id: uuid.UUID | None
    action: str
    target_type: str | None
    target_id: str | None
    ip: str | None
    metadata: dict[str, Any] = Field(validation_alias="metadata_")
    created_at: datetime

    @field_validator("ip", mode="before")
    @classmethod
    def _ip_to_str(cls, value: object) -> str | None:
        return None if value is None else str(value)


# ====================================================================== ops
class Health(BaseModel):
    status: Literal["ok"] = "ok"


class Readiness(BaseModel):
    status: Literal["ready", "unavailable"]
    checks: dict[str, str]


# ====================================================================== OpenAPI helpers
ResponsesDoc = dict[int | str, dict[str, Any]]


def problem_responses(*statuses: int) -> ResponsesDoc:
    """Document problem-details error responses for a route."""
    return {status: {"model": Problem} for status in statuses}
