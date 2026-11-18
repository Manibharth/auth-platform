"""RFC 9457 problem details with stable error codes."""

from __future__ import annotations

from typing import Any

import structlog
from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.core.logging import request_id_ctx

PROBLEM_JSON = "application/problem+json"
PROBLEM_TYPE_BASE = "https://auth-platform.dev/problems/"

log = structlog.get_logger(__name__)

_DEFAULT_TITLES: dict[int, tuple[str, str]] = {
    400: ("bad_request", "Bad request"),
    401: ("not_authenticated", "Authentication required"),
    403: ("forbidden", "Forbidden"),
    404: ("not_found", "Not found"),
    405: ("method_not_allowed", "Method not allowed"),
    409: ("conflict", "Conflict"),
    415: ("unsupported_media_type", "Unsupported media type"),
    422: ("validation_error", "Request validation failed"),
    429: ("rate_limited", "Too many requests"),
    503: ("service_unavailable", "Service unavailable"),
}


class ProblemError(Exception):
    """Raise anywhere below the router to return a problem-details response."""

    def __init__(
        self,
        status: int,
        code: str,
        title: str,
        detail: str | None = None,
        *,
        headers: dict[str, str] | None = None,
        extra: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(detail or title)
        self.status = status
        self.code = code
        self.title = title
        self.detail = detail
        self.headers = headers or {}
        self.extra = extra or {}


# ---------------------------------------------------------------- common errors
def not_authenticated(detail: str = "Missing or invalid access token") -> ProblemError:
    return ProblemError(
        401,
        "not_authenticated",
        "Authentication required",
        detail,
        headers={"WWW-Authenticate": 'Bearer error="invalid_token"'},
    )


def forbidden(detail: str = "You do not have permission to perform this action") -> ProblemError:
    return ProblemError(403, "forbidden", "Forbidden", detail)


def not_found(resource: str = "Resource") -> ProblemError:
    return ProblemError(404, "not_found", "Not found", f"{resource} not found")


def rate_limited(retry_after: int) -> ProblemError:
    return ProblemError(
        429,
        "rate_limited",
        "Too many requests",
        "Rate limit exceeded; retry later",
        headers={"Retry-After": str(max(1, retry_after))},
    )


def service_unavailable(detail: str) -> ProblemError:
    return ProblemError(503, "service_unavailable", "Service unavailable", detail)


def problem_response(
    request: Request,
    status: int,
    code: str,
    title: str,
    detail: str | None = None,
    headers: dict[str, str] | None = None,
    extra: dict[str, Any] | None = None,
) -> JSONResponse:
    body: dict[str, Any] = {
        "type": PROBLEM_TYPE_BASE + code,
        "title": title,
        "status": status,
        "code": code,
        "instance": request.url.path,
    }
    if detail:
        body["detail"] = detail
    rid = request_id_ctx.get()
    if rid:
        body["request_id"] = rid
    if extra:
        body.update(extra)
    return JSONResponse(body, status_code=status, headers=headers, media_type=PROBLEM_JSON)


def _clean_validation_errors(exc: RequestValidationError) -> list[dict[str, Any]]:
    # Never echo submitted values back (they may contain passwords).
    return [
        {"loc": list(err.get("loc", ())), "msg": err.get("msg", ""), "type": err.get("type", "")}
        for err in exc.errors()
    ]


def install_exception_handlers(app: FastAPI) -> None:
    @app.exception_handler(ProblemError)
    async def _problem(request: Request, exc: ProblemError) -> JSONResponse:
        return problem_response(
            request, exc.status, exc.code, exc.title, exc.detail, exc.headers, exc.extra
        )

    @app.exception_handler(RequestValidationError)
    async def _validation(request: Request, exc: RequestValidationError) -> JSONResponse:
        return problem_response(
            request,
            422,
            "validation_error",
            "Request validation failed",
            "One or more fields are invalid",
            extra={"errors": _clean_validation_errors(exc)},
        )

    @app.exception_handler(StarletteHTTPException)
    async def _http(request: Request, exc: StarletteHTTPException) -> JSONResponse:
        code, title = _DEFAULT_TITLES.get(exc.status_code, ("http_error", "HTTP error"))
        detail = exc.detail if isinstance(exc.detail, str) else None
        return problem_response(
            request, exc.status_code, code, title, detail, headers=dict(exc.headers or {})
        )

    @app.exception_handler(Exception)
    async def _unhandled(request: Request, exc: Exception) -> JSONResponse:
        log.exception("unhandled_exception", error_type=type(exc).__name__)
        return problem_response(
            request, 500, "internal_error", "Internal server error", "An unexpected error occurred"
        )
