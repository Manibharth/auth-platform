"""Pure-ASGI middleware: request id, access log + metrics, security headers, global rate limit."""

from __future__ import annotations

import re
import time
import uuid
from typing import Any

import structlog
from redis.exceptions import RedisError
from starlette.datastructures import MutableHeaders
from starlette.requests import Request
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from app.core import metrics
from app.core.errors import problem_response
from app.core.logging import request_id_ctx

log = structlog.get_logger("http")

_REQUEST_ID_RE = re.compile(r"^[A-Za-z0-9\-_.]{8,128}$")
_EXEMPT_PATHS = frozenset({"/healthz", "/readyz", "/metrics"})
_DOCS_PATHS = frozenset({"/docs", "/redoc", "/docs/oauth2-redirect"})

API_CSP = "default-src 'none'; frame-ancestors 'none'; base-uri 'none'"
DOCS_CSP = (
    "default-src 'none'; "
    "script-src 'self' https://cdn.jsdelivr.net 'unsafe-inline'; "
    "style-src 'self' https://cdn.jsdelivr.net https://fonts.googleapis.com 'unsafe-inline'; "
    "img-src 'self' data: https://fastapi.tiangolo.com https://cdn.redoc.ly; "
    "font-src https://fonts.gstatic.com; "
    "connect-src 'self'; worker-src blob:; frame-ancestors 'none'; base-uri 'none'"
)


def _route_template(scope: Scope) -> str:
    route = scope.get("route")
    path = getattr(route, "path", None)
    return str(path) if path else "unmatched"


class RequestContextMiddleware:
    """Outermost: assigns a request id, times the request, logs it, records metrics,
    and stamps security headers on every response (including errors)."""

    def __init__(self, app: ASGIApp, *, hsts: bool) -> None:
        self.app = app
        self.hsts = hsts

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        headers = dict(scope.get("headers") or [])
        incoming = headers.get(b"x-request-id", b"").decode("latin-1")
        rid = incoming if _REQUEST_ID_RE.match(incoming) else uuid.uuid4().hex
        token = request_id_ctx.set(rid)
        start = time.perf_counter()
        status_holder: dict[str, int] = {"status": 500}
        path = scope.get("path", "")

        async def send_wrapper(message: Message) -> None:
            if message["type"] == "http.response.start":
                status_holder["status"] = message["status"]
                h = MutableHeaders(scope=message)
                h["X-Request-ID"] = rid
                h["X-Content-Type-Options"] = "nosniff"
                h["Referrer-Policy"] = "no-referrer"
                h["X-Frame-Options"] = "DENY"
                h["Cross-Origin-Opener-Policy"] = "same-origin"
                h["Permissions-Policy"] = "geolocation=(), camera=(), microphone=()"
                h["Content-Security-Policy"] = DOCS_CSP if path in _DOCS_PATHS else API_CSP
                if self.hsts:
                    h["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains"
                if "cache-control" not in h and path.startswith("/v1/"):
                    h["Cache-Control"] = "no-store"
            await send(message)

        try:
            await self.app(scope, receive, send_wrapper)
        finally:
            elapsed = time.perf_counter() - start
            route = _route_template(scope)
            method = scope.get("method", "")
            status = status_holder["status"]
            metrics.HTTP_REQUESTS.labels(method=method, route=route, status=str(status)).inc()
            metrics.HTTP_LATENCY.labels(method=method, route=route).observe(elapsed)
            if path not in _EXEMPT_PATHS:
                log.info(
                    "request",
                    method=method,
                    route=route,
                    status=status,
                    duration_ms=round(elapsed * 1000, 2),
                )
            request_id_ctx.reset(token)


class GlobalRateLimitMiddleware:
    """Per-IP ceiling across all routes. Fails open if Redis is down (logged):
    the stricter login limits fail closed separately."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or scope.get("path") in _EXEMPT_PATHS:
            await self.app(scope, receive, send)
            return
        container: Any = scope["app"].state.container
        s = container.settings
        if s.rate_limit_enabled:
            client = scope.get("client")
            ip = client[0] if client else "unknown"
            try:
                result = await container.limiter.hit(
                    "global", ip, s.global_rate_limit, s.global_rate_window_seconds
                )
            except RedisError:
                log.warning("global_rate_limit_degraded")
            else:
                if not result.allowed:
                    response = problem_response(
                        Request(scope),
                        429,
                        "rate_limited",
                        "Too many requests",
                        "Rate limit exceeded; retry later",
                        headers={"Retry-After": str(result.retry_after_seconds)},
                    )
                    await response(scope, receive, send)
                    return
        await self.app(scope, receive, send)
