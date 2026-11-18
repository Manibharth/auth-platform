"""Application factory.

gunicorn -c gunicorn.conf.py 'app.main:create_app()'
uvicorn --factory app.main:create_app --reload
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.v1 import admin, auth, health, projects, users
from app.core.config import Settings, get_settings
from app.core.container import Container
from app.core.errors import install_exception_handlers
from app.core.logging import configure_logging
from app.core.middleware import GlobalRateLimitMiddleware, RequestContextMiddleware
from app.core.openapi import install_openapi
from app.core.telemetry import setup_tracing

DESCRIPTION = """
Identity and API service: register, verify email, log in, receive short-lived RS256
access tokens and rotating refresh tokens, and call role-protected endpoints.

**Try it:** `POST /v1/auth/login` with the demo account, copy `access_token`, click
**Authorize** and paste it. Errors follow RFC 9457 (`application/problem+json`).
"""


def create_app(settings: Settings | None = None, container: Container | None = None) -> FastAPI:
    settings = settings or get_settings()
    configure_logging(settings.log_level, settings.log_json)

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        owned = container is None
        app.state.container = container or Container.build(settings)
        setup_tracing(app, app.state.container, settings)
        try:
            yield
        finally:
            if owned:
                await app.state.container.close()

    docs = settings.docs_enabled
    app = FastAPI(
        title=settings.app_name,
        version="1.0.0",
        description=DESCRIPTION,
        lifespan=lifespan,
        docs_url="/docs" if docs else None,
        redoc_url="/redoc" if docs else None,
        openapi_url="/openapi.json" if docs else None,
        swagger_ui_parameters={"persistAuthorization": False, "displayRequestDuration": True},
    )
    if container is not None:
        app.state.container = container

    install_exception_handlers(app)
    install_openapi(app)

    # add_middleware wraps: the last one added is the outermost.
    if settings.cors_origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=settings.cors_origins,  # explicit allow-list, never "*"
            allow_credentials=True,
            allow_methods=["GET", "POST", "PATCH", "DELETE"],
            allow_headers=["Authorization", "Content-Type", "Idempotency-Key", "X-Request-ID"],
            expose_headers=["X-Request-ID", "Retry-After", "Idempotent-Replayed"],
            max_age=600,
        )
    app.add_middleware(GlobalRateLimitMiddleware)
    app.add_middleware(RequestContextMiddleware, hsts=settings.is_production_like)

    app.include_router(health.router)
    app.include_router(auth.router)
    app.include_router(users.router)
    app.include_router(projects.router)
    app.include_router(admin.router)
    return app
