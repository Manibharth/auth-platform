"""Ops endpoints and the public JWKS document."""

from __future__ import annotations

import ipaddress
from typing import Any

import anyio
from fastapi import APIRouter, Request, Response
from fastapi.responses import JSONResponse
from sqlalchemy import text

from app.api.deps import ContainerDep
from app.core import metrics
from app.core.errors import not_found
from app.core.security import constant_time_equals
from app.schemas import Health, Problem, Readiness

router = APIRouter()


@router.get("/healthz", tags=["ops"], response_model=Health, summary="Liveness: the process is up")
async def healthz() -> Health:
    return Health()


@router.get(
    "/readyz",
    tags=["ops"],
    response_model=Readiness,
    responses={503: {"model": Readiness}},
    summary="Readiness: PostgreSQL and Redis are reachable",
)
async def readyz(container: ContainerDep) -> JSONResponse:
    checks: dict[str, str] = {}
    try:
        with anyio.fail_after(2):
            async with container.engine.connect() as conn:
                await conn.execute(text("SELECT 1"))
        checks["database"] = "ok"
    except Exception:
        checks["database"] = "unavailable"
    try:
        with anyio.fail_after(2):
            await container.redis.ping()
        checks["redis"] = "ok"
    except Exception:
        checks["redis"] = "unavailable"
    ready = all(v == "ok" for v in checks.values())
    body = Readiness(status="ready" if ready else "unavailable", checks=checks)
    return JSONResponse(body.model_dump(), status_code=200 if ready else 503)


@router.get(
    "/metrics",
    include_in_schema=False,
    responses={404: {"model": Problem}},
)
async def prometheus_metrics(request: Request, container: ContainerDep) -> Response:
    """Network-restricted: only allow-listed CIDRs (and an optional bearer token)."""
    s = container.settings
    client = request.client.host if request.client else ""
    try:
        addr = ipaddress.ip_address(client)
        allowed = any(
            addr in ipaddress.ip_network(c, strict=False) for c in s.metrics_allowed_cidrs
        )
    except ValueError:
        allowed = False
    if s.metrics_bearer_token is not None:
        header = request.headers.get("authorization", "")
        allowed = allowed and constant_time_equals(
            header, f"Bearer {s.metrics_bearer_token.get_secret_value()}"
        )
    if not allowed:
        raise not_found()  # do not advertise the endpoint
    payload, content_type = metrics.render_latest()
    return Response(payload, media_type=content_type)


@router.get(
    "/.well-known/jwks.json",
    tags=["auth"],
    summary="Public signing keys (current and previous) so other services can verify tokens",
)
async def jwks(container: ContainerDep, response: Response) -> dict[str, Any]:
    response.headers["Cache-Control"] = "public, max-age=300"
    return container.keyring.jwks()
