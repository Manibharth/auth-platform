"""OpenAPI post-processing so the published contract matches real responses.

* Every 4xx/5xx is documented as application/problem+json with the Problem schema.
* Every operation documents 429 (global rate limit) and 500.
* Operations that take input document 400 (unparseable) and 422 (invalid).
* FastAPI's default 422 body is replaced by the problem shape the app actually sends.
"""

from __future__ import annotations

from typing import Any

from fastapi import FastAPI
from fastapi.openapi.utils import get_openapi

PROBLEM_REF = {"$ref": "#/components/schemas/Problem"}
_DESCRIPTIONS = {
    "400": "Bad request",
    "401": "Missing, invalid, expired or revoked access token",
    "403": "Authenticated but not allowed",
    "404": "Not found (also returned for other users' resources)",
    "409": "Conflict",
    "422": "Validation failed",
    "429": "Rate limited; see Retry-After",
    "500": "Unexpected server error",
    "503": "Dependency unavailable",
}
_RATE_LIMIT_EXEMPT = {"/healthz", "/readyz"}
_PROBLEM_SCHEMA: dict[str, Any] = {
    "title": "Problem",
    "description": "RFC 9457 problem details",
    "type": "object",
    "required": ["type", "title", "status", "code"],
    "properties": {
        "type": {"type": "string"},
        "title": {"type": "string"},
        "status": {"type": "integer"},
        "code": {"type": "string", "description": "Stable machine-readable error code"},
        "detail": {"type": "string"},
        "instance": {"type": "string"},
        "request_id": {"type": "string"},
        "errors": {"type": "array", "items": {"type": "object"}},
        "problems": {"type": "array", "items": {"type": "string"}},
    },
}


def _problem(status: str) -> dict[str, Any]:
    return {
        "description": _DESCRIPTIONS.get(status, "Error"),
        "content": {"application/problem+json": {"schema": PROBLEM_REF}},
    }


def install_openapi(app: FastAPI) -> None:
    def custom_openapi() -> dict[str, Any]:
        if app.openapi_schema:
            return app.openapi_schema
        schema = get_openapi(
            title=app.title, version=app.version, description=app.description, routes=app.routes
        )
        components = schema.setdefault("components", {}).setdefault("schemas", {})
        components["Problem"] = _PROBLEM_SCHEMA
        for name in ("HTTPValidationError", "ValidationError"):
            components.pop(name, None)
        for path, item in schema.get("paths", {}).items():
            for op in item.values():
                responses: dict[str, Any] = op.setdefault("responses", {})
                for status in list(responses):
                    if status.isdigit() and int(status) >= 400:
                        responses[status] = _problem(status)
                if path not in _RATE_LIMIT_EXEMPT:
                    responses.setdefault("429", _problem("429"))
                responses.setdefault("500", _problem("500"))
                if op.get("requestBody") or op.get("parameters"):
                    # malformed JSON / cursors -> 400, schema violations -> 422
                    responses.setdefault("400", _problem("400"))
                    responses.setdefault("422", _problem("422"))
        app.openapi_schema = schema
        return schema

    app.openapi = custom_openapi  # type: ignore[method-assign]
