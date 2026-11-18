"""Structured JSON logging with a request id on every line.

A redaction processor removes tokens and passwords and masks email addresses,
so a log leak cannot leak credentials.
"""

from __future__ import annotations

import logging
import re
import sys
from contextvars import ContextVar
from typing import Any

import structlog
from structlog.types import EventDict, WrappedLogger

request_id_ctx: ContextVar[str | None] = ContextVar("request_id", default=None)

_SENSITIVE_KEYS = re.compile(
    r"(password|passwd|secret|token|authorization|cookie|api[_-]?key|code_verifier|mfa_code)",
    re.IGNORECASE,
)
_EMAIL_RE = re.compile(r"([A-Za-z0-9._%+-])[A-Za-z0-9._%+-]*@([A-Za-z0-9.-]+\.[A-Za-z]{2,})")
_BEARER_RE = re.compile(r"(Bearer\s+)[A-Za-z0-9\-_.=]+", re.IGNORECASE)
_JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*")


def mask_email(email: str) -> str:
    """j***@example.com — enough to correlate, not enough to identify."""
    return _EMAIL_RE.sub(lambda m: f"{m.group(1)}***@{m.group(2)}", email)


def _scrub(value: Any) -> Any:
    if isinstance(value, str):
        value = _BEARER_RE.sub(r"\1[REDACTED]", value)
        value = _JWT_RE.sub("[REDACTED_JWT]", value)
        return mask_email(value)
    if isinstance(value, dict):
        return {
            k: ("[REDACTED]" if _SENSITIVE_KEYS.search(str(k)) else _scrub(v))
            for k, v in value.items()
        }
    if isinstance(value, list | tuple):
        return [_scrub(v) for v in value]
    return value


def redact(_: WrappedLogger, __: str, event_dict: EventDict) -> EventDict:
    for key in list(event_dict.keys()):
        if _SENSITIVE_KEYS.search(key):
            event_dict[key] = "[REDACTED]"
        else:
            event_dict[key] = _scrub(event_dict[key])
    return event_dict


def add_request_id(_: WrappedLogger, __: str, event_dict: EventDict) -> EventDict:
    rid = request_id_ctx.get()
    if rid is not None:
        event_dict.setdefault("request_id", rid)
    return event_dict


def configure_logging(level: str = "INFO", json_logs: bool = True) -> None:
    shared: list[Any] = [
        structlog.contextvars.merge_contextvars,
        add_request_id,
        structlog.stdlib.add_log_level,
        structlog.processors.TimeStamper(fmt="iso", utc=True),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        redact,
    ]
    renderer: Any = (
        structlog.processors.JSONRenderer() if json_logs else structlog.dev.ConsoleRenderer()
    )
    structlog.configure(
        processors=[*shared, renderer],
        wrapper_class=structlog.make_filtering_bound_logger(logging.getLevelName(level.upper())),
        logger_factory=structlog.PrintLoggerFactory(sys.stdout),
        cache_logger_on_first_use=True,
    )
    # Route stdlib loggers (uvicorn, sqlalchemy) through the same format.
    logging.basicConfig(level=level.upper(), stream=sys.stdout, format="%(message)s")
    logging.getLogger("uvicorn.access").disabled = True  # we log requests ourselves
