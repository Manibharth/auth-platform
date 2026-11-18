"""Business rules. Services use repositories for data and never see HTTP objects."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class RequestContext:
    ip: str | None = None
    user_agent: str | None = None
