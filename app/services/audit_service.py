from __future__ import annotations

import uuid
from collections.abc import Sequence
from datetime import datetime
from typing import Any

import structlog
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import AuditLog
from app.repositories.audit import AuditRepository
from app.services import RequestContext
from app.services.pagination import decode_cursor, encode_cursor

log = structlog.get_logger(__name__)


class AuditService:
    def __init__(self, session: AsyncSession) -> None:
        self.repo = AuditRepository(session)

    async def record(
        self,
        action: str,
        *,
        actor_id: uuid.UUID | None,
        ctx: RequestContext | None = None,
        target_type: str | None = None,
        target_id: uuid.UUID | str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> AuditLog:
        entry = AuditLog(
            actor_id=actor_id,
            action=action,
            target_type=target_type,
            target_id=str(target_id) if target_id is not None else None,
            ip=ctx.ip if ctx else None,
            metadata_=metadata or {},
        )
        await self.repo.add(entry)
        log.info(
            "audit",
            action=action,
            actor_id=str(actor_id) if actor_id else None,
            target_type=target_type,
            target_id=entry.target_id,
        )
        return entry

    async def search(
        self,
        *,
        actor_id: uuid.UUID | None,
        action: str | None,
        target_id: str | None,
        since: datetime | None,
        until: datetime | None,
        cursor: str | None,
        limit: int,
    ) -> tuple[Sequence[AuditLog], str | None]:
        rows = await self.repo.search(
            actor_id=actor_id,
            action=action,
            target_id=target_id,
            since=since,
            until=until,
            after=decode_cursor(cursor),
            limit=limit + 1,
        )
        next_cursor = (
            encode_cursor(rows[limit - 1].created_at, rows[limit - 1].id)
            if len(rows) > limit
            else None
        )
        return rows[:limit], next_cursor
