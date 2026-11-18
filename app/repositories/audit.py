from __future__ import annotations

import uuid
from collections.abc import Sequence
from datetime import datetime

from sqlalchemy import func, select, tuple_
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import AuditLog


class AuditRepository:
    """Insert and select only: there is deliberately no update or delete method."""

    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def add(self, entry: AuditLog) -> AuditLog:
        self.session.add(entry)
        await self.session.flush()
        return entry

    async def search(
        self,
        *,
        actor_id: uuid.UUID | None,
        action: str | None,
        target_id: str | None,
        since: datetime | None,
        until: datetime | None,
        after: tuple[datetime, uuid.UUID] | None,
        limit: int,
    ) -> Sequence[AuditLog]:
        stmt = select(AuditLog)
        if actor_id is not None:
            stmt = stmt.where(AuditLog.actor_id == actor_id)
        if action:
            stmt = stmt.where(AuditLog.action == action)
        if target_id:
            stmt = stmt.where(AuditLog.target_id == target_id)
        if since is not None:
            stmt = stmt.where(AuditLog.created_at >= since)
        if until is not None:
            stmt = stmt.where(AuditLog.created_at < until)
        if after is not None:
            stmt = stmt.where(tuple_(AuditLog.created_at, AuditLog.id) < tuple_(after[0], after[1]))
        stmt = stmt.order_by(AuditLog.created_at.desc(), AuditLog.id.desc()).limit(limit)
        return (await self.session.scalars(stmt)).all()

    async def count(self, *, action: str | None = None, target_id: str | None = None) -> int:
        stmt = select(func.count()).select_from(AuditLog)
        if action:
            stmt = stmt.where(AuditLog.action == action)
        if target_id:
            stmt = stmt.where(AuditLog.target_id == target_id)
        return int(await self.session.scalar(stmt) or 0)
