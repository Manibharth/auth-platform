from __future__ import annotations

import uuid
from collections.abc import Sequence
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import delete, select, tuple_, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import IdempotencyKey, Project


class ProjectRepository:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def add(self, project: Project) -> Project:
        self.session.add(project)
        await self.session.flush()
        await self.session.refresh(project)
        return project

    async def get(self, project_id: uuid.UUID) -> Project | None:
        return await self.session.scalar(
            select(Project).where(Project.id == project_id, Project.deleted_at.is_(None))
        )

    async def list_for_owner(
        self, owner_id: uuid.UUID, after: tuple[datetime, uuid.UUID] | None, limit: int
    ) -> Sequence[Project]:
        stmt = select(Project).where(Project.owner_id == owner_id, Project.deleted_at.is_(None))
        if after is not None:
            stmt = stmt.where(tuple_(Project.created_at, Project.id) < tuple_(after[0], after[1]))
        stmt = stmt.order_by(Project.created_at.desc(), Project.id.desc()).limit(limit)
        return (await self.session.scalars(stmt)).all()


class IdempotencyRepository:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def purge_expired_key(
        self, user_id: uuid.UUID, key: str, now: datetime, ttl: timedelta
    ) -> None:
        await self.session.execute(
            delete(IdempotencyKey).where(
                IdempotencyKey.user_id == user_id,
                IdempotencyKey.key == key,
                IdempotencyKey.created_at < now - ttl,
            )
        )

    async def try_claim(self, user_id: uuid.UUID, key: str, request_hash: str) -> bool:
        """Insert the key; returns False if another request already holds it.

        If a concurrent transaction holds the same key, this blocks on the
        primary-key index until that transaction commits or rolls back.
        """
        result = await self.session.execute(
            pg_insert(IdempotencyKey)
            .values(user_id=user_id, key=key, request_hash=request_hash)
            .on_conflict_do_nothing(index_elements=["user_id", "key"])
            .returning(IdempotencyKey.key)
        )
        return result.scalar_one_or_none() is not None

    async def get(self, user_id: uuid.UUID, key: str) -> IdempotencyKey | None:
        return await self.session.scalar(
            select(IdempotencyKey).where(
                IdempotencyKey.user_id == user_id, IdempotencyKey.key == key
            )
        )

    async def store_response(
        self, user_id: uuid.UUID, key: str, status: int, body: dict[str, Any]
    ) -> None:
        await self.session.execute(
            update(IdempotencyKey)
            .where(IdempotencyKey.user_id == user_id, IdempotencyKey.key == key)
            .values(response_status=status, response_body=body)
        )

    async def purge_all_expired(self, now: datetime, ttl: timedelta) -> int:
        result = await self.session.execute(
            delete(IdempotencyKey).where(IdempotencyKey.created_at < now - ttl)
        )
        return int(getattr(result, "rowcount", 0) or 0)
