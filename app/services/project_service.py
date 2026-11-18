"""Projects: the demo resource. Ownership is enforced here, not in the router."""

from __future__ import annotations

import hashlib
import json
import uuid
from collections.abc import Sequence
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings
from app.core.container import PermissionCache
from app.core.errors import ProblemError, not_found
from app.models import Project
from app.repositories.projects import IdempotencyRepository, ProjectRepository
from app.schemas import ProjectCreate, ProjectOut, ProjectUpdate
from app.services import RequestContext
from app.services.audit_service import AuditService
from app.services.pagination import decode_cursor, encode_cursor
from app.services.rbac_service import RbacService


def request_fingerprint(payload: dict[str, Any]) -> str:
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canonical.encode()).hexdigest()


class ProjectService:
    def __init__(
        self, session: AsyncSession, *, settings: Settings, cache: PermissionCache
    ) -> None:
        self.session = session
        self.settings = settings
        self.repo = ProjectRepository(session)
        self.idem = IdempotencyRepository(session)
        self.rbac = RbacService(session, cache)
        self.audit = AuditService(session)

    async def create(
        self, owner_id: uuid.UUID, data: ProjectCreate, idempotency_key: str | None
    ) -> tuple[int, dict[str, Any], bool]:
        """Returns (status, body, replayed)."""
        if idempotency_key is None:
            project = await self.repo.add(Project(owner_id=owner_id, **data.model_dump()))
            await self.session.commit()
            return 201, ProjectOut.model_validate(project).model_dump(mode="json"), False

        now = datetime.now(UTC)
        ttl = timedelta(hours=self.settings.idempotency_ttl_hours)
        fingerprint = request_fingerprint(data.model_dump(mode="json"))
        await self.idem.purge_expired_key(owner_id, idempotency_key, now, ttl)
        if not await self.idem.try_claim(owner_id, idempotency_key, fingerprint):
            existing = await self.idem.get(owner_id, idempotency_key)
            # Copy before rollback: rollback expires loaded instances.
            stored = (
                (existing.request_hash, existing.response_status, existing.response_body)
                if existing is not None
                else None
            )
            await self.session.rollback()
            if stored is None or stored[1] is None or stored[2] is None:
                raise ProblemError(
                    409, "idempotency_in_progress", "Request with this key is in progress"
                )
            if stored[0] != fingerprint:
                raise ProblemError(
                    422, "idempotency_key_mismatch", "Idempotency-Key reused with a different body"
                )
            return stored[1], stored[2], True

        project = await self.repo.add(Project(owner_id=owner_id, **data.model_dump()))
        body = ProjectOut.model_validate(project).model_dump(mode="json")
        await self.idem.store_response(owner_id, idempotency_key, 201, body)
        await self.session.commit()  # project row and stored response commit together
        return 201, body, False

    async def list_own(
        self, owner_id: uuid.UUID, cursor: str | None, limit: int
    ) -> tuple[Sequence[Project], str | None]:
        rows = await self.repo.list_for_owner(owner_id, decode_cursor(cursor), limit + 1)
        next_cursor = (
            encode_cursor(rows[limit - 1].created_at, rows[limit - 1].id)
            if len(rows) > limit
            else None
        )
        return rows[:limit], next_cursor

    async def _get_authorised(self, project_id: uuid.UUID, caller_id: uuid.UUID) -> Project:
        project = await self.repo.get(project_id)
        # 404, not 403, so a caller cannot learn that someone else's project exists.
        if project is None:
            raise not_found("Project")
        if project.owner_id != caller_id and not await self.rbac.is_admin(caller_id):
            raise not_found("Project")
        return project

    async def get(self, project_id: uuid.UUID, caller_id: uuid.UUID) -> Project:
        return await self._get_authorised(project_id, caller_id)

    async def update(
        self, project_id: uuid.UUID, caller_id: uuid.UUID, data: ProjectUpdate
    ) -> Project:
        project = await self._get_authorised(project_id, caller_id)
        changes = data.model_dump(exclude_unset=True)
        if "name" in changes and changes["name"] is None:
            raise ProblemError(422, "validation_error", "name cannot be null")
        for field, value in changes.items():
            setattr(project, field, value)
        await self.session.commit()
        await self.session.refresh(project)
        return project

    async def delete(
        self, project_id: uuid.UUID, caller_id: uuid.UUID, ctx: RequestContext
    ) -> None:
        project = await self._get_authorised(project_id, caller_id)
        project.deleted_at = datetime.now(UTC)
        await self.audit.record(
            "project.deleted",
            actor_id=caller_id,
            ctx=ctx,
            target_type="project",
            target_id=project.id,
            metadata={"owner_id": str(project.owner_id)},
        )
        await self.session.commit()
