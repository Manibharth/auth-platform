from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import OneTimeToken, RefreshToken


class RefreshTokenRepository:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def add(self, token: RefreshToken) -> RefreshToken:
        self.session.add(token)
        await self.session.flush()
        return token

    async def get_by_hash_for_update(self, token_hash: str) -> RefreshToken | None:
        # Row lock: two parallel refreshes with the same token serialise here,
        # so only one can see it as unused.
        return await self.session.scalar(
            select(RefreshToken).where(RefreshToken.token_hash == token_hash).with_for_update()
        )

    async def revoke_family(self, family_id: uuid.UUID, now: datetime) -> int:
        result = await self.session.execute(
            update(RefreshToken)
            .where(RefreshToken.family_id == family_id, RefreshToken.revoked_at.is_(None))
            .values(revoked_at=now)
        )
        return int(getattr(result, "rowcount", 0) or 0)

    async def revoke_all_for_user(self, user_id: uuid.UUID, now: datetime) -> int:
        result = await self.session.execute(
            update(RefreshToken)
            .where(RefreshToken.user_id == user_id, RefreshToken.revoked_at.is_(None))
            .values(revoked_at=now)
        )
        return int(getattr(result, "rowcount", 0) or 0)

    async def family_owner(self, family_id: uuid.UUID) -> uuid.UUID | None:
        return await self.session.scalar(
            select(RefreshToken.user_id).where(RefreshToken.family_id == family_id).limit(1)
        )


class OneTimeTokenRepository:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def add(self, token: OneTimeToken) -> OneTimeToken:
        self.session.add(token)
        await self.session.flush()
        return token

    async def get_by_hash_for_update(self, token_hash: str, purpose: str) -> OneTimeToken | None:
        return await self.session.scalar(
            select(OneTimeToken)
            .where(OneTimeToken.token_hash == token_hash, OneTimeToken.purpose == purpose)
            .with_for_update()
        )

    async def invalidate_outstanding(self, user_id: uuid.UUID, purpose: str, now: datetime) -> None:
        await self.session.execute(
            update(OneTimeToken)
            .where(
                OneTimeToken.user_id == user_id,
                OneTimeToken.purpose == purpose,
                OneTimeToken.consumed_at.is_(None),
            )
            .values(consumed_at=now)
        )
