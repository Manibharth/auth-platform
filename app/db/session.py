"""Async engine and session factory."""

from __future__ import annotations

from sqlalchemy import event
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from app.core import metrics
from app.core.config import Settings


def create_engine(settings: Settings) -> AsyncEngine:
    engine = create_async_engine(
        settings.database_url.get_secret_value(),
        pool_size=settings.db_pool_size,
        max_overflow=settings.db_max_overflow,
        pool_pre_ping=True,
        pool_recycle=1800,
        echo=settings.db_echo,
        connect_args={"server_settings": {"application_name": "auth-platform", "timezone": "UTC"}},
    )
    metrics.DB_POOL_SIZE.set(settings.db_pool_size)

    @event.listens_for(engine.sync_engine, "checkout")
    def _checkout(*_: object) -> None:
        metrics.DB_POOL_CHECKED_OUT.inc()

    @event.listens_for(engine.sync_engine, "checkin")
    def _checkin(*_: object) -> None:
        metrics.DB_POOL_CHECKED_OUT.dec()

    return engine


def create_sessionmaker(engine: AsyncEngine) -> async_sessionmaker[AsyncSession]:
    return async_sessionmaker(engine, expire_on_commit=False, autoflush=False)
