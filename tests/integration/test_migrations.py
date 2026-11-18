"""Spec test 12: every migration upgrades and downgrades cleanly on an empty database."""

from __future__ import annotations

import uuid

import anyio
import pytest
from alembic import command
from alembic.script import ScriptDirectory
from sqlalchemy import text
from sqlalchemy.engine import make_url
from sqlalchemy.ext.asyncio import create_async_engine

from tests.conftest import alembic_config

pytestmark = pytest.mark.slow


async def test_upgrade_downgrade_every_revision(migrated_db):
    url = make_url(migrated_db)
    name = f"migr_{uuid.uuid4().hex[:8]}"
    admin = create_async_engine(url.set(database="postgres"), isolation_level="AUTOCOMMIT")
    async with admin.connect() as conn:
        await conn.execute(text(f'CREATE DATABASE "{name}"'))
    target = url.set(database=name).render_as_string(hide_password=False)
    try:
        cfg = alembic_config(target)
        revisions = [
            s.revision for s in ScriptDirectory.from_config(cfg).walk_revisions("base", "heads")
        ][::-1]
        for rev in revisions:  # step up one at a time
            await anyio.to_thread.run_sync(command.upgrade, cfg, rev)
        for _ in revisions:  # and back down one at a time
            await anyio.to_thread.run_sync(command.downgrade, cfg, "-1")
        await anyio.to_thread.run_sync(command.upgrade, cfg, "head")

        engine = create_async_engine(target)
        async with engine.connect() as conn:
            roles = (
                (await conn.execute(text("SELECT name FROM roles ORDER BY name"))).scalars().all()
            )
            tables = (
                await conn.execute(
                    text(
                        "SELECT count(*) FROM information_schema.tables WHERE table_schema='public'"
                    )
                )
            ).scalar_one()
        await engine.dispose()
        assert roles == ["admin", "auditor", "user"]
        assert tables == 11  # ten tables plus alembic_version
    finally:
        async with admin.connect() as conn:
            await conn.execute(text(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)'))
        await admin.dispose()


async def test_models_match_migrations(migrated_db):
    """No drift between SQLAlchemy models and the migration history."""
    from alembic.autogenerate import compare_metadata
    from alembic.migration import MigrationContext

    from app.db.base import Base

    engine = create_async_engine(migrated_db)

    def _diff(sync_conn):
        ctx = MigrationContext.configure(sync_conn, opts={"compare_type": True})
        return compare_metadata(ctx, Base.metadata)

    async with engine.connect() as conn:
        diff = await conn.run_sync(_diff)
    await engine.dispose()
    assert diff == [], diff
