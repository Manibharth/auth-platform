"""Test fixtures. Everything runs against real PostgreSQL and Redis.

If TEST_DATABASE_URL and TEST_REDIS_URL are set (CI service containers, or a
local instance) they are used; otherwise Testcontainers starts both in Docker.
"""

from __future__ import annotations

import os
import uuid
from collections.abc import AsyncIterator, Iterator
from dataclasses import dataclass
from typing import Any

import pytest
from alembic import command
from alembic.config import Config
from httpx import ASGITransport, AsyncClient
from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine

from app.core.config import Settings
from app.core.container import Container
from app.core.security import PasswordHasher
from app.db.seed import ensure_user
from app.main import create_app
from app.services.email_service import MemoryEmailSender

PASSWORD = "correct-Horse-battery-42"
MUTABLE_TABLES = (
    "idempotency_keys, projects, audit_log, one_time_tokens, refresh_tokens, user_roles, users"
)


@pytest.fixture(scope="session")
def service_urls() -> Iterator[tuple[str, str]]:
    db_url = os.environ.get("TEST_DATABASE_URL")
    redis_url = os.environ.get("TEST_REDIS_URL")
    if db_url and redis_url:
        yield db_url, redis_url
        return
    from testcontainers.community.postgres import PostgresContainer
    from testcontainers.community.redis import RedisContainer

    with (
        PostgresContainer("postgres:16-alpine", driver="asyncpg") as pg,
        RedisContainer("redis:7-alpine") as rd,
    ):
        redis_url = f"redis://{rd.get_container_host_ip()}:{rd.get_exposed_port(6379)}/0"
        yield pg.get_connection_url(), redis_url


def alembic_config(db_url: str) -> Config:
    cfg = Config("alembic.ini")
    cfg.attributes["database_url"] = db_url
    return cfg


@pytest.fixture(scope="session")
async def migrated_db(service_urls: tuple[str, str]) -> str:
    db_url, _ = service_urls
    engine = create_async_engine(db_url)
    async with engine.begin() as conn:
        await conn.execute(text("DROP SCHEMA public CASCADE"))
        await conn.execute(text("CREATE SCHEMA public"))
    await engine.dispose()
    # Alembic's env runs its own event loop, so run it in a worker thread.
    import anyio

    await anyio.to_thread.run_sync(command.upgrade, alembic_config(db_url), "head")
    return db_url


@pytest.fixture(scope="session")
def settings(service_urls: tuple[str, str], migrated_db: str) -> Settings:
    return Settings(
        _env_file=None,  # type: ignore[call-arg]
        environment="test",
        database_url=migrated_db,
        redis_url=service_urls[1],
        email_backend="memory",
        log_json=True,
        log_level="WARNING",
        argon2_time_cost=1,
        argon2_memory_cost_kib=1024,
        refresh_cookie_secure=False,
        public_base_url="http://testserver",
        db_pool_size=20,
    )


@pytest.fixture(scope="session")
async def container(settings: Settings) -> AsyncIterator[Container]:
    c = Container.build(settings)
    yield c
    await c.close()


@pytest.fixture(scope="session")
def app(settings: Settings, container: Container) -> Any:
    return create_app(settings, container)


@pytest.fixture(autouse=True)
async def clean_state(request: pytest.FixtureRequest) -> AsyncIterator[None]:
    if request.node.nodeid.startswith("tests/unit/"):
        yield  # unit tests need no database or Redis
        return
    container: Container = request.getfixturevalue("container")
    snapshot = container.settings.model_dump()
    async with container.engine.begin() as conn:
        await conn.execute(text(f"TRUNCATE {MUTABLE_TABLES} CASCADE"))
    await container.redis.flushdb()
    container.permission_cache.clear()
    outbox = container.email
    assert isinstance(outbox, MemoryEmailSender)
    outbox.outbox.clear()
    yield
    for key, value in snapshot.items():  # undo per-test settings tweaks
        object.__setattr__(container.settings, key, value)


@pytest.fixture
async def client(app: Any) -> AsyncIterator[AsyncClient]:
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as c:
        yield c


@pytest.fixture
def outbox(container: Container) -> MemoryEmailSender:
    assert isinstance(container.email, MemoryEmailSender)
    return container.email


# ---------------------------------------------------------------- helpers
@dataclass
class TestUser:
    __test__ = False
    id: uuid.UUID
    email: str
    password: str
    access: str
    refresh: str

    @property
    def headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.access}"}


@pytest.fixture
def make_user(container: Container, client: AsyncClient) -> Any:
    hasher = PasswordHasher.from_settings(container.settings)

    async def _make(
        roles: list[str] | None = None,
        *,
        email: str | None = None,
        password: str = PASSWORD,
        login: bool = True,
    ) -> TestUser:
        email = email or f"user-{uuid.uuid4().hex[:10]}@example.com"
        async with container.sessionmaker() as session:
            user = await ensure_user(
                session, hasher, email, password, ["user"] if roles is None else roles
            )
            await session.commit()
            user_id = user.id
        access = refresh = ""
        if login:
            resp = await client.post("/v1/auth/login", json={"email": email, "password": password})
            assert resp.status_code == 200, resp.text
            access, refresh = resp.json()["access_token"], resp.json()["refresh_token"]
        return TestUser(user_id, email, password, access, refresh)

    return _make


@pytest.fixture
async def user(make_user: Any) -> TestUser:
    u: TestUser = await make_user(["user"])
    return u


@pytest.fixture
async def admin(make_user: Any) -> TestUser:
    u: TestUser = await make_user(["admin"])
    return u


@pytest.fixture
async def auditor(make_user: Any) -> TestUser:
    u: TestUser = await make_user(["auditor"])
    return u


async def count_rows(container: Container, sql: str, **params: Any) -> int:
    async with container.engine.connect() as conn:
        return int((await conn.execute(text(sql), params)).scalar_one())
