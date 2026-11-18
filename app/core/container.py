"""Process-wide singletons, built once in the app lifespan and kept on app.state."""

from __future__ import annotations

import time
from dataclasses import dataclass, field

from redis.asyncio import Redis
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker

from app.core.config import Settings
from app.core.rate_limit import RateLimiter
from app.core.security import KeyRing, PasswordHasher, SecretBox
from app.db.session import create_engine, create_sessionmaker
from app.services.email_service import EmailSender, build_email_sender


@dataclass
class PermissionCache:
    """Role -> permissions map, cached in-process. It changes only via migrations,
    so a short TTL removes a DB round trip from every authorised request."""

    ttl_seconds: float = 60.0
    _value: dict[str, frozenset[str]] | None = None
    _loaded_at: float = 0.0
    _hits: int = field(default=0, repr=False)

    def get(self) -> dict[str, frozenset[str]] | None:
        if self._value is not None and time.monotonic() - self._loaded_at < self.ttl_seconds:
            self._hits += 1
            return self._value
        return None

    def set(self, value: dict[str, frozenset[str]]) -> None:
        self._value = value
        self._loaded_at = time.monotonic()

    def clear(self) -> None:
        self._value = None


@dataclass
class Container:
    settings: Settings
    engine: AsyncEngine
    sessionmaker: async_sessionmaker[AsyncSession]
    redis: Redis
    keyring: KeyRing
    hasher: PasswordHasher
    limiter: RateLimiter
    email: EmailSender
    secret_box: SecretBox
    permission_cache: PermissionCache

    @classmethod
    def build(cls, settings: Settings) -> Container:
        engine = create_engine(settings)
        redis = Redis.from_url(
            settings.redis_url.get_secret_value(),
            decode_responses=True,
            socket_timeout=2,
            socket_connect_timeout=2,
            health_check_interval=30,
        )
        return cls(
            settings=settings,
            engine=engine,
            sessionmaker=create_sessionmaker(engine),
            redis=redis,
            keyring=KeyRing.from_settings(settings),
            hasher=PasswordHasher.from_settings(settings),
            limiter=RateLimiter(redis),
            email=build_email_sender(settings),
            secret_box=SecretBox(
                settings.mfa_encryption_key.get_secret_value()
                if settings.mfa_encryption_key
                else None
            ),
            permission_cache=PermissionCache(ttl_seconds=settings.permission_cache_ttl_seconds),
        )

    async def close(self) -> None:
        await self.redis.aclose()
        await self.engine.dispose()
