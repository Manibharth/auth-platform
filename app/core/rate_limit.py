"""Redis sliding-window rate limiter.

Each key is a sorted set of request timestamps (ms). A Lua script trims entries
older than the window, counts the rest and adds the new hit atomically, so
parallel requests across many app instances share one exact counter.
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass

from redis.asyncio import Redis

from app.core import metrics

_SLIDING_WINDOW_LUA = """
local key = KEYS[1]
local now = tonumber(ARGV[1])
local window = tonumber(ARGV[2])
local limit = tonumber(ARGV[3])
local member = ARGV[4]
local consume = tonumber(ARGV[5])
redis.call('ZREMRANGEBYSCORE', key, 0, now - window)
local count = redis.call('ZCARD', key)
if count >= limit then
  local oldest = redis.call('ZRANGE', key, 0, 0, 'WITHSCORES')
  local retry = window
  if oldest[2] then retry = tonumber(oldest[2]) + window - now end
  return {0, count, retry}
end
if consume == 1 then
  redis.call('ZADD', key, now, member)
  redis.call('PEXPIRE', key, window)
  count = count + 1
end
return {1, count, 0}
"""


@dataclass(frozen=True)
class RateLimitResult:
    allowed: bool
    count: int
    retry_after_seconds: int


class RateLimiter:
    def __init__(self, redis: Redis, prefix: str = "rl") -> None:
        self._redis = redis
        self._prefix = prefix
        self._script = redis.register_script(_SLIDING_WINDOW_LUA)

    async def hit(
        self, scope: str, identifier: str, limit: int, window_seconds: int, *, consume: bool = True
    ) -> RateLimitResult:
        now_ms = int(time.time() * 1000)
        key = f"{self._prefix}:{scope}:{identifier}"
        allowed, count, retry_ms = await self._script(
            keys=[key],
            args=[
                now_ms,
                window_seconds * 1000,
                limit,
                f"{now_ms}-{uuid.uuid4().hex}",
                int(consume),
            ],
        )
        result = RateLimitResult(bool(allowed), int(count), -(-int(retry_ms) // 1000))
        if not result.allowed:
            metrics.RATE_LIMIT_HITS.labels(scope=scope).inc()
        return result

    async def peek(
        self, scope: str, identifier: str, limit: int, window_seconds: int
    ) -> RateLimitResult:
        """Check without consuming (used for 'too many failed logins from this IP')."""
        return await self.hit(scope, identifier, limit, window_seconds, consume=False)

    async def reset(self, scope: str, identifier: str) -> None:
        await self._redis.delete(f"{self._prefix}:{scope}:{identifier}")
