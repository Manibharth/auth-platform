from app.core.rate_limit import RateLimiter


async def test_sliding_window(container):
    limiter = RateLimiter(container.redis, prefix="t")
    results = [await limiter.hit("s", "id", 3, 60) for _ in range(4)]
    assert [r.allowed for r in results] == [True, True, True, False]
    assert results[-1].retry_after_seconds >= 59
    peek = await limiter.peek("s", "id", 3, 60)
    assert not peek.allowed and peek.count == 3
    await limiter.reset("s", "id")
    assert (await limiter.hit("s", "id", 3, 60)).allowed
