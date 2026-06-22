import asyncio

import pytest

from app.cache import TTLCache
from app.rate_limiter import HomeyQueue, HomeyRateLimiter


def test_cache_returns_live_then_cache() -> None:
    cache: TTLCache[list[str]] = TTLCache(ttl_seconds=60)
    live = cache.set(["device"])
    cached = cache.get()

    assert live.source == "live"
    assert cached is not None
    assert cached.source == "cache"
    assert cached.value == ["device"]


@pytest.mark.asyncio
async def test_queue_runs_operations_serially() -> None:
    limiter = HomeyRateLimiter(max_requests_per_minute=60)
    queue = HomeyQueue(limiter)
    calls: list[int] = []

    async def operation(value: int) -> int:
        await asyncio.sleep(0.01)
        calls.append(value)
        return value

    results = await asyncio.gather(
        queue.run(lambda: operation(1)),
        queue.run(lambda: operation(2)),
    )

    assert results == [1, 2]
    assert calls == [1, 2]
