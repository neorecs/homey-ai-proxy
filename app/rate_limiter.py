import asyncio
import time
from collections import deque
from collections.abc import Awaitable, Callable
from typing import TypeVar


T = TypeVar("T")


class HomeyRateLimiter:
    def __init__(self, max_requests_per_minute: int):
        self.max_requests = max(1, max_requests_per_minute)
        self._timestamps: deque[float] = deque()
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        async with self._lock:
            while True:
                now = time.monotonic()
                while self._timestamps and now - self._timestamps[0] >= 60:
                    self._timestamps.popleft()

                if len(self._timestamps) < self.max_requests:
                    self._timestamps.append(now)
                    return

                wait_for = 60 - (now - self._timestamps[0])
                await asyncio.sleep(max(wait_for, 0.01))


class HomeyQueue:
    def __init__(self, rate_limiter: HomeyRateLimiter):
        self.rate_limiter = rate_limiter
        self._queue_lock = asyncio.Lock()

    async def run(self, operation: Callable[[], Awaitable[T]]) -> T:
        async with self._queue_lock:
            await self.rate_limiter.acquire()
            return await operation()
