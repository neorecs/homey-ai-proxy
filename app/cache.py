import time
from dataclasses import dataclass
from typing import Generic, TypeVar


T = TypeVar("T")


@dataclass
class CacheResult(Generic[T]):
    value: T
    source: str
    age_seconds: float


class TTLCache(Generic[T]):
    def __init__(self, ttl_seconds: int):
        self.ttl_seconds = ttl_seconds
        self._value: T | None = None
        self._created_at: float | None = None

    def get(self) -> CacheResult[T] | None:
        if self._value is None or self._created_at is None:
            return None
        age = time.monotonic() - self._created_at
        if age > self.ttl_seconds:
            return None
        return CacheResult(value=self._value, source="cache", age_seconds=age)

    def set(self, value: T) -> CacheResult[T]:
        self._value = value
        self._created_at = time.monotonic()
        return CacheResult(value=value, source="live", age_seconds=0.0)

    def clear(self) -> None:
        self._value = None
        self._created_at = None
