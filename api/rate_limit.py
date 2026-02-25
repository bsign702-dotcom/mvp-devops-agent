from __future__ import annotations

import threading
import time
from collections import defaultdict, deque

from .errors import APIError


class InMemoryRateLimiter:
    def __init__(self) -> None:
        self._buckets: dict[str, deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    def check(self, key: str, limit: int, window_seconds: int = 60) -> None:
        now = time.time()
        with self._lock:
            bucket = self._buckets[key]
            cutoff = now - window_seconds
            while bucket and bucket[0] < cutoff:
                bucket.popleft()
            if len(bucket) >= limit:
                raise APIError(
                    code="bad_request",
                    message="Rate limit exceeded",
                    status_code=429,
                    details={"key": key, "limit": limit, "window_seconds": window_seconds},
                )
            bucket.append(now)
