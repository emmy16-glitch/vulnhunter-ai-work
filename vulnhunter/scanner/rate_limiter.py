"""Concurrency-safe minimum delay between HTTP request starts."""

from __future__ import annotations

import asyncio
import time
from collections.abc import Awaitable, Callable

Clock = Callable[[], float]
Sleeper = Callable[[float], Awaitable[None]]


class MinimumDelayLimiter:
    """Prevent concurrent workers from exceeding the configured request rate."""

    def __init__(
        self,
        minimum_delay_seconds: float,
        *,
        clock: Clock = time.monotonic,
        sleeper: Sleeper = asyncio.sleep,
    ) -> None:
        if minimum_delay_seconds < 0:
            raise ValueError("minimum_delay_seconds cannot be negative.")

        self._minimum_delay_seconds = minimum_delay_seconds
        self._clock = clock
        self._sleeper = sleeper
        self._last_request_started: float | None = None
        self._lock = asyncio.Lock()

    async def wait(self) -> None:
        """Wait until another request is permitted to begin."""
        async with self._lock:
            now = self._clock()

            if self._last_request_started is not None:
                elapsed = now - self._last_request_started
                remaining_delay = self._minimum_delay_seconds - elapsed

                if remaining_delay > 0:
                    await self._sleeper(remaining_delay)

            self._last_request_started = self._clock()
