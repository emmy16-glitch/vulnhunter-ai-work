"""Concurrency-safe request-budget enforcement."""

from __future__ import annotations

import asyncio

from vulnhunter.exceptions import RequestBudgetExceededError


class RequestBudget:
    """Track the number of network requests consumed by one scan."""

    def __init__(self, maximum_requests: int) -> None:
        if maximum_requests < 1:
            raise ValueError("maximum_requests must be at least 1.")

        self._maximum_requests = maximum_requests
        self._used_requests = 0
        self._lock = asyncio.Lock()

    @property
    def maximum_requests(self) -> int:
        """Return the total number of requests permitted."""
        return self._maximum_requests

    @property
    def used_requests(self) -> int:
        """Return the number of request slots already consumed."""
        return self._used_requests

    @property
    def remaining_requests(self) -> int:
        """Return the number of request slots still available."""
        return self._maximum_requests - self._used_requests

    async def consume(self) -> int:
        """Reserve and return the next request number.

        The lock ensures two concurrent tasks cannot both consume the same
        final request slot.
        """
        async with self._lock:
            if self._used_requests >= self._maximum_requests:
                raise RequestBudgetExceededError(
                    "The scan has reached its configured request limit "
                    f"of {self._maximum_requests}."
                )

            self._used_requests += 1
            return self._used_requests
