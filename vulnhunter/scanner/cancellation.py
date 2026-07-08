"""Cooperative cancellation for VulnHunter scan operations."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field

from vulnhunter.exceptions import RequestCancelledError


@dataclass(slots=True)
class CancellationToken:
    """Allow scan components to share one cancellation state."""

    _event: asyncio.Event = field(
        default_factory=asyncio.Event,
        init=False,
        repr=False,
    )

    _reason: str = field(
        default="Operation cancelled.",
        init=False,
        repr=False,
    )

    def cancel(self, reason: str = "Operation cancelled.") -> None:
        """Request cancellation without abruptly terminating resources."""
        cleaned_reason = reason.strip()

        self._reason = cleaned_reason or "Operation cancelled."
        self._event.set()

    @property
    def is_cancelled(self) -> bool:
        """Return whether cancellation has been requested."""
        return self._event.is_set()

    @property
    def reason(self) -> str:
        """Return the human-readable cancellation reason."""
        return self._reason

    def raise_if_cancelled(self) -> None:
        """Stop the current operation when cancellation was requested."""
        if self.is_cancelled:
            raise RequestCancelledError(self.reason)

    async def wait(self) -> None:
        """Wait until another component requests cancellation."""
        await self._event.wait()
