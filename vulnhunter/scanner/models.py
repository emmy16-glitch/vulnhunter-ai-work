"""Structured results and audit records for safe HTTP communication."""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from vulnhunter.scanner.policy import HttpMethod
from vulnhunter.scope.models import ScopedUrl


class RedirectHop(BaseModel):
    """One manually validated redirect followed by the transport."""

    model_config = ConfigDict(frozen=True)

    from_url: str
    to_url: str
    status_code: int = Field(ge=300, le=399)


class HttpAuditEvent(BaseModel):
    """A sanitised audit record for one generated HTTP request."""

    model_config = ConfigDict(frozen=True)

    timestamp: datetime
    request_number: int = Field(ge=1)
    method: HttpMethod
    url: str
    outcome: Literal["response", "error", "blocked"]

    status_code: int | None = Field(
        default=None,
        ge=100,
        le=599,
    )

    response_bytes: int = Field(default=0, ge=0)
    elapsed_ms: float = Field(default=0, ge=0)

    request_headers: dict[str, str] = Field(default_factory=dict)
    response_headers: dict[str, str] = Field(default_factory=dict)

    message: str | None = None


class SafeHttpResponse(BaseModel):
    """A bounded in-memory response returned by the safe HTTP client.

    The body may contain sensitive target data and must not be logged or
    persisted directly. Later components must extract features and redact
    evidence before storage.
    """

    model_config = ConfigDict(frozen=True)

    method: HttpMethod
    final_url: ScopedUrl
    status_code: int = Field(ge=100, le=599)
    headers: dict[str, str]
    body: bytes
    elapsed_ms: float = Field(ge=0)
    redirects: tuple[RedirectHop, ...] = ()
    audit_events: tuple[HttpAuditEvent, ...] = ()
