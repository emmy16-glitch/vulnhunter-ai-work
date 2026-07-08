"""Validated safety policy for VulnHunter HTTP communication."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

HttpMethod = Literal["GET", "HEAD"]


class HttpClientPolicy(BaseModel):
    """Immutable resource and behaviour limits for one HTTP client."""

    model_config = ConfigDict(frozen=True)

    allowed_methods: tuple[HttpMethod, ...] = ("GET", "HEAD")

    request_timeout_seconds: float = Field(
        default=10.0,
        gt=0,
        le=60,
    )

    maximum_response_bytes: int = Field(
        default=5 * 1024 * 1024,
        ge=1,
        le=50 * 1024 * 1024,
    )

    maximum_redirects: int = Field(
        default=5,
        ge=0,
        le=10,
    )

    maximum_requests: int = Field(
        default=100,
        ge=1,
        le=10_000,
    )

    minimum_request_delay_seconds: float = Field(
        default=0.2,
        ge=0,
        le=10,
    )

    user_agent: str = Field(
        default="VulnHunter-Lab/0.1 (authorised security research)",
        min_length=1,
        max_length=200,
    )

    verify_tls: bool = True

    @field_validator("allowed_methods")
    @classmethod
    def validate_allowed_methods(
        cls,
        methods: tuple[HttpMethod, ...],
    ) -> tuple[HttpMethod, ...]:
        """Require at least one unique, read-only HTTP method."""
        if not methods:
            raise ValueError("At least one HTTP method must be enabled.")

        if len(methods) != len(set(methods)):
            raise ValueError("HTTP methods must not contain duplicates.")

        return methods
