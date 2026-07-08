"""Structured passive-security observations and review records."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from vulnhunter.security import redact_mapping, redact_text, redact_url

Severity = Literal["info", "low", "medium", "high"]
ReviewOutcome = Literal["confirmed", "false_positive", "needs_review"]
ReviewLabel = Literal["unreviewed", "confirmed", "false_positive", "needs_review"]


class Observation(BaseModel):
    """A sanitised passive-security signal discovered on one page."""

    model_config = ConfigDict(frozen=True)

    category: str = Field(min_length=1, max_length=100)
    severity: Severity
    title: str = Field(min_length=1, max_length=200)
    description: str = Field(min_length=1, max_length=2_000)
    url: str = Field(min_length=1, max_length=2_000)
    evidence: dict[str, Any] = Field(default_factory=dict)
    fingerprint: str = Field(min_length=64, max_length=64)

    @classmethod
    def create(
        cls,
        *,
        category: str,
        severity: Severity,
        title: str,
        description: str,
        url: str,
        evidence: dict[str, Any] | None = None,
    ) -> Observation:
        """Create a redacted observation with a deterministic fingerprint."""
        safe_url = redact_url(url)
        safe_title = redact_text(title)
        safe_description = redact_text(description)
        safe_evidence = redact_mapping(evidence or {})

        fingerprint_payload = {
            "category": category,
            "title": safe_title,
            "url": safe_url,
            "evidence": safe_evidence,
        }
        encoded_payload = json.dumps(
            fingerprint_payload,
            sort_keys=True,
            separators=(",", ":"),
            default=str,
        ).encode("utf-8")

        return cls(
            category=category,
            severity=severity,
            title=safe_title,
            description=safe_description,
            url=safe_url,
            evidence=safe_evidence,
            fingerprint=hashlib.sha256(encoded_payload).hexdigest(),
        )


class ScanSummary(BaseModel):
    """Read-only summary of one persisted mapping scan."""

    model_config = ConfigDict(frozen=True)

    id: int
    target_url: str
    status: Literal["running", "completed", "failed"]
    started_at: datetime
    completed_at: datetime | None = None
    pages_visited: int = Field(default=0, ge=0)
    observations_count: int = Field(default=0, ge=0)
    error_message: str | None = None


class ObservationSummary(BaseModel):
    """Read-only persisted observation used by review commands."""

    model_config = ConfigDict(frozen=True)

    id: int
    scan_id: int
    page_id: int | None = None
    category: str
    severity: Severity
    title: str
    description: str
    url: str
    evidence: dict[str, Any]
    fingerprint: str
    review_label: ReviewLabel
    review_note: str | None = None
    reviewed_at: datetime | None = None
