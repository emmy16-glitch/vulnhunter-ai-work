from __future__ import annotations

from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from vulnhunter.governance.auth import hash_secret, verify_secret
from vulnhunter.governance.models import (
    CampaignLimits,
    ReviewerIdentity,
    identity_record_sha256,
)


def test_secret_hash_round_trip() -> None:
    salt, digest = hash_secret("reviewer-secret-123")

    assert verify_secret(
        "reviewer-secret-123",
        encoded_salt=salt,
        encoded_hash=digest,
    )
    assert not verify_secret(
        "incorrect-secret",
        encoded_salt=salt,
        encoded_hash=digest,
    )


def test_short_secret_is_rejected() -> None:
    with pytest.raises(Exception, match="12 characters"):
        hash_secret("too-short")


def test_campaign_limits_validate_boundaries() -> None:
    limits = CampaignLimits(
        maximum_pages=20,
        maximum_depth=2,
        maximum_requests=100,
        minimum_request_delay_seconds=0.3,
    )

    assert limits.maximum_scans_per_application == 10


def test_identity_hash_changes_with_roles() -> None:
    base = {
        "reviewer_id": "reviewer-a",
        "display_name": "Reviewer A",
        "roles": ("reviewer",),
        "conflict_tags": (),
        "status": "active",
        "credential_salt": "A" * 22,
        "credential_hash": "B" * 43,
        "created_by": "admin-a",
        "created_at": datetime(2026, 7, 9, tzinfo=UTC),
        "status_changed_at": None,
        "status_reason": None,
        "record_sha256": "0" * 64,
    }
    first = identity_record_sha256(base)
    base["roles"] = ("reviewer", "adjudicator")

    assert identity_record_sha256(base) != first


def test_identity_rejects_naive_timestamp() -> None:
    data = {
        "reviewer_id": "reviewer-a",
        "display_name": "Reviewer A",
        "roles": ("reviewer",),
        "conflict_tags": (),
        "status": "active",
        "credential_salt": "A" * 22,
        "credential_hash": "B" * 43,
        "created_by": "admin-a",
        "created_at": datetime(2026, 7, 9),
        "record_sha256": "0" * 64,
    }

    with pytest.raises(ValidationError, match="timezone"):
        ReviewerIdentity.model_validate(data)
