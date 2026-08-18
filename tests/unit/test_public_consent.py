from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from vulnhunter.authorization.models import AuthorizationLimits
from vulnhunter.authorization.public_consent import (
    PublicConsentError,
    create_public_consent_authorization,
    has_verified_public_consent,
)
from vulnhunter.authorization.service import validate_scan_authorization
from vulnhunter.authorization.store import AuthorizationStore
from vulnhunter.exceptions import AuthorizationPolicyError
from vulnhunter.scope import validate_target

NOW = datetime(2026, 8, 19, 12, tzinfo=UTC)
TOKEN = "consent-token-0123456789"


def resolver(hostname: str) -> tuple[str, ...]:
    assert hostname == "example.test"
    return ("93.184.216.34",)


def fetcher(url: str) -> tuple[int, bytes, str]:
    assert url == "https://example.test/.well-known/vulnhunter-consent.json"
    return 200, (f'{{"token":"{TOKEN}"}}').encode(), "application/json"


def limits() -> AuthorizationLimits:
    return AuthorizationLimits(
        maximum_pages=10,
        maximum_depth=1,
        maximum_requests=50,
        minimum_request_delay_seconds=1.0,
    )


def create(store: AuthorizationStore):
    return create_public_consent_authorization(
        target_url="https://example.test/community/",
        challenge_token=TOKEN,
        owner="Example Owner",
        approved_by="Security Approver",
        purpose="Bounded passive mapping",
        expires_at=NOW + timedelta(days=7),
        limits=limits(),
        authorization_store=store,
        resolver=resolver,
        fetcher=fetcher,
        now=NOW,
    )


def test_public_consent_creates_exact_passive_authorization_and_event(tmp_path) -> None:
    store = AuthorizationStore.from_path(tmp_path / "auth.db")
    store.initialize()

    result = create(store)

    assert result.record.target_url == "https://example.test/community/"
    assert result.record.approved_addresses == ("93.184.216.34",)
    assert result.passive_only is True
    assert has_verified_public_consent(store, result.record.authorization_id)
    assert any(
        event.event_type == "public_consent_verified"
        for event in store.list_events(result.record.authorization_id)
    )


def test_public_consent_token_mismatch_fails_closed_without_record(tmp_path) -> None:
    store = AuthorizationStore.from_path(tmp_path / "auth.db")
    store.initialize()

    with pytest.raises(PublicConsentError, match="did not match"):
        create_public_consent_authorization(
            target_url="https://example.test/community/",
            challenge_token="different-token-012345",
            owner="Example Owner",
            approved_by="Security Approver",
            purpose="Bounded passive mapping",
            expires_at=NOW + timedelta(days=7),
            limits=limits(),
            authorization_store=store,
            resolver=resolver,
            fetcher=fetcher,
            now=NOW,
        )

    assert store.list(limit=10) == ()


def test_public_validation_requires_verified_consent_event(tmp_path) -> None:
    store = AuthorizationStore.from_path(tmp_path / "auth.db")
    store.initialize()
    result = create(store)
    target = validate_target(
        "https://example.test/community/",
        resolver=resolver,
        allow_public=True,
    )

    with pytest.raises(AuthorizationPolicyError, match="explicit consent-enabled"):
        validate_scan_authorization(
            store,
            result.record.authorization_id,
            target,
            maximum_pages=5,
            maximum_depth=1,
            maximum_requests=20,
            request_delay_seconds=1.0,
            now=NOW + timedelta(hours=1),
        )

    decision = validate_scan_authorization(
        store,
        result.record.authorization_id,
        target,
        maximum_pages=5,
        maximum_depth=1,
        maximum_requests=20,
        request_delay_seconds=1.0,
        now=NOW + timedelta(hours=1),
        allow_public=True,
    )
    assert decision.target_url == target.normalized_url
