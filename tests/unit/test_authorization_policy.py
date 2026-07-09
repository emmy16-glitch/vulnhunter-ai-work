"""Authorization policy tests without network or external DNS."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest

from vulnhunter.authorization import (
    AuthorizationLimits,
    AuthorizationStore,
    issue_authorization,
    validate_scan_authorization,
)
from vulnhunter.exceptions import AuthorizationPolicyError


def target(
    *,
    url: str = "http://lab.internal:8000/app/",
    path: str = "/app/",
    addresses: tuple[str, ...] = ("10.0.0.5",),
):
    return SimpleNamespace(
        normalized_url=url,
        scheme="http",
        hostname="lab.internal",
        port=8000,
        path=path,
        resolved_addresses=addresses,
    )


def issue(store: AuthorizationStore, now: datetime):
    return issue_authorization(
        store,
        target(),
        owner="Lab Owner",
        approved_by="Research Supervisor",
        purpose="Passive mapping for authorised research",
        expires_at=now + timedelta(days=7),
        limits=AuthorizationLimits(
            maximum_pages=20,
            maximum_depth=2,
            maximum_requests=100,
            minimum_request_delay_seconds=0.2,
        ),
        now=now,
    )


def test_valid_authorization_accepts_narrower_target_and_limits(tmp_path) -> None:
    now = datetime(2026, 7, 9, 12, tzinfo=UTC)
    store = AuthorizationStore.from_path(tmp_path / "auth.db")
    store.initialize()
    record = issue(store, now)

    decision = validate_scan_authorization(
        store,
        record.authorization_id,
        target(url="http://lab.internal:8000/app/admin/", path="/app/admin/"),
        maximum_pages=10,
        maximum_depth=1,
        maximum_requests=50,
        request_delay_seconds=0.5,
        now=now + timedelta(hours=1),
    )

    assert decision.authorization_id == record.authorization_id
    assert decision.limits.maximum_requests == 50


def test_expired_authorization_is_rejected(tmp_path) -> None:
    now = datetime(2026, 7, 9, 12, tzinfo=UTC)
    store = AuthorizationStore.from_path(tmp_path / "auth.db")
    store.initialize()
    record = issue(store, now)

    with pytest.raises(AuthorizationPolicyError, match="expired"):
        validate_scan_authorization(
            store,
            record.authorization_id,
            target(),
            maximum_pages=20,
            maximum_depth=2,
            maximum_requests=100,
            request_delay_seconds=0.2,
            now=now + timedelta(days=8),
        )


def test_revoked_authorization_is_rejected(tmp_path) -> None:
    now = datetime(2026, 7, 9, 12, tzinfo=UTC)
    store = AuthorizationStore.from_path(tmp_path / "auth.db")
    store.initialize()
    record = issue(store, now)
    store.revoke(record.authorization_id, reason="Permission withdrawn", revoked_at=now)

    with pytest.raises(AuthorizationPolicyError, match="revoked"):
        validate_scan_authorization(
            store,
            record.authorization_id,
            target(),
            maximum_pages=20,
            maximum_depth=2,
            maximum_requests=100,
            request_delay_seconds=0.2,
            now=now + timedelta(minutes=1),
        )


def test_target_outside_authorized_path_is_rejected(tmp_path) -> None:
    now = datetime(2026, 7, 9, 12, tzinfo=UTC)
    store = AuthorizationStore.from_path(tmp_path / "auth.db")
    store.initialize()
    record = issue(store, now)

    with pytest.raises(AuthorizationPolicyError, match="path boundary"):
        validate_scan_authorization(
            store,
            record.authorization_id,
            target(url="http://lab.internal:8000/admin/", path="/admin/"),
            maximum_pages=20,
            maximum_depth=2,
            maximum_requests=100,
            request_delay_seconds=0.2,
            now=now + timedelta(minutes=1),
        )


def test_new_resolved_address_is_rejected(tmp_path) -> None:
    now = datetime(2026, 7, 9, 12, tzinfo=UTC)
    store = AuthorizationStore.from_path(tmp_path / "auth.db")
    store.initialize()
    record = issue(store, now)

    with pytest.raises(AuthorizationPolicyError, match="address"):
        validate_scan_authorization(
            store,
            record.authorization_id,
            target(addresses=("10.0.0.99",)),
            maximum_pages=20,
            maximum_depth=2,
            maximum_requests=100,
            request_delay_seconds=0.2,
            now=now + timedelta(minutes=1),
        )


def test_request_budget_above_ceiling_is_rejected(tmp_path) -> None:
    now = datetime(2026, 7, 9, 12, tzinfo=UTC)
    store = AuthorizationStore.from_path(tmp_path / "auth.db")
    store.initialize()
    record = issue(store, now)

    with pytest.raises(AuthorizationPolicyError, match="request budget"):
        validate_scan_authorization(
            store,
            record.authorization_id,
            target(),
            maximum_pages=20,
            maximum_depth=2,
            maximum_requests=101,
            request_delay_seconds=0.2,
            now=now + timedelta(minutes=1),
        )


def test_faster_delay_than_authorized_is_rejected(tmp_path) -> None:
    now = datetime(2026, 7, 9, 12, tzinfo=UTC)
    store = AuthorizationStore.from_path(tmp_path / "auth.db")
    store.initialize()
    record = issue(store, now)

    with pytest.raises(AuthorizationPolicyError, match="faster"):
        validate_scan_authorization(
            store,
            record.authorization_id,
            target(),
            maximum_pages=20,
            maximum_depth=2,
            maximum_requests=100,
            request_delay_seconds=0.1,
            now=now + timedelta(minutes=1),
        )
