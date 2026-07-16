"""Authorization registry persistence and integrity tests."""

from __future__ import annotations

import sqlite3
from contextlib import closing
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest

from vulnhunter.authorization import (
    AuthorizationLimits,
    AuthorizationStore,
    issue_authorization,
)
from vulnhunter.exceptions import AuthorizationIntegrityError


def create_record(store: AuthorizationStore):
    now = datetime(2026, 7, 9, 12, tzinfo=UTC)
    target = SimpleNamespace(
        normalized_url="http://127.0.0.1:8080/app/",
        scheme="http",
        hostname="127.0.0.1",
        port=8080,
        path="/app/",
        resolved_addresses=("127.0.0.1",),
    )
    return issue_authorization(
        store,
        target,
        owner="Local Lab",
        approved_by="Supervisor",
        purpose="Controlled passive test",
        expires_at=now + timedelta(days=30),
        evidence_reference="ticket AUTH-17",
        limits=AuthorizationLimits(
            maximum_pages=25,
            maximum_depth=3,
            maximum_requests=120,
            minimum_request_delay_seconds=0.3,
        ),
        now=now,
    )


def test_create_get_and_list_round_trip(tmp_path) -> None:
    store = AuthorizationStore.from_path(tmp_path / "auth.db")
    store.initialize()
    created = create_record(store)

    loaded = store.get(created.authorization_id)
    listed = store.list()

    assert loaded == created
    assert listed == (created,)
    assert len(store.list_events(created.authorization_id)) == 1


def test_tampered_database_record_fails_integrity_check(tmp_path) -> None:
    store = AuthorizationStore.from_path(tmp_path / "auth.db")
    store.initialize()
    created = create_record(store)

    with closing(sqlite3.connect(store.path)) as connection:
        connection.execute(
            "UPDATE authorizations SET purpose = ? WHERE authorization_id = ?",
            ("Tampered purpose", created.authorization_id),
        )
        connection.commit()

    with pytest.raises(AuthorizationIntegrityError, match="integrity"):
        store.get(created.authorization_id)


def test_revoke_preserves_record_and_appends_event(tmp_path) -> None:
    store = AuthorizationStore.from_path(tmp_path / "auth.db")
    store.initialize()
    created = create_record(store)

    revoked = store.revoke(created.authorization_id, reason="Owner withdrew approval")
    event_types = [event.event_type for event in store.list_events(created.authorization_id)]

    assert revoked.status == "revoked"
    assert revoked.revocation_reason == "Owner withdrew approval"
    assert event_types == ["revoked", "created"]


def test_audit_event_details_are_redacted(tmp_path) -> None:
    store = AuthorizationStore.from_path(tmp_path / "auth.db")
    store.initialize()
    created = create_record(store)

    event = store.append_event(
        created.authorization_id,
        "scan_failed",
        {"authorization": "Bearer top-secret-token", "reason": "failure"},
    )

    assert "top-secret-token" not in str(event.detail)
    assert "REDACTED" in str(event.detail)


def test_store_closes_every_database_connection(monkeypatch, tmp_path) -> None:
    opened_connections: list[sqlite3.Connection] = []
    original_connect = sqlite3.connect

    class TrackingConnection(sqlite3.Connection):
        closed_by_store = False

        def close(self) -> None:
            self.closed_by_store = True
            super().close()

    def tracking_connect(*args, **kwargs):
        kwargs["factory"] = TrackingConnection
        connection = original_connect(*args, **kwargs)
        opened_connections.append(connection)
        return connection

    monkeypatch.setattr(sqlite3, "connect", tracking_connect)

    store = AuthorizationStore.from_path(tmp_path / "auth.db")
    store.initialize()
    created = create_record(store)
    store.get(created.authorization_id)
    store.list()
    store.list_events(created.authorization_id)
    store.revoke(created.authorization_id, reason="No longer needed")

    assert opened_connections
    assert all(
        isinstance(connection, TrackingConnection) and connection.closed_by_store
        for connection in opened_connections
    )


def test_repeated_authorization_store_use_stays_bounded(tmp_path) -> None:
    store = AuthorizationStore.from_path(tmp_path / "auth.db")
    store.initialize()
    created = create_record(store)

    for _ in range(300):
        assert store.get(created.authorization_id).authorization_id == created.authorization_id
