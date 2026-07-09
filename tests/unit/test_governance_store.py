from __future__ import annotations

import json
import sqlite3

import pytest
from governance_test_support import ADMIN_SECRET, NOW, make_governance_store

from vulnhunter.exceptions import GovernanceIntegrityError
from vulnhunter.governance.service import bootstrap_administrator


def test_identity_round_trip_and_event_chain(tmp_path) -> None:
    governance_store = make_governance_store(tmp_path)
    identity = bootstrap_administrator(
        governance_store,
        reviewer_id="admin-a",
        display_name="Administrator",
        secret=ADMIN_SECRET,
        now=NOW,
    )

    assert governance_store.get_identity("admin-a") == identity
    assert governance_store.list_events()[0].event_type == "created"
    governance_store.verify_integrity()


def test_tampered_identity_record_is_detected(tmp_path) -> None:
    governance_store = make_governance_store(tmp_path)
    bootstrap_administrator(
        governance_store,
        reviewer_id="admin-a",
        display_name="Administrator",
        secret=ADMIN_SECRET,
        now=NOW,
    )

    with sqlite3.connect(governance_store.path) as connection:
        row = connection.execute(
            "SELECT record_json FROM governance_identities WHERE reviewer_id = ?",
            ("admin-a",),
        ).fetchone()
        payload = json.loads(row[0])
        payload["display_name"] = "Tampered Administrator"
        connection.execute(
            "UPDATE governance_identities SET record_json = ? WHERE reviewer_id = ?",
            (json.dumps(payload), "admin-a"),
        )

    with pytest.raises(GovernanceIntegrityError, match="integrity"):
        governance_store.get_identity("admin-a")


def test_tampered_event_chain_is_detected(tmp_path) -> None:
    governance_store = make_governance_store(tmp_path)
    bootstrap_administrator(
        governance_store,
        reviewer_id="admin-a",
        display_name="Administrator",
        secret=ADMIN_SECRET,
        now=NOW,
    )

    with sqlite3.connect(governance_store.path) as connection:
        connection.execute(
            "UPDATE governance_events SET detail_json = ? WHERE event_id = 1",
            ('{"roles":["reviewer"]}',),
        )

    with pytest.raises(GovernanceIntegrityError, match="event 1"):
        governance_store.verify_integrity()


def test_event_details_are_redacted(tmp_path) -> None:
    governance_store = make_governance_store(tmp_path)
    bootstrap_administrator(
        governance_store,
        reviewer_id="admin-a",
        display_name="Administrator",
        secret=ADMIN_SECRET,
        now=NOW,
    )
    event = governance_store.append_event(
        subject_type="campaign",
        subject_id="campaign-test",
        event_type="test",
        actor_id="admin-a",
        detail={"secret": "do-not-store", "reason": "safe"},
    )

    assert "do-not-store" not in str(event.detail)
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

    governance_store = make_governance_store(tmp_path)
    assert governance_store.identity_count() == 0

    assert opened_connections
    assert all(
        isinstance(connection, TrackingConnection) and connection.closed_by_store
        for connection in opened_connections
    )
