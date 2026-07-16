import hashlib
import json
import sqlite3
from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError

from vulnhunter.actions.models import sha256_json
from vulnhunter.oracle import (
    DurableResponseReplayLedger,
    FindingClaim,
    OracleResponse,
    OracleSession,
    OracleSessionStatus,
    OracleStore,
    OracleStoreError,
    OracleVerdict,
    OracleVerifier,
    PentestAiConnector,
    PentestAiConnectorError,
    ProofCapsule,
    StructuredObservation,
    VerificationStrategy,
)

DIGEST = "a" * 64
ACTION = "b" * 64


class StaticAuthenticator:
    def __init__(self, *, allowed: bool = True) -> None:
        self.allowed = allowed

    def authenticate(self, capsule: ProofCapsule, response: OracleResponse) -> bool:
        return self.allowed and response.capsule_sha256 == capsule.capsule_hash()


def _capsule(**updates):
    claim = FindingClaim(
        claim_id="finding-claim",
        title="Exported activity is present",
        claimed_severity="medium",
        claimed_confidence="high",
    )
    observation = StructuredObservation(
        observation_id="obs-01",
        evidence_sha256=DIGEST,
        observation_type="manifest_fact",
        value="activity exported true",
    )
    base = {
        "capsule_id": "capsule-01",
        "candidate_finding_id": "finding-01",
        "campaign_id": "campaign-01",
        "authorization_reference": "auth-01",
        "scope_reference": "scope-01",
        "target_identity": "apk:sample",
        "action_manifest_sha256": ACTION,
        "original_tool": "aapt2",
        "original_adapter_version": "adapter-1",
        "original_tool_version": "tool-1",
        "evidence_hashes": (DIGEST,),
        "structured_observations": (observation,),
        "finding_claim": claim,
        "claim_author": "scanner-01",
        "expected_verification_rule": "manifest-exported-component",
        "verification_limits": {"maximum_attempts": 1},
        "permitted_strategies": (VerificationStrategy.DETERMINISTIC_REPLAY,),
        "created_at": datetime(2026, 1, 1, tzinfo=UTC),
        "expires_at": datetime(2026, 1, 2, tzinfo=UTC),
        "redaction_policy": "standard",
        "customer_boundary": "customer-01",
        "provenance_chain": ("evidence-ledger",),
    }
    base.update(updates)
    return ProofCapsule(**base)


def test_proof_capsule_hash_is_deterministic_and_mutation_changes_it():
    first = _capsule()
    second = _capsule()
    changed = _capsule(target_identity="apk:changed")

    assert first.capsule_hash() == second.capsule_hash()
    assert first.capsule_hash() != changed.capsule_hash()


def test_capsule_rejects_path_traversal_and_expiry_is_verdict():
    with pytest.raises(ValidationError, match="path traversal"):
        _capsule(scope_reference="../scope")

    expired = _capsule(expires_at=datetime(2026, 1, 1, 1, tzinfo=UTC))
    result = OracleVerifier().verify(
        expired,
        verifier_identity="oracle-01",
        now=datetime(2026, 1, 2, tzinfo=UTC),
    )
    assert result.verdict == OracleVerdict.EXPIRED


def test_oracle_cannot_verify_its_own_generated_claim_or_model_only_consequence():
    self_verified = OracleVerifier().verify(
        _capsule(),
        verifier_identity="scanner-01",
        now=datetime(2026, 1, 1, 1, tzinfo=UTC),
    )
    assert self_verified.verdict == OracleVerdict.VERIFICATION_BLOCKED

    consequential = _capsule(
        finding_claim=FindingClaim(
            claim_id="finding-claim",
            title="Consequential issue",
            claimed_severity="high",
            claimed_confidence="medium",
            consequential=True,
        ),
        permitted_strategies=(VerificationStrategy.MODEL_ASSISTED_REVIEW,),
    )
    result = OracleVerifier().verify(
        consequential,
        verifier_identity="oracle-01",
        strategy=VerificationStrategy.MODEL_ASSISTED_REVIEW,
        now=datetime(2026, 1, 1, 1, tzinfo=UTC),
    )
    assert result.verdict == OracleVerdict.INSUFFICIENT_EVIDENCE


def test_deterministic_replay_can_verify_rule_hash():
    capsule = _capsule()
    rule_hash = sha256_json(
        {
            "claim": capsule.finding_claim.model_dump(mode="json"),
            "observations": [
                item.model_dump(mode="json") for item in capsule.structured_observations
            ],
            "rule": capsule.expected_verification_rule,
        }
    )
    verified = _capsule(evidence_hashes=(DIGEST, rule_hash))

    result = OracleVerifier().verify(
        verified,
        verifier_identity="oracle-01",
        now=datetime(2026, 1, 1, 1, tzinfo=UTC),
    )
    assert result.verdict == OracleVerdict.VERIFIED


def _trusted_connector(tmp_path, *, authenticator=None) -> PentestAiConnector:
    return PentestAiConnector(
        trusted_verifier_identities=("oracle-01",),
        supported_versions=("internal-deterministic-1",),
        authenticator=authenticator,
        replay_ledger=DurableResponseReplayLedger(tmp_path / "replay"),
    )


def test_pentest_ai_connector_disabled_and_requires_authenticator(tmp_path):
    capsule = _capsule()
    connector = _trusted_connector(tmp_path, authenticator=StaticAuthenticator())
    with pytest.raises(PentestAiConnectorError, match="disabled"):
        connector.submit(capsule)

    unauthenticated = PentestAiConnector(
        trusted_verifier_identities=("oracle-01",),
        supported_versions=("internal-deterministic-1",),
        replay_ledger=DurableResponseReplayLedger(tmp_path / "replay"),
    )
    response = OracleVerifier().verify(
        capsule,
        verifier_identity="oracle-01",
        now=datetime(2026, 1, 1, 1, tzinfo=UTC),
    )
    with pytest.raises(PentestAiConnectorError, match="authenticator"):
        unauthenticated.validate_response(capsule, response)


def test_forged_trusted_identity_response_is_rejected_without_authentication(tmp_path):
    capsule = _capsule()
    response = (
        OracleVerifier()
        .verify(
            capsule,
            verifier_identity="oracle-01",
            now=datetime(2026, 1, 1, 1, tzinfo=UTC),
        )
        .model_copy(update={"verdict": OracleVerdict.VERIFIED})
    )
    forged = response.model_copy(update={"response_hash": response.expected_hash()})
    connector = _trusted_connector(tmp_path, authenticator=StaticAuthenticator(allowed=False))

    with pytest.raises(PentestAiConnectorError, match="authentication failed"):
        connector.validate_response(capsule, forged)


def test_authenticated_response_binding_version_and_replay_checks(tmp_path):
    capsule = _capsule()
    response = OracleVerifier().verify(
        capsule,
        verifier_identity="oracle-01",
        now=datetime(2026, 1, 1, 1, tzinfo=UTC),
    )
    connector = _trusted_connector(tmp_path, authenticator=StaticAuthenticator())

    assert connector.validate_response(capsule, response) == response
    with pytest.raises(PentestAiConnectorError, match="replay"):
        connector.validate_response(capsule, response)
    with pytest.raises(PentestAiConnectorError, match="replay"):
        _trusted_connector(tmp_path, authenticator=StaticAuthenticator()).validate_response(
            capsule, response
        )

    other_capsule = _capsule(capsule_id="capsule-02")
    with pytest.raises(PentestAiConnectorError, match="another capsule"):
        _trusted_connector(
            tmp_path / "other",
            authenticator=StaticAuthenticator(),
        ).validate_response(other_capsule, response)

    wrong_identity = response.model_copy(update={"verifier_identity": "oracle-02"})
    wrong_identity = wrong_identity.model_copy(
        update={"response_hash": wrong_identity.expected_hash()}
    )
    with pytest.raises(PentestAiConnectorError, match="unknown verifier"):
        _trusted_connector(
            tmp_path / "identity",
            authenticator=StaticAuthenticator(),
        ).validate_response(
            capsule,
            wrong_identity,
        )

    wrong_version = response.model_copy(update={"verifier_version": "unsupported-1"})
    wrong_version = wrong_version.model_copy(
        update={"response_hash": wrong_version.expected_hash()}
    )
    with pytest.raises(PentestAiConnectorError, match="unsupported"):
        _trusted_connector(
            tmp_path / "version",
            authenticator=StaticAuthenticator(),
        ).validate_response(
            capsule,
            wrong_version,
        )


def test_durable_replay_ledger_rejects_malformed_and_duplicate_claims(tmp_path):
    ledger = DurableResponseReplayLedger(tmp_path / "replay")
    ledger.claim("c" * 64)

    with pytest.raises(PentestAiConnectorError, match="replay"):
        DurableResponseReplayLedger(tmp_path / "replay").claim("c" * 64)
    with pytest.raises(PentestAiConnectorError, match="malformed"):
        ledger.claim("../" + "c" * 64)


def test_malformed_observation_evidence_reference_fails_validation():
    with pytest.raises(ValidationError, match="structured observations"):
        _capsule(evidence_hashes=("c" * 64,))


def test_authenticated_external_conflict_response_is_preserved_candidate_material(tmp_path):
    capsule = _capsule()
    draft = {
        "response_id": "oracle-response-conflict",
        "capsule_sha256": capsule.capsule_hash(),
        "verdict": OracleVerdict.CONFLICTING_EVIDENCE,
        "strategy": VerificationStrategy.SECOND_TOOL_CORROBORATION,
        "verifier_identity": "oracle-01",
        "verifier_version": "internal-deterministic-1",
        "independence_strength": "bounded_independent",
        "evidence_hashes": (DIGEST,),
        "response_hash": "0" * 64,
        "created_at": datetime(2026, 1, 1, 1, tzinfo=UTC),
    }
    temporary = OracleResponse.model_validate(draft)
    response = temporary.model_copy(update={"response_hash": temporary.expected_hash()})

    accepted = _trusted_connector(tmp_path, authenticator=StaticAuthenticator()).validate_response(
        capsule, response
    )

    assert accepted.verdict == OracleVerdict.CONFLICTING_EVIDENCE


def test_oracle_store_rejects_digest_traversal(tmp_path):
    store = OracleStore(tmp_path / "oracle")
    capsule = _capsule()
    store.save_capsule(capsule)
    assert store.load_capsule(capsule.capsule_hash()) == capsule
    with pytest.raises(OracleStoreError, match="malformed"):
        store.load_capsule("../" + capsule.capsule_hash())


def _session(**updates) -> OracleSession:
    created = datetime(2026, 1, 1, tzinfo=UTC)
    base = {
        "session_id": "oracle-session-01",
        "capsule_sha256": "d" * 64,
        "strategy": VerificationStrategy.DETERMINISTIC_REPLAY,
        "verifier_identity": "oracle-01",
        "provider_identity": "internal-provider",
        "connector_identity": "deterministic-connector",
        "authorization_reference": "authorization-01",
        "scope_reference": "scope-01",
        "status": OracleSessionStatus.QUEUED,
        "limits": {"maximum_attempts": 2, "timeout_seconds": 60},
        "created_at": created,
        "last_heartbeat_at": created,
    }
    base.update(updates)
    return OracleSession(**base)


def test_oracle_session_transitions_and_history_are_integrity_checked(tmp_path):
    store = OracleStore(tmp_path / "oracle")
    queued = _session()
    store.create_session(queued)
    with pytest.raises(OracleStoreError, match="already exists"):
        store.create_session(queued)

    preparing = queued.model_copy(
        update={"status": OracleSessionStatus.PREPARING, "step": "prepare"}
    )
    store.update_session(
        preparing,
        expected_status=OracleSessionStatus.QUEUED,
        expected_snapshot_sha256=store.session_snapshot_hash(queued),
    )
    verifying = preparing.model_copy(
        update={"status": OracleSessionStatus.VERIFYING, "step": "verify", "attempt": 1}
    )
    store.update_session(
        verifying,
        expected_status=OracleSessionStatus.PREPARING,
        expected_snapshot_sha256=store.session_snapshot_hash(preparing),
    )
    completed = verifying.model_copy(
        update={
            "status": OracleSessionStatus.COMPLETED,
            "step": "complete",
            "final_verdict": OracleVerdict.INSUFFICIENT_EVIDENCE,
        }
    )
    store.update_session(
        completed,
        expected_status=OracleSessionStatus.VERIFYING,
        expected_snapshot_sha256=store.session_snapshot_hash(verifying),
    )

    assert store.load_session(queued.session_id) == completed
    events = store.load_session_events(queued.session_id)
    assert [event.sequence for event in events] == [1, 2, 3, 4]
    assert events[-1].previous_sha256 == events[-2].event_sha256

    with pytest.raises(OracleStoreError, match="terminal"):
        store.update_session(
            queued,
            expected_status=OracleSessionStatus.COMPLETED,
            expected_snapshot_sha256=store.session_snapshot_hash(completed),
        )
    assert store.load_session(queued.session_id) == completed
    assert store.load_session_events(queued.session_id) == events


def test_oracle_session_rejects_stale_or_invalid_updates(tmp_path):
    store = OracleStore(tmp_path / "oracle")
    queued = _session()
    store.create_session(queued)
    preparing = queued.model_copy(update={"status": OracleSessionStatus.PREPARING})

    with pytest.raises(OracleStoreError, match="stale expected status"):
        store.update_session(
            preparing,
            expected_status=OracleSessionStatus.VERIFYING,
            expected_snapshot_sha256=store.session_snapshot_hash(queued),
        )
    with pytest.raises(OracleStoreError, match="stale expected snapshot"):
        store.update_session(
            preparing,
            expected_status=OracleSessionStatus.QUEUED,
            expected_snapshot_sha256="e" * 64,
        )
    with pytest.raises(OracleStoreError, match="invalid Oracle session transition"):
        store.update_session(
            queued.model_copy(
                update={
                    "status": OracleSessionStatus.COMPLETED,
                    "final_verdict": OracleVerdict.INSUFFICIENT_EVIDENCE,
                }
            ),
            expected_status=OracleSessionStatus.QUEUED,
            expected_snapshot_sha256=store.session_snapshot_hash(queued),
        )

    assert store.load_session(queued.session_id) == queued
    assert len(store.load_session_events(queued.session_id)) == 1


@pytest.mark.parametrize(
    "session",
    [
        _session(
            status=OracleSessionStatus.COMPLETED,
            step="complete",
            final_verdict=OracleVerdict.INSUFFICIENT_EVIDENCE,
        ),
        _session(status=OracleSessionStatus.CANCELLED, step="cancelled"),
        _session(
            status=OracleSessionStatus.FAILED,
            step="failed",
            safe_error_category="verifier_unavailable",
        ),
    ],
)
def test_oracle_session_creation_requires_canonical_queued_state(tmp_path, session):
    store = OracleStore(tmp_path / "oracle")

    with pytest.raises(OracleStoreError, match="canonical queued state"):
        store.create_session(session)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("capsule_sha256", "e" * 64),
        ("verifier_identity", "oracle-02"),
        ("strategy", VerificationStrategy.EVIDENCE_CONSISTENCY_CHECK),
        ("limits", {"maximum_attempts": 3, "timeout_seconds": 60}),
        ("provider_identity", "other-provider"),
        ("connector_identity", "other-connector"),
        ("authorization_reference", "authorization-02"),
        ("scope_reference", "scope-02"),
    ],
)
def test_oracle_session_immutable_identity_and_configuration_cannot_change(tmp_path, field, value):
    store = OracleStore(tmp_path / "oracle")
    queued = _session()
    store.create_session(queued)
    changed = queued.model_copy(
        update={
            "status": OracleSessionStatus.PREPARING,
            "step": "prepare",
            field: value,
        }
    )

    with pytest.raises(OracleStoreError, match="immutable Oracle session field"):
        store.update_session(
            changed,
            expected_status=queued.status,
            expected_snapshot_sha256=store.session_snapshot_hash(queued),
        )


def _advance_to_verifying(store: OracleStore) -> tuple[OracleSession, OracleSession]:
    queued = _session()
    store.create_session(queued)
    preparing = queued.model_copy(
        update={
            "status": OracleSessionStatus.PREPARING,
            "step": "prepare",
            "last_heartbeat_at": queued.last_heartbeat_at + timedelta(seconds=1),
        }
    )
    store.update_session(
        preparing,
        expected_status=queued.status,
        expected_snapshot_sha256=store.session_snapshot_hash(queued),
    )
    verifying = preparing.model_copy(
        update={
            "status": OracleSessionStatus.VERIFYING,
            "step": "verify",
            "attempt": 1,
            "produced_evidence_hashes": ("1" * 64, "2" * 64),
            "last_heartbeat_at": preparing.last_heartbeat_at + timedelta(seconds=1),
        }
    )
    store.update_session(
        verifying,
        expected_status=preparing.status,
        expected_snapshot_sha256=store.session_snapshot_hash(preparing),
    )
    return preparing, verifying


@pytest.mark.parametrize(
    ("updates", "message"),
    [
        ({"produced_evidence_hashes": ("1" * 64,)}, "append-only"),
        ({"produced_evidence_hashes": ("1" * 64, "3" * 64)}, "append-only"),
        ({"attempt": 0}, "attempt cannot decrease"),
        (
            {"last_heartbeat_at": datetime(2026, 1, 1, 0, 0, 1, tzinfo=UTC)},
            "heartbeat cannot move backwards",
        ),
    ],
)
def test_oracle_session_monotonic_state_is_enforced(tmp_path, updates, message):
    store = OracleStore(tmp_path / "oracle")
    _, verifying = _advance_to_verifying(store)
    invalid = verifying.model_copy(update=updates)

    with pytest.raises(OracleStoreError, match=message):
        store.update_session(
            invalid,
            expected_status=verifying.status,
            expected_snapshot_sha256=store.session_snapshot_hash(verifying),
        )


def test_oracle_session_stale_concurrent_update_loses(tmp_path):
    store = OracleStore(tmp_path / "oracle")
    queued = _session()
    store.create_session(queued)
    expected_hash = store.session_snapshot_hash(queued)
    preparing = queued.model_copy(
        update={"status": OracleSessionStatus.PREPARING, "step": "prepare"}
    )
    cancelled = queued.model_copy(
        update={"status": OracleSessionStatus.CANCELLED, "step": "cancelled"}
    )
    store.update_session(
        preparing,
        expected_status=OracleSessionStatus.QUEUED,
        expected_snapshot_sha256=expected_hash,
    )

    with pytest.raises(OracleStoreError, match="stale expected status"):
        store.update_session(
            cancelled,
            expected_status=OracleSessionStatus.QUEUED,
            expected_snapshot_sha256=expected_hash,
        )


def _read_session_row(store: OracleStore) -> tuple[dict[str, object], list[dict[str, object]]]:
    with sqlite3.connect(store.database_path) as connection:
        connection.row_factory = sqlite3.Row
        row = connection.execute(
            "SELECT * FROM oracle_sessions WHERE session_id=?",
            ("oracle-session-01",),
        ).fetchone()
    assert row is not None
    values = dict(row)
    return values, json.loads(str(values["history_json"]))


def _write_history(
    store: OracleStore,
    events: list[dict[str, object]],
    *,
    event_count: int | None = None,
    last_event_sha256: str | None = None,
) -> None:
    history_json = json.dumps(events, sort_keys=True, separators=(",", ":"))
    history_sha256 = hashlib.sha256(history_json.encode()).hexdigest()
    with sqlite3.connect(store.database_path) as connection:
        connection.execute(
            """
            UPDATE oracle_sessions
            SET history_json=?, history_sha256=?, event_count=?, last_event_sha256=?
            WHERE session_id=?
            """,
            (
                history_json,
                history_sha256,
                len(events) if event_count is None else event_count,
                (
                    str(events[-1]["event_sha256"])
                    if last_event_sha256 is None and events
                    else last_event_sha256 or "0" * 64
                ),
                "oracle-session-01",
            ),
        )


def test_oracle_history_modified_event_payload_is_detected(tmp_path):
    store = OracleStore(tmp_path / "oracle")
    _advance_to_verifying(store)
    _, events = _read_session_row(store)
    events[0]["snapshot"]["step"] = "tampered"
    _write_history(store, events)

    with pytest.raises(OracleStoreError, match="snapshot hash|event hash"):
        store.load_session("oracle-session-01")


def test_oracle_history_modified_event_hash_is_detected(tmp_path):
    store = OracleStore(tmp_path / "oracle")
    _advance_to_verifying(store)
    _, events = _read_session_row(store)
    events[0]["event_sha256"] = "e" * 64
    _write_history(store, events)

    with pytest.raises(OracleStoreError, match="event hash"):
        store.load_session("oracle-session-01")


def test_oracle_history_broken_previous_hash_is_detected(tmp_path):
    store = OracleStore(tmp_path / "oracle")
    _advance_to_verifying(store)
    _, events = _read_session_row(store)
    events[1]["previous_sha256"] = "e" * 64
    _write_history(store, events)

    with pytest.raises(OracleStoreError, match="previous event hash"):
        store.load_session("oracle-session-01")


def test_oracle_history_missing_event_is_detected(tmp_path):
    store = OracleStore(tmp_path / "oracle")
    _advance_to_verifying(store)
    _, events = _read_session_row(store)
    del events[1]
    _write_history(store, events, event_count=3)

    with pytest.raises(OracleStoreError, match="missing or truncated"):
        store.load_session("oracle-session-01")


def test_oracle_history_reordered_events_are_detected(tmp_path):
    store = OracleStore(tmp_path / "oracle")
    _advance_to_verifying(store)
    _, events = _read_session_row(store)
    events[0], events[1] = events[1], events[0]
    _write_history(store, events)

    with pytest.raises(OracleStoreError, match="sequence"):
        store.load_session("oracle-session-01")


def test_oracle_history_truncation_is_detected(tmp_path):
    store = OracleStore(tmp_path / "oracle")
    _advance_to_verifying(store)
    _, events = _read_session_row(store)
    events.pop()
    _write_history(store, events, event_count=3)

    with pytest.raises(OracleStoreError, match="missing or truncated"):
        store.load_session("oracle-session-01")


def test_oracle_missing_and_malformed_history_fail_closed(tmp_path):
    store = OracleStore(tmp_path / "oracle")
    store.create_session(_session())
    _write_history(store, [])
    with pytest.raises(OracleStoreError, match="history is missing"):
        store.load_session("oracle-session-01")

    malformed = "{}"
    with sqlite3.connect(store.database_path) as connection:
        connection.execute(
            "UPDATE oracle_sessions SET history_json=?, history_sha256=? WHERE session_id=?",
            (
                malformed,
                hashlib.sha256(malformed.encode()).hexdigest(),
                "oracle-session-01",
            ),
        )
    with pytest.raises(OracleStoreError, match="malformed"):
        store.load_session("oracle-session-01")


def test_oracle_snapshot_history_disagreement_is_detected(tmp_path):
    store = OracleStore(tmp_path / "oracle")
    preparing, _ = _advance_to_verifying(store)
    snapshot_json = preparing.model_dump_json()
    snapshot_sha256 = store.session_snapshot_hash(preparing)
    with sqlite3.connect(store.database_path) as connection:
        connection.execute(
            """
            UPDATE oracle_sessions
            SET status=?, snapshot_json=?, snapshot_sha256=?
            WHERE session_id=?
            """,
            (
                preparing.status.value,
                snapshot_json,
                snapshot_sha256,
                "oracle-session-01",
            ),
        )

    with pytest.raises(OracleStoreError, match="snapshot and history disagree"):
        store.load_session("oracle-session-01")
