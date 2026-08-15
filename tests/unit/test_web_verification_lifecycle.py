from __future__ import annotations

import base64
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import ValidationError

from vulnhunter.actions.models import sha256_json
from vulnhunter.authorization.models import (
    AuthorizationLimits,
    AuthorizationRecord,
    authorization_record_sha256,
)
from vulnhunter.authorization.store import AuthorizationStore
from vulnhunter.governance.store import GovernanceStore
from vulnhunter.security_tools.opensandbox_supply_chain import public_key_id
from vulnhunter.web_hunters.models import VerificationStrategy
from vulnhunter.web_verification import (
    ExternalEvidenceAdmissionService,
    ExternalEvidenceClass,
    ExternalEvidenceOutcome,
    ExternalEvidenceSignature,
    IndependentVerificationResult,
    SignedExternalEvidenceSubmission,
    TrustedExternalEvidenceCollector,
    VerificationEvidenceReference,
    VerificationLifecycleService,
    VerificationLifecycleStore,
    VerificationReason,
    VerificationVerdict,
    VerificationWorkerRegistry,
    WebVerificationContractError,
    authorization_reference_sha256,
    build_external_evidence_receipt,
    build_external_evidence_trust_policy,
    default_verification_worker_capabilities,
    external_evidence_signing_bytes,
    target_reference_sha256,
    verification_id_for,
)

_NOW = datetime(2026, 8, 15, 15, 0, tzinfo=UTC)
_TARGET = "http://10.22.0.7:8080/app"


class RecordingProjector:
    def __init__(self) -> None:
        self.events: list[tuple[str, str | None]] = []

    def evidence_admitted(self, run_id: str | None) -> None:
        self.events.append(("evidence", run_id))

    def adjudicated(self, run_id: str | None) -> None:
        self.events.append(("adjudicated", run_id))

    def finalized(self, run_id: str | None) -> None:
        self.events.append(("finalized", run_id))


def _authorization(
    store: AuthorizationStore, *, expires_at: datetime | None = None
) -> AuthorizationRecord:
    data: dict[str, object] = {
        "authorization_id": "auth-verification-lab01",
        "target_url": _TARGET,
        "scheme": "http",
        "hostname": "10.22.0.7",
        "port": 8080,
        "path_boundary": "/app",
        "approved_addresses": ("10.22.0.7",),
        "owner": "target-owner",
        "approved_by": "independent-approver",
        "purpose": "Private-lab verification lifecycle test.",
        "evidence_reference": "test fixture",
        "issued_at": _NOW - timedelta(minutes=20),
        "valid_from": _NOW - timedelta(minutes=20),
        "expires_at": expires_at or _NOW + timedelta(hours=1),
        "limits": AuthorizationLimits(
            maximum_pages=10,
            maximum_depth=2,
            maximum_requests=100,
            minimum_request_delay_seconds=1,
        ),
        "status": "active",
        "revoked_at": None,
        "revocation_reason": None,
        "record_sha256": "0" * 64,
    }
    data["record_sha256"] = authorization_record_sha256(data)
    record = AuthorizationRecord.model_validate(data)
    store.create(record)
    return record


def _passive_result(strategy: VerificationStrategy = VerificationStrategy.API_ACCESS_REVIEW):
    evidence = VerificationEvidenceReference(
        hunter_result_sha256="1" * 64,
        perception_plan_sha256="2" * 64,
        perception_evidence_sha256="3" * 64,
        graph_sha256="4" * 64,
        hypothesis_sha256="5" * 64,
        verification_intent_sha256="6" * 64,
        target_reference_sha256=target_reference_sha256(_TARGET),
        hypothesis_id="8" * 64,
        intent_id="9" * 64,
        target_node_id="a" * 64,
        node_ids=("a" * 64,),
    )
    verifier_id = "deterministic-passive-web-verifier-v1"
    verification_id = verification_id_for(
        verifier_id=verifier_id,
        hunter_result_sha256=evidence.hunter_result_sha256,
        hypothesis_id=evidence.hypothesis_id,
        intent_id=evidence.intent_id,
    )
    payload = {
        "schema_version": 1,
        "verification_id": verification_id,
        "verifier_id": verifier_id,
        "hunter_id": "api-access",
        "vulnerability_class": "api_access_control_candidate",
        "strategy": strategy.value,
        "verdict": VerificationVerdict.INCONCLUSIVE.value,
        "reason": VerificationReason.PASSIVE_EVIDENCE_INSUFFICIENT.value,
        "structural_predicate_reproduced": True,
        "evidence": evidence.model_dump(mode="json"),
        "started_at": "2026-08-15T14:30:00Z",
        "completed_at": "2026-08-15T14:30:00Z",
        "network_access_performed": False,
        "mutating_request_performed": False,
        "credential_use_performed": False,
        "authorization_bypass_performed": False,
        "shell_execution_performed": False,
        "external_evidence_accepted": False,
    }
    return IndependentVerificationResult(
        verification_id=verification_id,
        verifier_id=verifier_id,
        hunter_id="api-access",
        vulnerability_class="api_access_control_candidate",
        strategy=strategy,
        verdict=VerificationVerdict.INCONCLUSIVE,
        reason=VerificationReason.PASSIVE_EVIDENCE_INSUFFICIENT,
        structural_predicate_reproduced=True,
        evidence=evidence,
        started_at=_NOW - timedelta(minutes=30),
        completed_at=_NOW - timedelta(minutes=30),
        result_sha256=sha256_json(payload),
    )


def _collector(strategy: VerificationStrategy):
    private = Ed25519PrivateKey.generate()
    public = private.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    policy = build_external_evidence_trust_policy(
        collector_id="offline-evidence-collector-v1",
        collector_key_id=public_key_id(public),
        allowed_strategies=(strategy,),
        maximum_evidence_bytes=4096,
    )
    return private, TrustedExternalEvidenceCollector(policy=policy, public_key_pem=public)


def _submission(
    passive: IndependentVerificationResult,
    record: AuthorizationRecord,
    private: Ed25519PrivateKey,
    collector: TrustedExternalEvidenceCollector,
    *,
    evidence_class: ExternalEvidenceClass = ExternalEvidenceClass.OFFLINE_ARTIFACT_REVIEW,
    outcome: ExternalEvidenceOutcome = ExternalEvidenceOutcome.SUPPORTS_HYPOTHESIS,
    evidence_sha: str = "b" * 64,
) -> SignedExternalEvidenceSubmission:
    receipt = build_external_evidence_receipt(
        passive_result=passive,
        collector_id=collector.policy.collector_id,
        collector_key_id=collector.policy.collector_key_id,
        authorization_reference_sha256=authorization_reference_sha256(record.authorization_id),
        authorization_snapshot_sha256=record.record_sha256,
        collection_plan_sha256="c" * 64,
        collector_runtime_sha256="d" * 64,
        evidence_sha256=evidence_sha,
        evidence_bytes=512,
        evidence_class=evidence_class,
        outcome=outcome,
        started_at=_NOW - timedelta(minutes=10),
        completed_at=_NOW - timedelta(minutes=9),
    )
    signature = ExternalEvidenceSignature(
        key_id=collector.policy.collector_key_id,
        signature=base64.b64encode(private.sign(external_evidence_signing_bytes(receipt))).decode(
            "ascii"
        ),
    )
    return SignedExternalEvidenceSubmission(receipt=receipt, signature=signature)


def _service(tmp_path, monkeypatch, *, strategy=VerificationStrategy.API_ACCESS_REVIEW):
    authorization_store = AuthorizationStore(tmp_path / "authorization.sqlite3")
    authorization_store.initialize()
    record = _authorization(authorization_store)
    lifecycle_store = VerificationLifecycleStore(tmp_path / "verification.sqlite3")
    governance_store = GovernanceStore(tmp_path / "governance.sqlite3")
    private, collector = _collector(strategy)
    projector = RecordingProjector()

    roles = {
        "reviewer-one": "reviewer",
        "reviewer-two": "reviewer",
        "reviewer-three": "reviewer",
        "adjudicator-one": "adjudicator",
    }

    def fake_authenticate(_store, reviewer_id, secret, *, required_role=None):
        normalized = reviewer_id.strip().casefold()
        if secret != f"secret-{normalized}" or roles.get(normalized) != required_role:
            raise RuntimeError("authentication rejected")
        return SimpleNamespace(reviewer_id=normalized)

    monkeypatch.setattr(
        "vulnhunter.web_verification.lifecycle.authenticate_identity", fake_authenticate
    )
    service = VerificationLifecycleService(
        lifecycle_store=lifecycle_store,
        authorization_store=authorization_store,
        governance_store=governance_store,
        evidence_admission=ExternalEvidenceAdmissionService((collector,), clock=lambda: _NOW),
        projector=projector,
        clock=lambda: _NOW,
    )
    return service, record, private, collector, projector


def test_durable_receipt_replay_is_rejected_after_store_restart(tmp_path, monkeypatch) -> None:
    service, record, private, collector, _ = _service(tmp_path, monkeypatch)
    passive = _passive_result()
    submission = _submission(passive, record, private, collector)
    created = service.admit_evidence(
        authorization_id=record.authorization_id,
        passive_result=passive,
        submissions=(submission,),
    )
    assert created.revision == 0
    reopened = VerificationLifecycleStore(tmp_path / "verification.sqlite3")
    restarted = VerificationLifecycleService(
        lifecycle_store=reopened,
        authorization_store=service.authorization_store,
        governance_store=service.governance_store,
        evidence_admission=service.evidence_admission,
        clock=lambda: _NOW,
    )
    with pytest.raises(WebVerificationContractError, match="replay|duplicate"):
        restarted.admit_evidence(
            authorization_id=record.authorization_id,
            passive_result=passive,
            submissions=(submission,),
        )


def test_live_authorization_snapshot_and_revocation_fail_closed(tmp_path, monkeypatch) -> None:
    service, record, private, collector, _ = _service(tmp_path, monkeypatch)
    passive = _passive_result()
    submission = _submission(passive, record, private, collector)
    service.authorization_store.revoke(
        record.authorization_id, reason="test revocation", revoked_at=_NOW
    )
    with pytest.raises(WebVerificationContractError, match="revoked"):
        service.admit_evidence(
            authorization_id=record.authorization_id,
            passive_result=passive,
            submissions=(submission,),
        )


def test_stale_authorization_digest_and_target_binding_fail_closed(tmp_path, monkeypatch) -> None:
    service, record, private, collector, _ = _service(tmp_path, monkeypatch)
    passive = _passive_result()
    submission = _submission(passive, record, private, collector)
    tampered = submission.receipt.model_copy(update={"authorization_snapshot_sha256": "0" * 64})
    bad = submission.model_copy(update={"receipt": tampered})
    with pytest.raises(WebVerificationContractError, match="snapshot"):
        service.admit_evidence(
            authorization_id=record.authorization_id,
            passive_result=passive,
            submissions=(bad,),
        )


def test_validation_grade_support_requires_human_consensus(tmp_path, monkeypatch) -> None:
    service, record, private, collector, projector = _service(tmp_path, monkeypatch)
    passive = _passive_result()
    submission = _submission(passive, record, private, collector)
    case = service.admit_evidence(
        authorization_id=record.authorization_id,
        passive_result=passive,
        submissions=(submission,),
        assessment_run_id="assessment-lifecycle-01",
        workspace_id="workspace-01",
    )
    case = service.adjudicate(case.case_id, expected_revision=0)
    adjudication = service.store.get_adjudication(case.case_id)
    assert adjudication.candidate_verdict is VerificationVerdict.VALIDATED
    with pytest.raises(WebVerificationContractError, match="two distinct primary"):
        service.finalize(case.case_id, expected_revision=1)
    case = service.record_primary_review(
        case.case_id,
        expected_revision=1,
        reviewer_id="reviewer-one",
        reviewer_secret="secret-reviewer-one",
        verdict=VerificationVerdict.VALIDATED,
    )
    case = service.record_primary_review(
        case.case_id,
        expected_revision=2,
        reviewer_id="reviewer-two",
        reviewer_secret="secret-reviewer-two",
        verdict=VerificationVerdict.VALIDATED,
    )
    decision = service.finalize(case.case_id, expected_revision=3)
    assert decision.verdict is VerificationVerdict.VALIDATED
    assert decision.automatic_remediation_permitted is False
    assert service.status(case.case_id)["final_verdict"] == "validated"
    assert projector.events == [
        ("evidence", "assessment-lifecycle-01"),
        ("adjudicated", "assessment-lifecycle-01"),
        ("finalized", "assessment-lifecycle-01"),
    ]


def test_read_only_metadata_support_cannot_be_upgraded_to_validated(tmp_path, monkeypatch) -> None:
    strategy = VerificationStrategy.API_ACCESS_REVIEW
    service, record, private, collector, _ = _service(tmp_path, monkeypatch, strategy=strategy)
    passive = _passive_result(strategy)
    submission = _submission(
        passive,
        record,
        private,
        collector,
        evidence_class=ExternalEvidenceClass.READ_ONLY_HTTP_METADATA,
    )
    case = service.admit_evidence(
        authorization_id=record.authorization_id,
        passive_result=passive,
        submissions=(submission,),
    )
    case = service.adjudicate(case.case_id, expected_revision=0)
    adjudication = service.store.get_adjudication(case.case_id)
    assert adjudication.candidate_verdict is VerificationVerdict.INCONCLUSIVE
    with pytest.raises(WebVerificationContractError, match="ceiling"):
        service.record_primary_review(
            case.case_id,
            expected_revision=1,
            reviewer_id="reviewer-one",
            reviewer_secret="secret-reviewer-one",
            verdict=VerificationVerdict.VALIDATED,
        )


def test_refutation_produces_rejected_candidate(tmp_path, monkeypatch) -> None:
    service, record, private, collector, _ = _service(tmp_path, monkeypatch)
    passive = _passive_result()
    submission = _submission(
        passive,
        record,
        private,
        collector,
        outcome=ExternalEvidenceOutcome.REFUTES_HYPOTHESIS,
    )
    case = service.admit_evidence(
        authorization_id=record.authorization_id,
        passive_result=passive,
        submissions=(submission,),
    )
    service.adjudicate(case.case_id, expected_revision=0)
    assert (
        service.store.get_adjudication(case.case_id).candidate_verdict
        is VerificationVerdict.REJECTED
    )


def test_disagreement_requires_distinct_authenticated_adjudicator(tmp_path, monkeypatch) -> None:
    service, record, private, collector, _ = _service(tmp_path, monkeypatch)
    passive = _passive_result()
    submission = _submission(passive, record, private, collector)
    case = service.admit_evidence(
        authorization_id=record.authorization_id,
        passive_result=passive,
        submissions=(submission,),
    )
    case = service.adjudicate(case.case_id, expected_revision=0)
    case = service.record_primary_review(
        case.case_id,
        expected_revision=1,
        reviewer_id="reviewer-one",
        reviewer_secret="secret-reviewer-one",
        verdict=VerificationVerdict.VALIDATED,
    )
    case = service.record_primary_review(
        case.case_id,
        expected_revision=2,
        reviewer_id="reviewer-two",
        reviewer_secret="secret-reviewer-two",
        verdict=VerificationVerdict.INCONCLUSIVE,
    )
    with pytest.raises(WebVerificationContractError, match="adjudicator"):
        service.finalize(case.case_id, expected_revision=3)
    case = service.record_adjudicator_review(
        case.case_id,
        expected_revision=3,
        reviewer_id="adjudicator-one",
        reviewer_secret="secret-adjudicator-one",
        verdict=VerificationVerdict.INCONCLUSIVE,
    )
    assert (
        service.finalize(case.case_id, expected_revision=4).verdict
        is VerificationVerdict.INCONCLUSIVE
    )


def test_stale_compare_and_swap_and_duplicate_reviewer_fail_closed(tmp_path, monkeypatch) -> None:
    service, record, private, collector, _ = _service(tmp_path, monkeypatch)
    passive = _passive_result()
    submission = _submission(passive, record, private, collector)
    case = service.admit_evidence(
        authorization_id=record.authorization_id,
        passive_result=passive,
        submissions=(submission,),
    )
    case = service.adjudicate(case.case_id, expected_revision=0)
    with pytest.raises(WebVerificationContractError, match="stale"):
        service.record_primary_review(
            case.case_id,
            expected_revision=0,
            reviewer_id="reviewer-one",
            reviewer_secret="secret-reviewer-one",
            verdict=VerificationVerdict.VALIDATED,
        )
    case = service.record_primary_review(
        case.case_id,
        expected_revision=1,
        reviewer_id="reviewer-one",
        reviewer_secret="secret-reviewer-one",
        verdict=VerificationVerdict.VALIDATED,
    )
    with pytest.raises(WebVerificationContractError, match="distinct|only one"):
        service.record_primary_review(
            case.case_id,
            expected_revision=2,
            reviewer_id="reviewer-one",
            reviewer_secret="secret-reviewer-one",
            verdict=VerificationVerdict.VALIDATED,
        )


def test_worker_registry_has_no_mutating_or_shell_authority(tmp_path, monkeypatch) -> None:
    service, record, _private, collector, _ = _service(tmp_path, monkeypatch)
    passive = _passive_result()
    registry = VerificationWorkerRegistry(default_verification_worker_capabilities())
    workers = registry.compatible_workers(passive.strategy)
    assert workers
    assert all(item.mutating_requests_allowed is False for item in workers)
    assert all(item.credential_use_allowed is False for item in workers)
    assert all(item.authorization_bypass_allowed is False for item in workers)
    assert all(item.shell_execution_allowed is False for item in workers)
    assert all(item.payload_execution_allowed is False for item in workers)
    plan = registry.build_plan(
        worker_id="offline-artifact-verifier-v1",
        collector=collector,
        authorization=record,
        passive_result=passive,
        now=_NOW,
    )
    assert plan.execution_command_included is False
    assert plan.network_access_allowed is False
    with pytest.raises(ValidationError):
        plan.model_copy(update={"network_methods": ("POST",)}).__class__.model_validate(
            {**plan.model_dump(), "network_methods": ("POST",)}
        )
