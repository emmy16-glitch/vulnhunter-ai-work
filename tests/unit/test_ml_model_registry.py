import json
from datetime import UTC, datetime

import pytest

from vulnhunter.ml.model_registry import (
    DETERMINISTIC_FALLBACK_REF,
    ModelRegistry,
    ModelRegistryBoundaryError,
    ModelRegistryPackage,
    model_registry_package_sha256,
)

NOW = datetime(2026, 8, 8, 18, 30, tzinfo=UTC)
SIGNING_KEY = b"registry-signing-key-32-bytes-long!!"
SECRETS = {
    "training_operator": b"training-operator-secret-value",
    "evaluation_reviewer": b"evaluation-reviewer-secret-value",
    "model_promotion_authority": b"model-promotion-secret-value",
    "deployment_operator": b"deployment-operator-secret-value",
    "incident_authority": b"incident-authority-secret-value",
}


def _package(model_id: str, version: str, *, trainer: str = "trainer-a") -> ModelRegistryPackage:
    data = {
        "schema_version": 1,
        "model_id": model_id,
        "version": version,
        "task": "review-priority",
        "model_artifact_sha256": "1" * 64,
        "calibration_artifact_sha256": "2" * 64,
        "ood_policy_sha256": "3" * 64,
        "feature_schema_sha256": "4" * 64,
        "feature_extractor_sha256": "5" * 64,
        "training_release_ids": ("release-001",),
        "training_release_sha256s": ("6" * 64,),
        "partition_programme_id": "partition-001",
        "training_code_commit": "7" * 40,
        "application_version": "0.1.0",
        "dependency_lock_sha256": "8" * 64,
        "random_seeds": (11, 17, 29),
        "candidate_selection_report_sha256": "9" * 64,
        "locked_evaluation_report_sha256": "a" * 64,
        "intended_use": "Prioritise governed observations for human review.",
        "prohibited_uses": ("finding truth", "automatic severity", "target authorization"),
        "limitations": ("Development evidence does not establish real-world performance.",),
        "monitoring_policy_id": "monitoring-review-priority-v1",
        "training_operator_id": trainer,
        "package_sha256": "0" * 64,
    }
    data["package_sha256"] = model_registry_package_sha256(data)
    return ModelRegistryPackage.model_validate(data)


def _registry(tmp_path) -> ModelRegistry:
    return ModelRegistry(
        tmp_path / "registry",
        signing_key=SIGNING_KEY,
        authority_secrets=SECRETS,
    )


def _register_and_approve(
    registry: ModelRegistry,
    package: ModelRegistryPackage,
) -> None:
    registry.register_candidate(
        package,
        actor_id=package.training_operator_id,
        actor_secret=SECRETS["training_operator"],
        reason="Submit complete governed candidate package.",
        now=NOW,
    )
    registry.transition(
        package.reference,
        state="validated",
        actor_id="evaluator-a",
        actor_role="evaluation_reviewer",
        actor_secret=SECRETS["evaluation_reviewer"],
        reason="Declared evaluation and integrity gates verified.",
        now=NOW,
    )
    registry.transition(
        package.reference,
        state="approved",
        actor_id="promoter-a",
        actor_role="model_promotion_authority",
        actor_secret=SECRETS["model_promotion_authority"],
        reason="Human promotion approval for the bounded review-priority task.",
        now=NOW,
    )


def _enter_shadow(registry: ModelRegistry, package: ModelRegistryPackage) -> None:
    registry.transition(
        package.reference,
        state="shadow",
        actor_id="deployer-a",
        actor_role="deployment_operator",
        actor_secret=SECRETS["deployment_operator"],
        reason="Start non-authoritative shadow execution.",
        now=NOW,
    )


def test_candidate_package_is_content_addressed_and_signed(tmp_path) -> None:
    registry = _registry(tmp_path)
    package = _package("review-ranker", "v1")

    event = registry.register_candidate(
        package,
        actor_id="trainer-a",
        actor_secret=SECRETS["training_operator"],
        reason="Submit candidate.",
        now=NOW,
    )

    assert event.state == "candidate"
    assert event.event_sha256 != "0" * 64
    assert event.signature_hmac_sha256 != "0" * 64
    assert registry.package(package.reference) == package
    assert registry.events(package.reference) == (event,)


def test_tampered_package_digest_is_rejected(tmp_path) -> None:
    registry = _registry(tmp_path)
    package = _package("review-ranker", "v1")
    data = package.model_dump(mode="python")
    data["intended_use"] = "Changed after digest creation."
    tampered = ModelRegistryPackage.model_validate(data)

    with pytest.raises(ModelRegistryBoundaryError, match="digest"):
        registry.register_candidate(
            tampered,
            actor_id="trainer-a",
            actor_secret=SECRETS["training_operator"],
            reason="Submit candidate.",
            now=NOW,
        )


def test_role_secret_and_independent_promotion_are_enforced(tmp_path) -> None:
    registry = _registry(tmp_path)
    package = _package("review-ranker", "v1")
    registry.register_candidate(
        package,
        actor_id="trainer-a",
        actor_secret=SECRETS["training_operator"],
        reason="Submit candidate.",
        now=NOW,
    )

    with pytest.raises(ModelRegistryBoundaryError, match="authentication"):
        registry.transition(
            package.reference,
            state="validated",
            actor_id="evaluator-a",
            actor_role="evaluation_reviewer",
            actor_secret=b"wrong-secret-value",
            reason="Attempt validation.",
            now=NOW,
        )

    with pytest.raises(ModelRegistryBoundaryError, match="self-validate"):
        registry.transition(
            package.reference,
            state="validated",
            actor_id="trainer-a",
            actor_role="evaluation_reviewer",
            actor_secret=SECRETS["evaluation_reviewer"],
            reason="Attempt self validation.",
            now=NOW,
        )

    registry.transition(
        package.reference,
        state="validated",
        actor_id="evaluator-a",
        actor_role="evaluation_reviewer",
        actor_secret=SECRETS["evaluation_reviewer"],
        reason="Independent evaluation complete.",
        now=NOW,
    )
    with pytest.raises(ModelRegistryBoundaryError, match="independent"):
        registry.transition(
            package.reference,
            state="approved",
            actor_id="evaluator-a",
            actor_role="model_promotion_authority",
            actor_secret=SECRETS["model_promotion_authority"],
            reason="Attempt self promotion.",
            now=NOW,
        )


def test_first_activation_requires_shadow_and_deterministic_fallback(tmp_path) -> None:
    registry = _registry(tmp_path)
    package = _package("review-ranker", "v1")
    _register_and_approve(registry, package)

    with pytest.raises(ModelRegistryBoundaryError, match="shadow"):
        registry.activate(
            package.reference,
            actor_id="deployer-a",
            actor_secret=SECRETS["deployment_operator"],
            rollback_target_ref=DETERMINISTIC_FALLBACK_REF,
            reason="Activate too early.",
            now=NOW,
        )

    _enter_shadow(registry, package)
    with pytest.raises(ModelRegistryBoundaryError, match="deterministic"):
        registry.activate(
            package.reference,
            actor_id="deployer-a",
            actor_secret=SECRETS["deployment_operator"],
            rollback_target_ref="review-ranker@missing",
            reason="Activate without safe fallback.",
            now=NOW,
        )

    event = registry.activate(
        package.reference,
        actor_id="deployer-a",
        actor_secret=SECRETS["deployment_operator"],
        rollback_target_ref=DETERMINISTIC_FALLBACK_REF,
        reason="Activate bounded review-priority recommendations.",
        now=NOW,
    )
    pointer = registry.active(package.task)

    assert event.state == "active"
    assert event.rollback_target_ref == DETERMINISTIC_FALLBACK_REF
    assert pointer is not None
    assert pointer.model_ref == package.reference


def test_new_activation_preserves_exact_previous_package_and_rollback_restores_it(tmp_path) -> None:
    registry = _registry(tmp_path)
    first = _package("review-ranker", "v1", trainer="trainer-a")
    second = _package("review-ranker", "v2", trainer="trainer-b")
    _register_and_approve(registry, first)
    _enter_shadow(registry, first)
    registry.activate(
        first.reference,
        actor_id="deployer-a",
        actor_secret=SECRETS["deployment_operator"],
        rollback_target_ref=DETERMINISTIC_FALLBACK_REF,
        reason="Activate first package.",
        now=NOW,
    )

    _register_and_approve(registry, second)
    _enter_shadow(registry, second)
    registry.activate(
        second.reference,
        actor_id="deployer-a",
        actor_secret=SECRETS["deployment_operator"],
        rollback_target_ref=first.reference,
        reason="Activate second package with exact previous package as rollback target.",
        now=NOW,
    )

    assert registry.current(first.reference).state == "retired"
    assert registry.current(second.reference).state == "active"
    assert registry.active(first.task).model_ref == second.reference

    restored = registry.rollback(
        first.task,
        actor_id="deployer-a",
        actor_secret=SECRETS["deployment_operator"],
        reason="Rollback after acceptance regression.",
        now=NOW,
    )

    assert restored.event_type == "rollback_restored"
    assert restored.state == "active"
    assert restored.model_ref == first.reference
    assert registry.current(second.reference).state == "degraded"
    assert registry.active(first.task).model_ref == first.reference


def test_rollback_to_deterministic_fallback_disables_model_pointer(tmp_path) -> None:
    registry = _registry(tmp_path)
    package = _package("review-ranker", "v1")
    _register_and_approve(registry, package)
    _enter_shadow(registry, package)
    registry.activate(
        package.reference,
        actor_id="deployer-a",
        actor_secret=SECRETS["deployment_operator"],
        rollback_target_ref=DETERMINISTIC_FALLBACK_REF,
        reason="Activate first package.",
        now=NOW,
    )

    event = registry.rollback(
        package.task,
        actor_id="deployer-a",
        actor_secret=SECRETS["deployment_operator"],
        reason="Return to deterministic workflow.",
        now=NOW,
    )

    assert event.state == "degraded"
    assert registry.active(package.task) is None


def test_incident_revocation_of_active_model_fails_closed(tmp_path) -> None:
    registry = _registry(tmp_path)
    package = _package("review-ranker", "v1")
    _register_and_approve(registry, package)
    _enter_shadow(registry, package)
    registry.activate(
        package.reference,
        actor_id="deployer-a",
        actor_secret=SECRETS["deployment_operator"],
        rollback_target_ref=DETERMINISTIC_FALLBACK_REF,
        reason="Activate first package.",
        now=NOW,
    )

    event = registry.transition(
        package.reference,
        state="revoked",
        actor_id="incident-a",
        actor_role="incident_authority",
        actor_secret=SECRETS["incident_authority"],
        reason="Artifact integrity incident requires immediate revocation.",
        now=NOW,
    )

    assert event.state == "revoked"
    assert registry.active(package.task) is None


def test_ledger_tampering_and_wrong_signing_key_are_detected(tmp_path) -> None:
    registry = _registry(tmp_path)
    package = _package("review-ranker", "v1")
    registry.register_candidate(
        package,
        actor_id="trainer-a",
        actor_secret=SECRETS["training_operator"],
        reason="Submit candidate.",
        now=NOW,
    )

    wrong_key_registry = ModelRegistry(
        registry.root,
        signing_key=b"different-signing-key-32-bytes-long!",
        authority_secrets=SECRETS,
    )
    with pytest.raises(ModelRegistryBoundaryError, match="signature"):
        wrong_key_registry.events(package.reference)

    path = registry._events_path(package.reference)
    payload = json.loads(path.read_text(encoding="utf-8").splitlines()[0])
    payload["reason"] = "tampered reason"
    path.write_text(json.dumps(payload) + "\n", encoding="utf-8")
    with pytest.raises(ModelRegistryBoundaryError, match="integrity"):
        registry.events(package.reference)
