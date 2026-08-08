from __future__ import annotations

from datetime import UTC, datetime
from types import SimpleNamespace

import pytest

from vulnhunter.governance.release_package import (
    CampaignApplicationProvenance,
    CampaignReleasePackage,
    CampaignReviewProvenance,
    campaign_release_package_sha256,
)
from vulnhunter.ml.release_training import (
    ReleaseTrainingBoundaryError,
    TrainingReleaseLedger,
    build_production_training_package,
    governed_model_candidate_sha256,
    production_training_package_sha256,
    register_training_release,
    train_production_baseline,
    transition_training_release,
)
from vulnhunter.observations.models import ObservationSummary

NOW = datetime(2026, 8, 8, 12, 0, tzinfo=UTC)
COMMIT = "a" * 40
HEX_A = "a" * 64
HEX_B = "b" * 64
HEX_C = "c" * 64
HEX_D = "d" * 64
HEX_E = "e" * 64


class FakeRepository:
    def __init__(self, observations: tuple[ObservationSummary, ...]) -> None:
        self.observations = {item.id: item for item in observations}

    def get_review_case(self, observation_id: int):
        observation = self.observations[observation_id]
        return SimpleNamespace(
            state="consensus",
            effective_label=observation.review_label,
            observation=observation,
        )


class FakeGovernanceStore:
    def __init__(self, packages: tuple[CampaignReleasePackage, ...]) -> None:
        self.releases = {
            item.campaign_id: SimpleNamespace(
                release_id=item.release_id,
                manifest_sha256=item.release_manifest_sha256,
            )
            for item in packages
        }
        self.integrity_checks = 0

    def verify_integrity(self) -> None:
        self.integrity_checks += 1

    def get_release(self, campaign_id: str):
        return self.releases[campaign_id]


def _observation(
    observation_id: int,
    scan_id: int,
    label: str,
    *,
    fingerprint_seed: str,
) -> ObservationSummary:
    return ObservationSummary(
        id=observation_id,
        scan_id=scan_id,
        page_id=None,
        category="debug_error_exposure" if label == "confirmed" else "missing_header",
        severity="high" if label == "confirmed" else "low",
        title=f"Observation {observation_id}",
        description="Redacted deterministic training evidence.",
        url=f"http://127.0.0.1/example/{observation_id}",
        evidence={"status_code": 500 if label == "confirmed" else 200},
        fingerprint=(fingerprint_seed * 64)[:64],
        review_label=label,
        review_note="Final label established by two-reviewer consensus.",
        reviewed_at=NOW,
    )


def _release_package(
    *,
    release_id: str = "release-alpha-01",
    campaign_id: str = "campaign-alpha-01",
    overlap_scan_ids: bool = False,
    duplicate_fingerprint: bool = False,
) -> tuple[CampaignReleasePackage, dict[str, FakeRepository]]:
    applications = (
        CampaignApplicationProvenance(
            application_id="app-alpha-01",
            application_record_sha256=HEX_A,
            application_family="python-django",
            environment="owned-local-alpha",
            authorization_id="auth-alpha-01",
            authorization_record_sha256=HEX_B,
        ),
        CampaignApplicationProvenance(
            application_id="app-beta-001",
            application_record_sha256=HEX_C,
            application_family="node-express",
            environment="owned-local-beta",
            authorization_id="auth-beta-001",
            authorization_record_sha256=HEX_D,
        ),
    )
    repositories: dict[str, FakeRepository] = {}
    reviews: list[CampaignReviewProvenance] = []
    for app_index, application in enumerate(applications):
        database = f"/private/lab/{application.application_id}.sqlite3"
        observations: list[ObservationSummary] = []
        for offset in range(4):
            observation_id = app_index * 4 + offset + 1
            scan_id = offset + 1 if overlap_scan_ids else app_index * 4 + offset + 1
            label = "confirmed" if offset % 2 == 0 else "false_positive"
            seed = "f" if duplicate_fingerprint and observation_id in {1, 5} else hex(
                observation_id
            )[-1]
            observation = _observation(
                observation_id,
                scan_id,
                label,
                fingerprint_seed=seed,
            )
            observations.append(observation)
            reference = f"{database}#{observation_id}"
            reviews.append(
                CampaignReviewProvenance(
                    observation_reference=reference,
                    application_id=application.application_id,
                    assignment_record_sha256=HEX_A,
                    primary_reviewer_ids=("reviewer-a", "reviewer-b"),
                    primary_attestation_ids=(
                        f"attest-{observation_id:02d}-a",
                        f"attest-{observation_id:02d}-b",
                    ),
                    primary_attestation_record_sha256s=(HEX_B, HEX_C),
                    primary_repository_decision_sha256s=(HEX_D, HEX_E),
                    assigned_adjudicator_id=None,
                    resolution_state="consensus",
                    effective_label=label,
                )
            )
        repositories[database] = FakeRepository(tuple(observations))
    values: dict[str, object] = {
        "schema_version": "1.0",
        "package_id": f"campaign-release-package-{release_id[-8:]}",
        "release_id": release_id,
        "release_manifest_sha256": HEX_A,
        "campaign_id": campaign_id,
        "campaign_record_sha256": HEX_B,
        "campaign_manifest_sha256": HEX_C,
        "applications": applications,
        "reviews": tuple(reviews),
        "released_by": "admin-a",
        "released_at": NOW,
        "package_sha256": "0" * 64,
    }
    values["package_sha256"] = campaign_release_package_sha256(values)
    return CampaignReleasePackage.model_validate(values), repositories


def _register(
    monkeypatch,
    tmp_path,
    packages: tuple[CampaignReleasePackage, ...],
) -> tuple[TrainingReleaseLedger, FakeGovernanceStore]:
    ledger = TrainingReleaseLedger(tmp_path / "training-release-ledger")
    governance = FakeGovernanceStore(packages)
    monkeypatch.setattr(
        "vulnhunter.ml.release_training.authenticate_identity",
        lambda *_args, **_kwargs: SimpleNamespace(reviewer_id="admin-a"),
    )
    for package in packages:
        register_training_release(
            governance,
            ledger,
            package,
            actor_id="admin-a",
            actor_secret="test-secret",
            now=NOW,
        )
    return ledger, governance


def _build(package, ledger, repositories):
    return build_production_training_package(
        package,
        ledger,
        repositories,
        source_commit=COMMIT,
        label_ontology_version="binary-review-v1",
        redaction_policy_version="central-redaction-v1",
        permitted_tasks=("confirmed_false_positive_decision_support",),
        retention_policy="Owner-private laboratory retention policy v1.",
    )


def test_training_package_is_deterministic_redacted_and_release_bound(monkeypatch, tmp_path):
    release, repositories = _release_package(duplicate_fingerprint=True)
    ledger, governance = _register(monkeypatch, tmp_path, (release,))

    first = _build(release, ledger, repositories)
    second = _build(release, ledger, repositories)

    assert governance.integrity_checks == 1
    assert first == second
    assert production_training_package_sha256(first) == first.package_sha256
    assert first.source_release_id == release.release_id
    assert first.source_release_package_sha256 == release.package_sha256
    assert len(first.examples) == 7
    assert len(first.excluded_records) == 1
    assert first.excluded_records[0].reason == "duplicate_same_label"
    encoded = first.model_dump_json()
    assert "/private/lab/" not in encoded
    assert "auth-alpha-01" in encoded
    assert first.privacy_classification == "owner_private_redacted"


def test_withdrawal_immediately_blocks_new_package_derivation(monkeypatch, tmp_path):
    release, repositories = _release_package()
    ledger, governance = _register(monkeypatch, tmp_path, (release,))
    _build(release, ledger, repositories)

    event = transition_training_release(
        governance,
        ledger,
        release,
        actor_id="admin-a",
        actor_secret="test-secret",
        state="withdrawn",
        reason="A governed review requires correction.",
        now=NOW,
    )

    assert event.state == "withdrawn"
    with pytest.raises(ReleaseTrainingBoundaryError, match="withdrawn"):
        _build(release, ledger, repositories)


def test_superseding_release_blocks_old_lineage_and_keeps_successor_active(
    monkeypatch,
    tmp_path,
):
    old, _ = _release_package()
    successor, successor_repositories = _release_package(
        release_id="release-beta-002",
        campaign_id="campaign-beta-02",
    )
    ledger, governance = _register(monkeypatch, tmp_path, (old, successor))

    transition_training_release(
        governance,
        ledger,
        old,
        actor_id="admin-a",
        actor_secret="test-secret",
        state="superseded",
        successor=successor,
        reason="Corrected governed review is represented by a new immutable release.",
        now=NOW,
    )

    with pytest.raises(ReleaseTrainingBoundaryError, match="superseded"):
        ledger.require_active(old)
    assert ledger.require_active(successor).state == "active"
    successor_package = _build(successor, ledger, successor_repositories)
    assert successor_package.source_release_id == successor.release_id


def test_production_training_candidate_carries_exact_package_provenance(monkeypatch, tmp_path):
    release, repositories = _release_package()
    ledger, _ = _register(monkeypatch, tmp_path, (release,))
    package = _build(release, ledger, repositories)

    candidate = train_production_baseline(
        package,
        ledger,
        release,
        minimum_samples=8,
        minimum_per_class=4,
        minimum_scans=8,
        minimum_scans_per_class=4,
        test_fraction=0.25,
        random_seed=7,
    )

    assert candidate.training_mode == "production_candidate"
    assert candidate.training_package_id == package.package_id
    assert candidate.training_package_sha256 == package.package_sha256
    assert candidate.source_release_id == release.release_id
    assert candidate.model.dataset_sha256 == package.dataset_sha256
    assert governed_model_candidate_sha256(candidate) == candidate.candidate_sha256


def test_production_training_fails_closed_until_hierarchical_scan_identity_exists(
    monkeypatch,
    tmp_path,
):
    release, repositories = _release_package(overlap_scan_ids=True)
    ledger, _ = _register(monkeypatch, tmp_path, (release,))
    package = _build(release, ledger, repositories)

    with pytest.raises(ReleaseTrainingBoundaryError, match="P3.3 hierarchical grouping"):
        train_production_baseline(
            package,
            ledger,
            release,
            minimum_samples=8,
            minimum_per_class=4,
            minimum_scans=4,
            minimum_scans_per_class=2,
        )


def test_tampered_release_package_is_rejected_before_registration(monkeypatch, tmp_path):
    release, _ = _release_package()
    bad = release.model_copy(update={"package_sha256": HEX_E})
    ledger = TrainingReleaseLedger(tmp_path / "training-release-ledger")
    governance = FakeGovernanceStore((release,))
    monkeypatch.setattr(
        "vulnhunter.ml.release_training.authenticate_identity",
        lambda *_args, **_kwargs: SimpleNamespace(reviewer_id="admin-a"),
    )

    with pytest.raises(ReleaseTrainingBoundaryError, match="integrity"):
        register_training_release(
            governance,
            ledger,
            bad,
            actor_id="admin-a",
            actor_secret="test-secret",
            now=NOW,
        )
