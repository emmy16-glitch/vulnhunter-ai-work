"""Read-only governed pilot and dataset-readiness assessment."""

from __future__ import annotations

import hashlib
import json
from collections import Counter, defaultdict
from datetime import UTC, datetime

from pydantic import BaseModel, ConfigDict, Field

from vulnhunter.authorization import AuthorizationStore
from vulnhunter.exceptions import GovernanceError, GovernanceNotFoundError
from vulnhunter.governance.models import (
    DatasetReleaseManifest,
    ReviewOutcome,
    release_manifest_sha256,
)
from vulnhunter.governance.service import assess_release, scan_snapshot_sha256
from vulnhunter.governance.store import GovernanceStore
from vulnhunter.ml.dataset import dataset_sha256, to_training_example
from vulnhunter.observations.models import ObservationSummary
from vulnhunter.observations.storage import ScanRepository


class PilotReadinessReport(BaseModel):
    """Deterministic read-only evidence for a governed pilot dataset release."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    campaign_id: str
    assessed_at: datetime
    pilot_ready: bool
    model_training_ready: bool
    hard_release_blockers: tuple[str, ...]
    model_training_blockers: tuple[str, ...]
    warnings: tuple[str, ...]
    informational_metrics: dict[str, object]
    dataset_sha256: str
    release_manifest_sha256: str | None = None
    report_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


def _canonical_sha256(value: dict[str, object]) -> str:
    encoded = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _report_sha256(data: dict[str, object]) -> str:
    payload = {key: value for key, value in data.items() if key != "report_sha256"}
    return _canonical_sha256(payload)


def _load_release_manifest(
    store: GovernanceStore,
    campaign_id: str,
) -> tuple[DatasetReleaseManifest | None, tuple[str, ...]]:
    try:
        manifest = store.get_release(campaign_id)
    except GovernanceNotFoundError:
        return None, ("dataset release manifest is missing",)
    except GovernanceError as exc:
        return None, (f"dataset release manifest is invalid: {exc}",)

    expected = release_manifest_sha256(manifest)
    if expected != manifest.manifest_sha256:
        return manifest, ("dataset release manifest failed integrity verification",)
    return manifest, ()


def _observation_evidence_hash(observation: ObservationSummary) -> str:
    return _canonical_sha256(
        {
            "category": observation.category,
            "severity": observation.severity,
            "title": observation.title,
            "description": observation.description,
            "url": observation.url,
            "evidence": observation.evidence,
        }
    )


def assess_pilot_readiness(
    store: GovernanceStore,
    authorization_store: AuthorizationStore,
    repositories: dict[str, ScanRepository],
    *,
    campaign_id: str,
    now: datetime | None = None,
    minimum_samples: int = 20,
    minimum_per_class: int = 5,
    minimum_scans: int = 4,
    minimum_scans_per_class: int = 2,
) -> PilotReadinessReport:
    """Assess governed pilot release evidence without mutating state or training a model."""
    assessed_at = (now or datetime.now(UTC)).astimezone(UTC)
    hard_blockers: list[str] = []
    model_blockers: list[str] = []
    warnings: list[str] = []

    try:
        store.verify_integrity()
    except GovernanceError as exc:
        hard_blockers.append(f"governance store integrity failed: {exc}")

    release_assessment = assess_release(
        store,
        authorization_store,
        repositories,
        campaign_id=campaign_id,
        now=assessed_at,
        require_completed=True,
    )
    hard_blockers.extend(release_assessment.reasons)

    campaign = store.get_campaign(campaign_id)
    applications = store.list_applications(campaign_id)
    scans = store.list_scans(campaign_id)
    assignments = store.list_assignments(campaign_id)
    attestations = store.list_attestations(campaign_id)
    release_manifest, manifest_blockers = _load_release_manifest(store, campaign_id)
    hard_blockers.extend(manifest_blockers)

    observations: dict[tuple[str, int], ObservationSummary] = {}
    scan_states: Counter[str] = Counter()
    scan_snapshot_mismatches = 0
    for scan in scans:
        repository = repositories.get(scan.scan_database)
        if repository is None:
            continue
        try:
            current_scan = repository.get_scan(scan.scan_id)
        except ValueError:
            continue
        scan_states[current_scan.status] += 1
        if scan_snapshot_sha256(current_scan) != scan.scan_snapshot_sha256:
            scan_snapshot_mismatches += 1
        for observation in repository.list_observations(scan_id=scan.scan_id, limit=1_000):
            observations[(scan.scan_database, observation.id)] = observation

    review_states: Counter[str] = Counter()
    agreement_count = 0
    disagreement_count = 0
    adjudicated_count = 0
    unresolved_reviews = 0
    effective_labels: Counter[str] = Counter()
    reviewer_statuses: Counter[str] = Counter()
    revoked_or_disabled_reviewers: set[str] = set()

    for assignment in assignments:
        repository = repositories.get(assignment.scan_database)
        if repository is None:
            continue
        try:
            case = repository.get_review_case(assignment.observation_id)
        except ValueError:
            continue
        review_states[case.state] += 1
        effective_labels[case.effective_label] += 1
        if len(case.decisions) == 2 and case.decisions[0].outcome == case.decisions[1].outcome:
            agreement_count += 1
        elif len(case.decisions) == 2:
            disagreement_count += 1
        if case.state == "adjudicated":
            adjudicated_count += 1
        if case.state not in {"consensus", "adjudicated"}:
            unresolved_reviews += 1
        actor_ids = set(assignment.primary_reviewers)
        if assignment.adjudicator_id:
            actor_ids.add(assignment.adjudicator_id)
        for actor_id in actor_ids:
            identity = store.get_identity(actor_id)
            reviewer_statuses[identity.status] += 1
            if identity.status in {"disabled", "revoked"}:
                revoked_or_disabled_reviewers.add(identity.reviewer_id)

    fingerprint_groups: dict[str, list[str]] = defaultdict(list)
    evidence_groups: dict[str, list[str]] = defaultdict(list)
    scan_refs_by_label: dict[ReviewOutcome, set[str]] = {
        "confirmed": set(),
        "false_positive": set(),
    }
    examples = []
    for (scan_database, observation_id), observation in observations.items():
        reference = f"{scan_database}#{observation_id}"
        fingerprint_groups[observation.fingerprint].append(reference)
        evidence_groups[_observation_evidence_hash(observation)].append(reference)
        if observation.review_label in {"confirmed", "false_positive"}:
            examples.append(to_training_example(observation))
            scan_refs_by_label[observation.review_label].add(
                f"{scan_database}#{observation.scan_id}"
            )

    duplicate_fingerprints = {
        fingerprint: tuple(sorted(references))
        for fingerprint, references in sorted(fingerprint_groups.items())
        if len(references) > 1
    }
    duplicate_evidence = {
        fingerprint: tuple(sorted(references))
        for fingerprint, references in sorted(evidence_groups.items())
        if len(references) > 1
    }
    if duplicate_fingerprints:
        warnings.append(f"{len(duplicate_fingerprints)} duplicate observation fingerprint(s) found")
    if duplicate_evidence:
        warnings.append(f"{len(duplicate_evidence)} duplicate evidence payload(s) found")
    if scan_snapshot_mismatches:
        hard_blockers.append(f"{scan_snapshot_mismatches} linked scan snapshot(s) changed")
    if unresolved_reviews:
        hard_blockers.append(f"{unresolved_reviews} governed review(s) are unresolved")
    if revoked_or_disabled_reviewers:
        hard_blockers.append(
            "revoked or disabled reviewer evidence is present: "
            + ", ".join(sorted(revoked_or_disabled_reviewers))
        )

    class_counts: Counter[str] = Counter(example.label for example in examples)
    unique_scan_refs = {
        f"{scan_database}#{observation.scan_id}"
        for (scan_database, _), observation in observations.items()
    }
    if len(examples) < minimum_samples:
        model_blockers.append(
            f"At least {minimum_samples} reviewed samples are required; found {len(examples)}."
        )
    for label in ("confirmed", "false_positive"):
        if class_counts[label] < minimum_per_class:
            model_blockers.append(
                f"At least {minimum_per_class} {label} samples are required; "
                f"found {class_counts[label]}."
            )
        if len(scan_refs_by_label[label]) < minimum_scans_per_class:
            model_blockers.append(
                f"Label {label} must span at least {minimum_scans_per_class} scans; "
                f"found {len(scan_refs_by_label[label])}."
            )
    if len(unique_scan_refs) < minimum_scans:
        model_blockers.append(
            f"At least {minimum_scans} linked scans are required; found {len(unique_scan_refs)}."
        )
    if duplicate_fingerprints or duplicate_evidence:
        model_blockers.append(
            "Duplicate observations or evidence require deduplication before training."
        )
    if class_counts["confirmed"] == 0 or class_counts["false_positive"] == 0:
        model_blockers.append("Both confirmed and false_positive classes must be represented.")

    release_refs = tuple(release_manifest.observation_references) if release_manifest else ()
    current_refs = tuple(sorted(f"{database}#{obs_id}" for database, obs_id in observations))
    if release_manifest and release_refs != current_refs:
        hard_blockers.append(
            "dataset release manifest observations do not match current scan evidence"
        )

    application_families = Counter(item.application_family for item in applications)
    label_total = max(1, class_counts["confirmed"] + class_counts["false_positive"])
    agreement_total = max(1, agreement_count + disagreement_count)
    information: dict[str, object] = {
        "campaign_status": campaign.status,
        "application_count": len(applications),
        "application_family_count": len(application_families),
        "application_families": dict(sorted(application_families.items())),
        "scan_count": len(scans),
        "scan_states": dict(sorted(scan_states.items())),
        "observation_count": len(observations),
        "assignment_count": len(assignments),
        "attestation_count": len(attestations),
        "review_states": dict(sorted(review_states.items())),
        "agreement_count": agreement_count,
        "disagreement_count": disagreement_count,
        "agreement_rate": agreement_count / agreement_total,
        "disagreement_rate": disagreement_count / agreement_total,
        "adjudicated_count": adjudicated_count,
        "effective_labels": dict(sorted(effective_labels.items())),
        "class_counts": {
            "confirmed": class_counts["confirmed"],
            "false_positive": class_counts["false_positive"],
        },
        "class_balance": {
            "confirmed": class_counts["confirmed"] / label_total,
            "false_positive": class_counts["false_positive"] / label_total,
        },
        "scans_per_class": {
            "confirmed": len(scan_refs_by_label["confirmed"]),
            "false_positive": len(scan_refs_by_label["false_positive"]),
        },
        "duplicate_fingerprint_count": len(duplicate_fingerprints),
        "duplicate_evidence_count": len(duplicate_evidence),
        "duplicate_fingerprints": duplicate_fingerprints,
        "duplicate_evidence": duplicate_evidence,
        "reviewer_statuses": dict(sorted(reviewer_statuses.items())),
        "release_manifest_present": release_manifest is not None,
        "release_manifest_integrity": not manifest_blockers,
        "release_observation_count": len(release_refs),
        "sensitive_data_redaction": "assessed from redacted persisted observation fields only",
        "leakage_risk": (
            "duplicates detected across governed observations"
            if duplicate_fingerprints or duplicate_evidence
            else "no duplicate fingerprint or evidence leakage indicator detected"
        ),
    }

    unique_hard_blockers = tuple(dict.fromkeys(hard_blockers))
    unique_model_blockers = tuple(dict.fromkeys(model_blockers))
    unique_warnings = tuple(dict.fromkeys(warnings))
    data: dict[str, object] = {
        "campaign_id": campaign_id,
        "assessed_at": assessed_at,
        "pilot_ready": not unique_hard_blockers,
        "model_training_ready": not unique_hard_blockers and not unique_model_blockers,
        "hard_release_blockers": unique_hard_blockers,
        "model_training_blockers": unique_model_blockers,
        "warnings": unique_warnings,
        "informational_metrics": information,
        "dataset_sha256": dataset_sha256(
            tuple(sorted(examples, key=lambda item: item.observation_id))
        ),
        "release_manifest_sha256": release_manifest.manifest_sha256 if release_manifest else None,
        "report_sha256": "0" * 64,
    }
    data["report_sha256"] = _report_sha256(data)
    return PilotReadinessReport.model_validate(data)
