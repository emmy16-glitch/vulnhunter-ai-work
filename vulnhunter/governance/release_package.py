"""Exact append-only provenance packages for governed real-data campaign releases."""

from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal, Self

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

from vulnhunter.governance.models import ReviewOutcome, canonical_sha256
from vulnhunter.governance.store import GovernanceStore
from vulnhunter.observations.storage import ScanRepository

ReviewResolutionState = Literal["consensus", "adjudicated"]
_IDENTIFIER = re.compile(r"^[a-z0-9][a-z0-9._-]{1,127}$")


class CampaignReleasePackageError(RuntimeError):
    """A campaign release package failed an integrity or provenance boundary."""


def _safe_component(value: str, field_name: str) -> str:
    if _IDENTIFIER.fullmatch(value) is None:
        raise CampaignReleasePackageError(f"{field_name} is not a safe stable identifier")
    return value


class CampaignApplicationProvenance(BaseModel):
    """Exact application-family and authorization binding retained in a release package."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    application_id: str = Field(min_length=8, max_length=80)
    application_record_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    application_family: str = Field(min_length=1, max_length=200)
    environment: str = Field(min_length=1, max_length=200)
    authorization_id: str = Field(min_length=8, max_length=80)
    authorization_record_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


class CampaignReviewProvenance(BaseModel):
    """Full governed review and adjudication chain for one released observation."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    observation_reference: str = Field(min_length=3, max_length=4_096)
    application_id: str = Field(min_length=8, max_length=80)
    assignment_record_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    primary_reviewer_ids: tuple[str, str]
    primary_attestation_ids: tuple[str, str]
    primary_attestation_record_sha256s: tuple[str, str]
    primary_repository_decision_sha256s: tuple[str, str]
    assigned_adjudicator_id: str | None = Field(default=None, min_length=2, max_length=64)
    resolution_state: ReviewResolutionState
    effective_label: ReviewOutcome
    adjudication_attestation_id: str | None = Field(default=None, min_length=8, max_length=80)
    adjudication_attestation_record_sha256: str | None = Field(
        default=None,
        pattern=r"^[0-9a-f]{64}$",
    )
    adjudication_repository_decision_sha256: str | None = Field(
        default=None,
        pattern=r"^[0-9a-f]{64}$",
    )

    @model_validator(mode="after")
    def validate_resolution(self) -> Self:
        if len(set(self.primary_reviewer_ids)) != 2:
            raise ValueError("campaign release package primary reviewers must be distinct")
        if len(set(self.primary_attestation_ids)) != 2:
            raise ValueError("campaign release package primary attestations must be distinct")
        adjudication_values = (
            self.adjudication_attestation_id,
            self.adjudication_attestation_record_sha256,
            self.adjudication_repository_decision_sha256,
        )
        if self.resolution_state == "consensus":
            if any(value is not None for value in adjudication_values):
                raise ValueError("consensus review cannot contain adjudication provenance")
        else:
            if self.assigned_adjudicator_id is None:
                raise ValueError("adjudicated review requires an assigned adjudicator")
            if any(value is None for value in adjudication_values):
                raise ValueError("adjudicated review requires complete adjudication provenance")
        return self


class CampaignReleasePackage(BaseModel):
    """Deterministic immutable package for one governed dataset release."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    schema_version: str = "1.0"
    package_id: str = Field(min_length=8, max_length=100)
    release_id: str = Field(min_length=8, max_length=80)
    release_manifest_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    campaign_id: str = Field(min_length=8, max_length=80)
    campaign_record_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    campaign_manifest_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    applications: tuple[CampaignApplicationProvenance, ...] = Field(min_length=1)
    reviews: tuple[CampaignReviewProvenance, ...] = Field(min_length=1)
    released_by: str = Field(min_length=2, max_length=64)
    released_at: datetime
    package_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @field_validator("package_id", "release_id", "campaign_id")
    @classmethod
    def require_safe_identifier(cls, value: str) -> str:
        if _IDENTIFIER.fullmatch(value) is None:
            raise ValueError("campaign release package identifiers must be stable and path-safe")
        return value

    @field_validator("released_at")
    @classmethod
    def require_timezone(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("campaign release package timestamp must include a timezone")
        return value.astimezone(UTC)

    @model_validator(mode="after")
    def require_unique_references(self) -> Self:
        application_ids = tuple(item.application_id for item in self.applications)
        if len(set(application_ids)) != len(application_ids):
            raise ValueError("campaign release package application IDs must be unique")
        references = tuple(item.observation_reference for item in self.reviews)
        if len(set(references)) != len(references):
            raise ValueError("campaign release package observation references must be unique")
        return self


def campaign_release_package_sha256(
    value: CampaignReleasePackage | dict[str, object],
) -> str:
    return canonical_sha256(value, exclude={"package_sha256"})


def _decision_sha256(value: dict[str, object]) -> str:
    encoded = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=str,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _review_provenance(
    governance_store: GovernanceStore,
    repository: ScanRepository,
    *,
    campaign_id: str,
    assignment,
    expected_label: ReviewOutcome,
) -> CampaignReviewProvenance:
    case = repository.get_review_case(assignment.observation_id)
    if case.state not in {"consensus", "adjudicated"}:
        raise CampaignReleasePackageError(
            f"review {assignment.observation_id} is not final: {case.state}"
        )
    if case.effective_label != expected_label:
        raise CampaignReleasePackageError(
            f"review {assignment.observation_id} no longer matches the release label"
        )

    attestations = governance_store.list_attestations(
        campaign_id,
        scan_database=assignment.scan_database,
        observation_id=assignment.observation_id,
    )
    primary = {item.actor_id: item for item in attestations if item.role == "primary"}
    if set(primary) != set(assignment.primary_reviewers):
        raise CampaignReleasePackageError(
            f"review {assignment.observation_id} does not have exactly two assigned attestations"
        )
    decisions = {item.reviewer_id: item for item in case.decisions}
    if set(decisions) != set(assignment.primary_reviewers):
        raise CampaignReleasePackageError(
            f"review {assignment.observation_id} primary decisions do not match its assignment"
        )

    primary_attestation_ids: list[str] = []
    primary_attestation_hashes: list[str] = []
    primary_decision_hashes: list[str] = []
    for reviewer_id in assignment.primary_reviewers:
        attestation = primary[reviewer_id]
        decision = decisions[reviewer_id]
        decision_sha256 = _decision_sha256(decision.model_dump(mode="json"))
        if attestation.repository_decision_id != decision.id:
            raise CampaignReleasePackageError(
                f"review {assignment.observation_id} decision ID changed after attestation"
            )
        if attestation.repository_decision_sha256 != decision_sha256:
            raise CampaignReleasePackageError(
                f"review {assignment.observation_id} decision changed after attestation"
            )
        if attestation.outcome != decision.outcome:
            raise CampaignReleasePackageError(
                f"review {assignment.observation_id} attested outcome does not match"
            )
        primary_attestation_ids.append(attestation.attestation_id)
        primary_attestation_hashes.append(attestation.record_sha256)
        primary_decision_hashes.append(decision_sha256)

    adjudication_attestations = tuple(
        item for item in attestations if item.role == "adjudicator"
    )
    adjudication_attestation_id = None
    adjudication_attestation_hash = None
    adjudication_decision_hash = None
    if case.state == "consensus":
        if case.adjudication is not None or adjudication_attestations:
            raise CampaignReleasePackageError(
                f"consensus review {assignment.observation_id} contains adjudication state"
            )
    else:
        if assignment.adjudicator_id is None or case.adjudication is None:
            raise CampaignReleasePackageError(
                f"adjudicated review {assignment.observation_id} lacks its assigned adjudicator"
            )
        if len(adjudication_attestations) != 1:
            raise CampaignReleasePackageError(
                f"adjudicated review {assignment.observation_id} lacks one attestation"
            )
        attestation = adjudication_attestations[0]
        if attestation.actor_id != assignment.adjudicator_id:
            raise CampaignReleasePackageError(
                f"adjudicated review {assignment.observation_id} used a different adjudicator"
            )
        decision_sha256 = _decision_sha256(case.adjudication.model_dump(mode="json"))
        if attestation.repository_decision_id != case.adjudication.id:
            raise CampaignReleasePackageError(
                f"adjudication {assignment.observation_id} decision ID changed"
            )
        if attestation.repository_decision_sha256 != decision_sha256:
            raise CampaignReleasePackageError(
                f"adjudication {assignment.observation_id} changed after attestation"
            )
        if attestation.outcome != case.adjudication.outcome:
            raise CampaignReleasePackageError(
                f"adjudication {assignment.observation_id} outcome does not match"
            )
        adjudication_attestation_id = attestation.attestation_id
        adjudication_attestation_hash = attestation.record_sha256
        adjudication_decision_hash = decision_sha256

    reference = f"{assignment.scan_database}#{assignment.observation_id}"
    return CampaignReviewProvenance(
        observation_reference=reference,
        application_id=assignment.application_id,
        assignment_record_sha256=assignment.record_sha256,
        primary_reviewer_ids=assignment.primary_reviewers,
        primary_attestation_ids=tuple(primary_attestation_ids),
        primary_attestation_record_sha256s=tuple(primary_attestation_hashes),
        primary_repository_decision_sha256s=tuple(primary_decision_hashes),
        assigned_adjudicator_id=assignment.adjudicator_id,
        resolution_state=case.state,
        effective_label=expected_label,
        adjudication_attestation_id=adjudication_attestation_id,
        adjudication_attestation_record_sha256=adjudication_attestation_hash,
        adjudication_repository_decision_sha256=adjudication_decision_hash,
    )


def build_campaign_release_package(
    governance_store: GovernanceStore,
    repositories: dict[str, ScanRepository],
    *,
    campaign_id: str,
) -> CampaignReleasePackage:
    """Build an exact package only from one verified completed campaign release."""

    governance_store.verify_integrity()
    campaign = governance_store.get_campaign(campaign_id)
    release = governance_store.get_release(campaign_id)
    if campaign.status != "completed":
        raise CampaignReleasePackageError("campaign release package requires a completed campaign")
    if release.campaign_record_sha256 != campaign.record_sha256:
        raise CampaignReleasePackageError("campaign changed after dataset release")
    if release.campaign_manifest_sha256 != campaign.approved_manifest_sha256:
        raise CampaignReleasePackageError("approved campaign manifest no longer matches release")

    applications = governance_store.list_applications(campaign_id)
    expected_application_ids = tuple(
        item.application_id for item in sorted(applications, key=lambda item: item.application_id)
    )
    if release.application_ids != expected_application_ids:
        raise CampaignReleasePackageError("release application IDs do not match campaign state")
    application_provenance = tuple(
        CampaignApplicationProvenance(
            application_id=item.application_id,
            application_record_sha256=item.record_sha256,
            application_family=item.application_family,
            environment=item.environment,
            authorization_id=item.authorization_id,
            authorization_record_sha256=item.authorization_record_sha256,
        )
        for item in sorted(applications, key=lambda current: current.application_id)
    )

    assignments = governance_store.list_assignments(campaign_id)
    assignment_references = tuple(
        sorted(f"{item.scan_database}#{item.observation_id}" for item in assignments)
    )
    if release.observation_references != assignment_references:
        raise CampaignReleasePackageError(
            "release observation references do not match governed assignments"
        )
    if set(release.effective_labels) != set(assignment_references):
        raise CampaignReleasePackageError("release labels do not cover exact observations")

    review_provenance: list[CampaignReviewProvenance] = []
    for assignment in assignments:
        repository = repositories.get(assignment.scan_database)
        if repository is None:
            raise CampaignReleasePackageError(
                f"scan repository is unavailable for released observation {assignment.observation_id}"
            )
        reference = f"{assignment.scan_database}#{assignment.observation_id}"
        review_provenance.append(
            _review_provenance(
                governance_store,
                repository,
                campaign_id=campaign_id,
                assignment=assignment,
                expected_label=release.effective_labels[reference],
            )
        )
    ordered_reviews = tuple(
        sorted(review_provenance, key=lambda item: item.observation_reference)
    )

    base: dict[str, object] = {
        "schema_version": "1.0",
        "release_id": release.release_id,
        "release_manifest_sha256": release.manifest_sha256,
        "campaign_id": campaign.campaign_id,
        "campaign_record_sha256": campaign.record_sha256,
        "campaign_manifest_sha256": release.campaign_manifest_sha256,
        "applications": [item.model_dump(mode="json") for item in application_provenance],
        "reviews": [item.model_dump(mode="json") for item in ordered_reviews],
        "released_by": release.released_by,
        "released_at": release.released_at,
    }
    identity_digest = canonical_sha256(base, exclude=set())
    values = {
        **base,
        "package_id": f"campaign-release-package-{identity_digest[:24]}",
        "package_sha256": "0" * 64,
    }
    values["package_sha256"] = campaign_release_package_sha256(values)
    return CampaignReleasePackage.model_validate(values)


class CampaignReleasePackageStore:
    """Owner-private append-only filesystem store for release provenance packages."""

    def __init__(self, root: Path) -> None:
        self.root = root.expanduser().resolve()
        self.root.mkdir(parents=True, exist_ok=True)
        os.chmod(self.root, 0o700)

    def _campaign_directory(self, campaign_id: str) -> Path:
        safe_campaign_id = _safe_component(campaign_id, "campaign ID")
        directory = self.root / safe_campaign_id
        if directory.exists() and directory.is_symlink():
            raise CampaignReleasePackageError("campaign release package path is an unsafe symlink")
        directory.mkdir(parents=True, exist_ok=True)
        os.chmod(directory, 0o700)
        return directory

    def path_for(self, package: CampaignReleasePackage) -> Path:
        safe_release_id = _safe_component(package.release_id, "release ID")
        return self._campaign_directory(package.campaign_id) / f"{safe_release_id}.json"

    @staticmethod
    def _encoded(package: CampaignReleasePackage) -> bytes:
        return json.dumps(
            package.model_dump(mode="json"),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")

    def save(self, package: CampaignReleasePackage) -> bool:
        if campaign_release_package_sha256(package) != package.package_sha256:
            raise CampaignReleasePackageError("campaign release package failed integrity verification")
        destination = self.path_for(package)
        raw = self._encoded(package)
        if destination.exists():
            if destination.is_symlink():
                raise CampaignReleasePackageError(
                    "campaign release package storage contains an unsafe symlink"
                )
            if destination.read_bytes() == raw:
                return False
            raise CampaignReleasePackageError(
                "campaign release package already exists with different immutable content"
            )
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{package.release_id}-",
            suffix=".tmp",
            dir=destination.parent,
        )
        temporary = Path(temporary_name)
        try:
            os.fchmod(descriptor, 0o600)
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(raw)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, destination)
            os.chmod(destination, 0o600)
        except Exception:
            temporary.unlink(missing_ok=True)
            raise
        return True

    def load(self, campaign_id: str, release_id: str) -> CampaignReleasePackage:
        safe_release_id = _safe_component(release_id, "release ID")
        path = self._campaign_directory(campaign_id) / f"{safe_release_id}.json"
        try:
            if path.is_symlink():
                raise CampaignReleasePackageError(
                    "campaign release package storage contains an unsafe symlink"
                )
            package = CampaignReleasePackage.model_validate_json(path.read_text(encoding="utf-8"))
        except CampaignReleasePackageError:
            raise
        except (OSError, ValidationError) as exc:
            raise CampaignReleasePackageError(
                "campaign release package is unavailable or invalid"
            ) from exc
        if package.campaign_id != campaign_id or package.release_id != release_id:
            raise CampaignReleasePackageError("campaign release package storage key does not match")
        if campaign_release_package_sha256(package) != package.package_sha256:
            raise CampaignReleasePackageError("campaign release package failed integrity verification")
        return package


def create_campaign_release_package(
    governance_store: GovernanceStore,
    package_store: CampaignReleasePackageStore,
    repositories: dict[str, ScanRepository],
    *,
    campaign_id: str,
) -> tuple[CampaignReleasePackage, bool]:
    package = build_campaign_release_package(
        governance_store,
        repositories,
        campaign_id=campaign_id,
    )
    created = package_store.save(package)
    return package, created


__all__ = [
    "CampaignApplicationProvenance",
    "CampaignReleasePackage",
    "CampaignReleasePackageError",
    "CampaignReleasePackageStore",
    "CampaignReviewProvenance",
    "build_campaign_release_package",
    "campaign_release_package_sha256",
    "create_campaign_release_package",
]
