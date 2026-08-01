"""Read-only operator assessment for governed real-data campaign execution."""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from vulnhunter.authorization import AuthorizationStore
from vulnhunter.exceptions import AuthorizationError, GovernanceError, GovernanceNotFoundError
from vulnhunter.governance.release_package import (
    CampaignReleasePackage,
    CampaignReleasePackageError,
    build_campaign_release_package,
    campaign_release_package_sha256,
)
from vulnhunter.governance.service import assess_release
from vulnhunter.governance.store import GovernanceStore
from vulnhunter.observations.storage import ScanRepository
from vulnhunter.security import redact_url

PrerequisiteState = Literal["met", "blocked", "warning", "not_applicable"]
ReleasePackageState = Literal["not_released", "missing", "verified", "invalid"]
_IDENTIFIER = re.compile(r"^[a-z0-9][a-z0-9._-]{1,127}$")


class CampaignOperationsPrerequisite(BaseModel):
    """One operator-visible campaign gate without secret or filesystem detail."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    code: str = Field(min_length=1, max_length=100)
    title: str = Field(min_length=1, max_length=200)
    state: PrerequisiteState
    detail: str = Field(min_length=1, max_length=2_000)


class CampaignFamilyCoverage(BaseModel):
    """Coverage for one declared application family."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    application_family: str
    application_count: int = Field(ge=0)
    environments: tuple[str, ...]
    authorization_count: int = Field(ge=0)
    current_authorization_count: int = Field(ge=0)
    ownership_evidence_count: int = Field(ge=0)
    linked_scan_count: int = Field(ge=0)
    observation_count: int = Field(ge=0)


class CampaignReviewWorkload(BaseModel):
    """Current governed review workload without repository paths."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    total_observations: int = Field(ge=0)
    assigned_observations: int = Field(ge=0)
    unassigned_observations: int = Field(ge=0)
    awaiting_primary_review: int = Field(ge=0)
    disputed: int = Field(ge=0)
    consensus: int = Field(ge=0)
    adjudicated: int = Field(ge=0)
    final_observations: int = Field(ge=0)
    unavailable_or_invalid: int = Field(ge=0)


class CampaignReleasePackageStatus(BaseModel):
    """Verified persisted package state for one immutable dataset release."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    state: ReleasePackageState
    detail: str
    release_id: str | None = None
    package_id: str | None = None
    package_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")


class CampaignOperationsSnapshot(BaseModel):
    """Truthful operator view of activation, collection, review and release gates."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    campaign_id: str
    title: str
    purpose: str
    owner_id: str
    campaign_status: str
    assessed_at: datetime
    operator_activation_ready: bool
    genuine_collection_ready: bool
    release_ready: bool
    application_count: int = Field(ge=0)
    minimum_applications: int = Field(ge=1)
    application_family_count: int = Field(ge=0)
    minimum_application_families: int = Field(ge=1)
    authorization_count: int = Field(ge=0)
    current_authorization_count: int = Field(ge=0)
    ownership_evidence_count: int = Field(ge=0)
    families: tuple[CampaignFamilyCoverage, ...]
    review_workload: CampaignReviewWorkload
    release_manifest_state: str
    release_manifest_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    release_package: CampaignReleasePackageStatus
    prerequisites: tuple[CampaignOperationsPrerequisite, ...]
    blockers: tuple[str, ...]
    warnings: tuple[str, ...]
    next_actions: tuple[str, ...]


@dataclass
class _FamilyAccumulator:
    applications: set[str] = field(default_factory=set)
    environments: set[str] = field(default_factory=set)
    authorizations: set[str] = field(default_factory=set)
    current_authorizations: set[str] = field(default_factory=set)
    ownership_evidence: set[str] = field(default_factory=set)
    scans: int = 0
    observations: int = 0


def _prerequisite(
    code: str,
    title: str,
    state: PrerequisiteState,
    detail: str,
) -> CampaignOperationsPrerequisite:
    return CampaignOperationsPrerequisite(code=code, title=title, state=state, detail=detail)


def _authorization_addresses_are_private(authorization) -> bool:
    try:
        addresses = tuple(ipaddress.ip_address(value) for value in authorization.approved_addresses)
    except ValueError:
        return False
    return bool(addresses) and all(item.is_private or item.is_loopback for item in addresses)


def _authorization_is_current(authorization, application, campaign, now: datetime) -> bool:
    if authorization.status != "active":
        return False
    if now < authorization.valid_from or now >= authorization.expires_at:
        return False
    if authorization.record_sha256 != application.authorization_record_sha256:
        return False
    if redact_url(authorization.target_url) != application.target_url:
        return False
    if not _authorization_addresses_are_private(authorization):
        return False
    if campaign.limits.maximum_pages > authorization.limits.maximum_pages:
        return False
    if campaign.limits.maximum_depth > authorization.limits.maximum_depth:
        return False
    if campaign.limits.maximum_requests > authorization.limits.maximum_requests:
        return False
    return (
        campaign.limits.minimum_request_delay_seconds
        >= authorization.limits.minimum_request_delay_seconds
    )


def _ownership_evidence_is_explicit(authorization) -> bool:
    evidence_reference = authorization.evidence_reference or ""
    return bool(
        authorization.owner.strip()
        and authorization.approved_by.strip()
        and authorization.purpose.strip()
        and evidence_reference.strip()
        and authorization.owner.strip().casefold()
        != authorization.approved_by.strip().casefold()
    )


def _review_workload(
    governance_store: GovernanceStore,
    repositories: dict[str, ScanRepository],
    campaign_id: str,
) -> CampaignReviewWorkload:
    scans = governance_store.list_scans(campaign_id)
    assignments = governance_store.list_assignments(campaign_id)
    total_observations = sum(item.observations_count for item in scans)
    awaiting = 0
    disputed = 0
    consensus = 0
    adjudicated = 0
    unavailable = 0

    for assignment in assignments:
        repository = repositories.get(assignment.scan_database)
        if repository is None:
            unavailable += 1
            continue
        try:
            case = repository.get_review_case(assignment.observation_id)
        except (OSError, RuntimeError, ValueError):
            unavailable += 1
            continue
        if case.state == "disputed":
            disputed += 1
        elif case.state == "consensus":
            consensus += 1
        elif case.state == "adjudicated":
            adjudicated += 1
        else:
            awaiting += 1

    assigned = len(assignments)
    final_count = consensus + adjudicated
    return CampaignReviewWorkload(
        total_observations=total_observations,
        assigned_observations=assigned,
        unassigned_observations=max(0, total_observations - assigned),
        awaiting_primary_review=awaiting,
        disputed=disputed,
        consensus=consensus,
        adjudicated=adjudicated,
        final_observations=final_count,
        unavailable_or_invalid=unavailable,
    )


def _release_package_status(
    governance_store: GovernanceStore,
    repositories: dict[str, ScanRepository],
    package_root: Path,
    *,
    campaign_id: str,
    release,
) -> CampaignReleasePackageStatus:
    if release is None:
        return CampaignReleasePackageStatus(
            state="not_released",
            detail="No immutable dataset release exists, so no release package is expected.",
        )
    if _IDENTIFIER.fullmatch(campaign_id) is None or _IDENTIFIER.fullmatch(release.release_id) is None:
        return CampaignReleasePackageStatus(
            state="invalid",
            detail="The release identifiers are not safe stable package keys.",
            release_id=release.release_id,
        )

    root = package_root.expanduser()
    campaign_directory = root / campaign_id
    path = campaign_directory / f"{release.release_id}.json"
    try:
        if root.is_symlink() or campaign_directory.is_symlink() or path.is_symlink():
            raise CampaignReleasePackageError("unsafe release-package storage symlink")
        if not path.is_file():
            return CampaignReleasePackageStatus(
                state="missing",
                detail="The dataset is released, but its append-only provenance package is missing.",
                release_id=release.release_id,
            )
        package = CampaignReleasePackage.model_validate_json(path.read_text(encoding="utf-8"))
        if package.campaign_id != campaign_id or package.release_id != release.release_id:
            raise CampaignReleasePackageError("release package storage key mismatch")
        if campaign_release_package_sha256(package) != package.package_sha256:
            raise CampaignReleasePackageError("release package integrity mismatch")
        expected = build_campaign_release_package(
            governance_store,
            repositories,
            campaign_id=campaign_id,
        )
        if package.package_sha256 != expected.package_sha256:
            raise CampaignReleasePackageError("release package no longer matches governed state")
    except (
        CampaignReleasePackageError,
        GovernanceError,
        OSError,
        RuntimeError,
        ValueError,
        ValidationError,
    ):
        return CampaignReleasePackageStatus(
            state="invalid",
            detail="The persisted release package is unavailable, unsafe, or does not match governed state.",
            release_id=release.release_id,
        )
    return CampaignReleasePackageStatus(
        state="verified",
        detail="The append-only release package matches the current governed release evidence.",
        release_id=release.release_id,
        package_id=package.package_id,
        package_sha256=package.package_sha256,
    )


def _family_coverage(
    applications,
    scans,
    current_authorization_ids: set[str],
    ownership_evidence_ids: set[str],
) -> tuple[CampaignFamilyCoverage, ...]:
    accumulators: dict[str, _FamilyAccumulator] = {}
    family_by_application = {
        application.application_id: application.application_family for application in applications
    }
    for application in applications:
        accumulator = accumulators.setdefault(
            application.application_family,
            _FamilyAccumulator(),
        )
        accumulator.applications.add(application.application_id)
        accumulator.environments.add(application.environment)
        accumulator.authorizations.add(application.authorization_id)
        if application.application_id in current_authorization_ids:
            accumulator.current_authorizations.add(application.authorization_id)
        if application.application_id in ownership_evidence_ids:
            accumulator.ownership_evidence.add(application.authorization_id)
    for scan in scans:
        family = family_by_application.get(scan.application_id)
        if family is None:
            continue
        accumulator = accumulators[family]
        accumulator.scans += 1
        accumulator.observations += scan.observations_count

    return tuple(
        CampaignFamilyCoverage(
            application_family=family,
            application_count=len(accumulator.applications),
            environments=tuple(sorted(accumulator.environments)),
            authorization_count=len(accumulator.authorizations),
            current_authorization_count=len(accumulator.current_authorizations),
            ownership_evidence_count=len(accumulator.ownership_evidence),
            linked_scan_count=accumulator.scans,
            observation_count=accumulator.observations,
        )
        for family, accumulator in sorted(accumulators.items())
    )


def assess_campaign_operations(
    governance_store: GovernanceStore,
    authorization_store: AuthorizationStore,
    repositories: dict[str, ScanRepository],
    package_root: Path,
    *,
    campaign_id: str,
    now: datetime | None = None,
) -> CampaignOperationsSnapshot:
    """Assess operator gates without changing campaign, review or release state."""

    assessed_at = (now or datetime.now(UTC)).astimezone(UTC)
    campaign = governance_store.get_campaign(campaign_id)
    applications = governance_store.list_applications(campaign_id)
    scans = governance_store.list_scans(campaign_id)
    prerequisites: list[CampaignOperationsPrerequisite] = []
    blockers: list[str] = []
    warnings: list[str] = []

    integrity_ok = True
    try:
        governance_store.verify_integrity()
    except GovernanceError:
        integrity_ok = False
        blockers.append("Governance-store integrity verification failed.")
    prerequisites.append(
        _prerequisite(
            "governance_integrity",
            "Governance integrity",
            "met" if integrity_ok else "blocked",
            (
                "All governed records and audit-chain links verify."
                if integrity_ok
                else "Campaign operations must stop until governance integrity is restored."
            ),
        )
    )

    application_count_ok = len(applications) >= campaign.minimum_applications
    if not application_count_ok:
        blockers.append(
            f"Register at least {campaign.minimum_applications} applications; found {len(applications)}."
        )
    prerequisites.append(
        _prerequisite(
            "application_count",
            "Application coverage",
            "met" if application_count_ok else "blocked",
            f"{len(applications)} of {campaign.minimum_applications} required applications are registered.",
        )
    )

    families = {item.application_family for item in applications}
    family_count_ok = len(families) >= campaign.minimum_application_families
    if not family_count_ok:
        blockers.append(
            "Register applications across at least "
            f"{campaign.minimum_application_families} families; found {len(families)}."
        )
    prerequisites.append(
        _prerequisite(
            "application_family_diversity",
            "Application-family diversity",
            "met" if family_count_ok else "blocked",
            (
                f"{len(families)} of {campaign.minimum_application_families} required "
                "application families are represented."
            ),
        )
    )

    loaded_authorization_ids: set[str] = set()
    current_authorization_ids: set[str] = set()
    ownership_evidence_ids: set[str] = set()
    for application in applications:
        try:
            authorization = authorization_store.get(application.authorization_id)
        except (AuthorizationError, OSError, RuntimeError, ValueError):
            continue
        loaded_authorization_ids.add(application.application_id)
        current = _authorization_is_current(authorization, application, campaign, assessed_at)
        if current:
            current_authorization_ids.add(application.application_id)
            if _ownership_evidence_is_explicit(authorization):
                ownership_evidence_ids.add(application.application_id)

    authorization_ok = len(current_authorization_ids) == len(applications) and bool(applications)
    if not authorization_ok:
        blockers.append(
            "Every application requires one current exact private-target authorization whose "
            "immutable hash, target and limits still match the campaign."
        )
    prerequisites.append(
        _prerequisite(
            "exact_authorizations",
            "Current exact authorizations",
            "met" if authorization_ok else "blocked",
            (
                f"{len(current_authorization_ids)} of {len(applications)} application "
                "authorizations are current, exact and private-target scoped."
            ),
        )
    )

    ownership_evidence_ok = len(ownership_evidence_ids) == len(applications) and bool(applications)
    if not ownership_evidence_ok:
        blockers.append(
            "Each application authorization must record an ownership evidence reference and a "
            "separate approving authority before a genuine campaign run."
        )
    prerequisites.append(
        _prerequisite(
            "owned_target_evidence",
            "Owned-target evidence",
            "met" if ownership_evidence_ok else "blocked",
            (
                f"{len(ownership_evidence_ids)} of {len(applications)} applications have a "
                "current authorization with ownership evidence and a separate approver."
            ),
        )
    )
    warnings.append(
        "Ownership and approval fields are recorded declarations. Operators must independently "
        "verify that each evidence reference genuinely authorizes the exact target."
    )

    approval_locked = bool(
        campaign.approved_manifest_sha256
        and campaign.approved_by
        and campaign.status in {"approved", "active", "completed"}
    )
    if campaign.status == "draft":
        approval_state: PrerequisiteState = "blocked"
        approval_detail = "The draft requires approval by a distinct campaign administrator."
        blockers.append("The campaign draft has not been independently approved.")
    elif approval_locked:
        approval_state = "met"
        approval_detail = "An independently approved immutable campaign manifest is recorded."
    elif campaign.status == "cancelled":
        approval_state = "not_applicable"
        approval_detail = "The campaign is cancelled and cannot be activated."
        blockers.append("The campaign is cancelled.")
    else:
        approval_state = "blocked"
        approval_detail = "The campaign does not have a valid approved-manifest binding."
        blockers.append("The approved campaign manifest is missing or invalid.")
    prerequisites.append(
        _prerequisite(
            "independent_campaign_approval",
            "Independent campaign approval",
            approval_state,
            approval_detail,
        )
    )

    core_prerequisites_ok = all(
        (
            integrity_ok,
            application_count_ok,
            family_count_ok,
            authorization_ok,
            ownership_evidence_ok,
        )
    )
    operator_activation_ready = (
        campaign.status == "approved" and approval_locked and core_prerequisites_ok
    )
    genuine_collection_ready = (
        campaign.status == "active" and approval_locked and core_prerequisites_ok
    )

    if campaign.status == "active" and not core_prerequisites_ok:
        warnings.append(
            "The campaign is active while one or more genuine-run prerequisites are blocked. "
            "Do not start additional collection until the authorization boundary is corrected."
        )
    if campaign.status == "completed":
        warnings.append("The campaign is completed; no additional collection should be started.")

    workload = _review_workload(governance_store, repositories, campaign_id)
    if workload.unassigned_observations:
        blockers.append(
            f"{workload.unassigned_observations} collected observations lack governed assignments."
        )
    if workload.awaiting_primary_review:
        blockers.append(
            f"{workload.awaiting_primary_review} assignments still await two primary reviews."
        )
    if workload.disputed:
        blockers.append(f"{workload.disputed} disputed reviews require independent adjudication.")
    if workload.unavailable_or_invalid:
        blockers.append(
            f"{workload.unavailable_or_invalid} review records are unavailable or invalid."
        )

    try:
        release = governance_store.get_release(campaign_id)
        release_manifest_state = "present"
        release_manifest_sha256 = release.manifest_sha256
    except GovernanceNotFoundError:
        release = None
        release_manifest_state = "missing"
        release_manifest_sha256 = None
    except GovernanceError:
        release = None
        release_manifest_state = "invalid"
        release_manifest_sha256 = None
        blockers.append("The dataset release manifest is invalid.")

    release_ready = False
    if campaign.status in {"active", "completed"}:
        try:
            release_assessment = assess_release(
                governance_store,
                authorization_store,
                repositories,
                campaign_id=campaign_id,
                now=assessed_at,
                require_completed=campaign.status == "completed",
            )
        except (AuthorizationError, GovernanceError, OSError, RuntimeError, ValueError):
            warnings.append("Release readiness could not be evaluated safely.")
        else:
            release_ready = release_assessment.ready
            if not release_assessment.ready:
                blockers.extend(release_assessment.reasons)

    package_status = _release_package_status(
        governance_store,
        repositories,
        package_root,
        campaign_id=campaign_id,
        release=release,
    )
    if release is not None and package_status.state != "verified":
        blockers.append(package_status.detail)

    next_actions: list[str] = []
    if not application_count_ok:
        next_actions.append("Register additional explicitly authorized applications.")
    if not family_count_ok:
        next_actions.append("Add applications from additional declared application families.")
    if not authorization_ok:
        next_actions.append("Reissue or repair exact current authorizations before collection.")
    if not ownership_evidence_ok:
        next_actions.append(
            "Record verifiable owned-target evidence and a separate approving authority in each authorization."
        )
    if campaign.status == "draft" and core_prerequisites_ok:
        next_actions.append("Request independent approval of the frozen campaign manifest.")
    elif operator_activation_ready:
        next_actions.append("A distinct authorized administrator may activate the approved campaign.")
    elif genuine_collection_ready and not scans:
        next_actions.append("Run only bounded scans against the exact authorized owned targets.")
    if workload.unassigned_observations:
        next_actions.append("Assign every collected observation to two independent reviewers.")
    if workload.awaiting_primary_review:
        next_actions.append("Complete both authenticated primary reviews for each assignment.")
    if workload.disputed:
        next_actions.append(
            "Resolve every disputed review through its assigned independent adjudicator."
        )
    if release_ready and campaign.status == "active":
        next_actions.append("Complete the campaign through the governed completion transition.")
    if campaign.status == "completed" and release is None:
        next_actions.append(
            "Create the immutable dataset release manifest through the governed service."
        )
    if release is not None and package_status.state == "missing":
        next_actions.append("Create the append-only campaign release provenance package.")
    if release is not None and package_status.state == "invalid":
        next_actions.append("Stop release use and investigate the invalid provenance package.")
    if not next_actions:
        next_actions.append("No additional operator action is currently required.")

    return CampaignOperationsSnapshot(
        campaign_id=campaign.campaign_id,
        title=campaign.title,
        purpose=campaign.purpose,
        owner_id=campaign.owner_id,
        campaign_status=campaign.status,
        assessed_at=assessed_at,
        operator_activation_ready=operator_activation_ready,
        genuine_collection_ready=genuine_collection_ready,
        release_ready=release_ready,
        application_count=len(applications),
        minimum_applications=campaign.minimum_applications,
        application_family_count=len(families),
        minimum_application_families=campaign.minimum_application_families,
        authorization_count=len(loaded_authorization_ids),
        current_authorization_count=len(current_authorization_ids),
        ownership_evidence_count=len(ownership_evidence_ids),
        families=_family_coverage(
            applications,
            scans,
            current_authorization_ids,
            ownership_evidence_ids,
        ),
        review_workload=workload,
        release_manifest_state=release_manifest_state,
        release_manifest_sha256=release_manifest_sha256,
        release_package=package_status,
        prerequisites=tuple(prerequisites),
        blockers=tuple(dict.fromkeys(blockers)),
        warnings=tuple(dict.fromkeys(warnings)),
        next_actions=tuple(dict.fromkeys(next_actions)),
    )


__all__ = [
    "CampaignFamilyCoverage",
    "CampaignOperationsPrerequisite",
    "CampaignOperationsSnapshot",
    "CampaignReleasePackageStatus",
    "CampaignReviewWorkload",
    "assess_campaign_operations",
]
