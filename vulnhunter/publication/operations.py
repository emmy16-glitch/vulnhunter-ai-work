"""Read-only readiness assessment and narrowly safe publication recovery."""

from __future__ import annotations

import hashlib
import os
import shutil
import stat
from dataclasses import asdict, dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Literal

from vulnhunter.exceptions import GovernanceError, GovernanceNotFoundError
from vulnhunter.governance.store import GovernanceStore
from vulnhunter.publication.models import PublicationManifest
from vulnhunter.publication.service import PublicationDestinationConfig
from vulnhunter.publication.store import PublicationStore, PublicationStoreError

CheckState = Literal["ok", "warning", "failed", "disabled"]
IssueSeverity = Literal["warning", "blocker"]


@dataclass(frozen=True)
class PublicationReadinessCheck:
    name: str
    state: CheckState
    detail: str


@dataclass(frozen=True)
class PublicationStateAudit:
    counts: dict[str, int]
    current_publication_ids: tuple[str, ...]


@dataclass(frozen=True)
class PublicationRecoveryIssue:
    code: str
    severity: IssueSeverity
    recoverable: bool
    destination_id: str | None
    publication_id: str | None
    relative_path: str | None
    detail: str


@dataclass(frozen=True)
class PublicationRecoveryReport:
    inspected_at: datetime
    issues: tuple[PublicationRecoveryIssue, ...]
    actions: tuple[str, ...] = ()

    @property
    def blockers(self) -> tuple[PublicationRecoveryIssue, ...]:
        return tuple(item for item in self.issues if item.severity == "blocker")

    @property
    def warnings(self) -> tuple[PublicationRecoveryIssue, ...]:
        return tuple(item for item in self.issues if item.severity == "warning")

    @property
    def ready(self) -> bool:
        return not self.blockers

    def as_dict(self) -> dict[str, object]:
        return {
            "inspected_at": self.inspected_at.astimezone(UTC).isoformat(),
            "ready": self.ready,
            "issues": [asdict(item) for item in self.issues],
            "actions": list(self.actions),
        }


@dataclass(frozen=True)
class PublicationReadinessReport:
    enabled: bool
    ready: bool
    checked_at: datetime
    checks: tuple[PublicationReadinessCheck, ...]
    blockers: tuple[str, ...]
    warnings: tuple[str, ...]
    authority_ids: tuple[str, ...]
    destination_ids: tuple[str, ...]
    state_counts: dict[str, int]

    @property
    def status(self) -> CheckState:
        if not self.enabled:
            return "disabled"
        return "ok" if self.ready else "failed"

    def as_dict(self) -> dict[str, object]:
        return {
            "enabled": self.enabled,
            "ready": self.ready,
            "status": self.status,
            "checked_at": self.checked_at.astimezone(UTC).isoformat(),
            "checks": [asdict(item) for item in self.checks],
            "blockers": list(self.blockers),
            "warnings": list(self.warnings),
            "authority_ids": list(self.authority_ids),
            "destination_ids": list(self.destination_ids),
            "state_counts": dict(self.state_counts),
        }


def disabled_publication_readiness(
    detail: str = "publication activation is not configured",
) -> PublicationReadinessReport:
    return PublicationReadinessReport(
        enabled=False,
        ready=False,
        checked_at=datetime.now(UTC),
        checks=(PublicationReadinessCheck("activation", "disabled", detail),),
        blockers=(),
        warnings=(),
        authority_ids=(),
        destination_ids=(),
        state_counts={},
    )


def failed_publication_readiness(blocker: str) -> PublicationReadinessReport:
    return PublicationReadinessReport(
        enabled=True,
        ready=False,
        checked_at=datetime.now(UTC),
        checks=(PublicationReadinessCheck("activation", "failed", blocker),),
        blockers=(blocker,),
        warnings=(),
        authority_ids=(),
        destination_ids=(),
        state_counts={},
    )


def _record_identifiers(store: PublicationStore, category: str) -> tuple[str, ...]:
    directory = store.root / category
    if not directory.exists():
        return ()
    if directory.is_symlink() or not directory.is_dir():
        raise PublicationStoreError("publication state category is not a safe directory")
    identifiers: list[str] = []
    for path in sorted(directory.iterdir()):
        if path.is_symlink():
            raise PublicationStoreError("publication storage contains an unsafe symlink")
        if path.suffix != ".json":
            continue
        if not path.is_file():
            raise PublicationStoreError("publication state contains an invalid record entry")
        identifiers.append(path.stem)
    return tuple(identifiers)


def _load_verified_state(store: PublicationStore):
    requests = {
        identifier: store.load_request(identifier)
        for identifier in _record_identifiers(store, "requests")
    }
    approvals = {
        identifier: store.load_approval(identifier)
        for identifier in _record_identifiers(store, "approvals")
    }
    publications = {
        identifier: store.load_publication(identifier)
        for identifier in _record_identifiers(store, "publications")
    }
    corrections = {
        identifier: store.load_correction(identifier)
        for identifier in _record_identifiers(store, "corrections")
    }
    revocations = {
        identifier: store.load_revocation(identifier)
        for identifier in _record_identifiers(store, "revocations")
    }
    return requests, approvals, publications, corrections, revocations


def audit_publication_state(store: PublicationStore) -> PublicationStateAudit:
    """Verify every signed record and all cross-record digest relationships."""

    requests, approvals, publications, corrections, revocations = _load_verified_state(store)

    for approval in approvals.values():
        request = requests.get(approval.request_id)
        if request is None:
            raise PublicationStoreError("release approval references a missing request")
        if approval.request_sha256 != request.fingerprint():
            raise PublicationStoreError("release approval request digest does not match")

    publications_by_request: dict[str, list[PublicationManifest]] = {}
    for publication in publications.values():
        request = requests.get(publication.request_id)
        approval = approvals.get(publication.approval_id)
        if request is None or approval is None:
            raise PublicationStoreError("publication references missing release authority state")
        if publication.request_sha256 != request.fingerprint():
            raise PublicationStoreError("publication request digest does not match")
        if publication.approval_sha256 != approval.fingerprint():
            raise PublicationStoreError("publication approval digest does not match")
        if approval.request_id != request.request_id:
            raise PublicationStoreError("publication approval belongs to another request")
        bound_values = (
            publication.source_report_id == request.source_report_id,
            publication.source_manifest_id == request.source_manifest_id,
            publication.source_report_sha256 == request.source_report_sha256,
            publication.source_manifest_sha256 == request.source_manifest_sha256,
            publication.source_finding_id == request.source_finding_id,
            publication.destination == request.destination,
            publication.requester_id == request.requester_id,
            publication.approver_id == approval.approver_id,
            publication.correction_of_publication_id == request.correction_of_publication_id,
        )
        if not all(bound_values):
            raise PublicationStoreError("publication failed request and approval binding")
        publications_by_request.setdefault(publication.request_id, []).append(publication)

    if any(len(items) > 1 for items in publications_by_request.values()):
        raise PublicationStoreError("release request has multiple publication records")

    for superseded_id, correction in corrections.items():
        superseded = publications.get(superseded_id)
        replacement = publications.get(correction.replacement_publication_id)
        if superseded is None or replacement is None:
            raise PublicationStoreError("publication correction references missing publication state")
        if correction.superseded_publication_id != superseded.publication_id:
            raise PublicationStoreError("publication correction storage key does not match")
        if correction.replacement_publication_sha256 != replacement.fingerprint():
            raise PublicationStoreError("publication correction replacement digest does not match")
        if replacement.correction_of_publication_id != superseded.publication_id:
            raise PublicationStoreError("replacement publication does not bind its correction target")

    for publication_id, revocation in revocations.items():
        publication = publications.get(publication_id)
        if publication is None:
            raise PublicationStoreError("publication revocation references missing publication state")
        if revocation.publication_id != publication.publication_id:
            raise PublicationStoreError("publication revocation storage key does not match")
        if revocation.publication_sha256 != publication.fingerprint():
            raise PublicationStoreError("publication revocation digest does not match")
        if publication_id in corrections:
            raise PublicationStoreError("a publication cannot be both superseded and revoked")

    current_by_finding: dict[str, list[str]] = {}
    for publication in publications.values():
        if publication.publication_id in corrections or publication.publication_id in revocations:
            continue
        current_by_finding.setdefault(publication.source_finding_id, []).append(
            publication.publication_id
        )
    if any(len(items) > 1 for items in current_by_finding.values()):
        raise PublicationStoreError("multiple current publications exist for one finding")

    return PublicationStateAudit(
        counts={
            "requests": len(requests),
            "approvals": len(approvals),
            "publications": len(publications),
            "corrections": len(corrections),
            "revocations": len(revocations),
        },
        current_publication_ids=tuple(
            sorted(item for items in current_by_finding.values() for item in items)
        ),
    )


def _private_directory_problem(path: Path) -> str | None:
    try:
        metadata = path.stat()
    except OSError as exc:
        return f"directory metadata is unavailable: {exc}"
    if path.is_symlink() or not stat.S_ISDIR(metadata.st_mode):
        return "path is not a safe directory"
    mode = stat.S_IMODE(metadata.st_mode)
    if mode & 0o077:
        return f"directory mode {mode:04o} is not owner-private"
    if not mode & stat.S_IWUSR or not mode & stat.S_IXUSR:
        return "directory is not writable and searchable by its owner"
    if hasattr(os, "geteuid") and metadata.st_uid != os.geteuid():
        return "directory is not owned by the application account"
    return None


def _probe_destination_write(root: Path) -> None:
    path = root / f".publication-preflight-{os.getpid()}-{os.urandom(4).hex()}"
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(b"publication-preflight\n")
            handle.flush()
            os.fsync(handle.fileno())
    finally:
        path.unlink(missing_ok=True)


def _issue(
    code: str,
    *,
    severity: IssueSeverity,
    recoverable: bool,
    detail: str,
    destination_id: str | None = None,
    publication_id: str | None = None,
    relative_path: str | None = None,
) -> PublicationRecoveryIssue:
    return PublicationRecoveryIssue(
        code=code,
        severity=severity,
        recoverable=recoverable,
        destination_id=destination_id,
        publication_id=publication_id,
        relative_path=relative_path,
        detail=detail,
    )


def inspect_publication_operations(
    store: PublicationStore,
    destinations: tuple[PublicationDestinationConfig, ...],
    *,
    now: datetime | None = None,
    stale_after: timedelta = timedelta(hours=1),
) -> PublicationRecoveryReport:
    """Inspect destination and signed-state consistency without changing anything."""

    inspected_at = (now or datetime.now(UTC)).astimezone(UTC)
    issues: list[PublicationRecoveryIssue] = []
    if stale_after <= timedelta(0):
        raise ValueError("stale publication threshold must be positive")

    try:
        audit_publication_state(store)
        _, _, publications, corrections, revocations = _load_verified_state(store)
    except PublicationStoreError as exc:
        return PublicationRecoveryReport(
            inspected_at=inspected_at,
            issues=(
                _issue(
                    "state_integrity_failed",
                    severity="blocker",
                    recoverable=False,
                    detail=str(exc),
                ),
            ),
        )

    configs = {item.destination_id: item for item in destinations}
    for destination_id, config in configs.items():
        root = config.resolved_root()
        problem = _private_directory_problem(root)
        if problem is not None:
            issues.append(
                _issue(
                    "destination_unavailable",
                    severity="blocker",
                    recoverable=False,
                    destination_id=destination_id,
                    detail=problem,
                )
            )
            continue
        known = {
            item.publication_id
            for item in publications.values()
            if item.destination.destination_id == destination_id
        }
        try:
            children = tuple(root.iterdir())
        except OSError as exc:
            issues.append(
                _issue(
                    "destination_unreadable",
                    severity="blocker",
                    recoverable=False,
                    destination_id=destination_id,
                    detail=str(exc),
                )
            )
            continue
        for child in children:
            if child.is_symlink():
                issues.append(
                    _issue(
                        "unsafe_destination_symlink",
                        severity="blocker",
                        recoverable=False,
                        destination_id=destination_id,
                        relative_path=child.name,
                        detail="destination contains a symlink",
                    )
                )
                continue
            if child.name.startswith(".publication-") and child.is_dir():
                modified = datetime.fromtimestamp(child.stat().st_mtime, tz=UTC)
                stale = inspected_at - modified >= stale_after
                issues.append(
                    _issue(
                        "stale_staging_directory" if stale else "active_staging_directory",
                        severity="blocker" if stale else "warning",
                        recoverable=stale,
                        destination_id=destination_id,
                        relative_path=child.name,
                        detail=(
                            "staging directory exceeded the operator recovery threshold"
                            if stale
                            else "publication staging directory may belong to an active operation"
                        ),
                    )
                )
                continue
            if child.is_dir() and child.name.startswith("publication-") and child.name not in known:
                issues.append(
                    _issue(
                        "orphan_publication_directory",
                        severity="blocker",
                        recoverable=False,
                        destination_id=destination_id,
                        relative_path=child.name,
                        detail="artifact directory has no matching signed publication record",
                    )
                )

    for publication in publications.values():
        destination_id = publication.destination.destination_id
        config = configs.get(destination_id)
        if config is None:
            issues.append(
                _issue(
                    "destination_configuration_missing",
                    severity="blocker",
                    recoverable=False,
                    destination_id=destination_id,
                    publication_id=publication.publication_id,
                    detail="signed publication destination is no longer configured",
                )
            )
            continue
        if config.policy() != publication.destination:
            issues.append(
                _issue(
                    "destination_policy_changed",
                    severity="blocker",
                    recoverable=False,
                    destination_id=destination_id,
                    publication_id=publication.publication_id,
                    detail="configured destination policy no longer matches signed state",
                )
            )
            continue
        root = config.resolved_root()
        directory = root / publication.publication_id
        if directory.is_symlink() or not directory.is_dir():
            issues.append(
                _issue(
                    "publication_directory_missing",
                    severity="blocker",
                    recoverable=False,
                    destination_id=destination_id,
                    publication_id=publication.publication_id,
                    relative_path=publication.publication_id,
                    detail="published artifact directory is missing or unsafe",
                )
            )
            continue

        metadata_files: tuple[tuple[str, str, object | None], ...] = (
            ("publication-manifest.json", "publications", publication),
            ("correction.json", "corrections", corrections.get(publication.publication_id)),
            ("revocation.json", "revocations", revocations.get(publication.publication_id)),
        )
        for filename, category, record in metadata_files:
            if record is None:
                continue
            path = directory / filename
            if not path.exists():
                issues.append(
                    _issue(
                        f"missing_{category.rstrip('s')}_notice",
                        severity="blocker",
                        recoverable=True,
                        destination_id=destination_id,
                        publication_id=publication.publication_id,
                        relative_path=f"{publication.publication_id}/{filename}",
                        detail="signed metadata file is missing and can be restored exactly",
                    )
                )
                continue
            if path.is_symlink() or not path.is_file():
                issues.append(
                    _issue(
                        "unsafe_publication_metadata",
                        severity="blocker",
                        recoverable=False,
                        destination_id=destination_id,
                        publication_id=publication.publication_id,
                        relative_path=f"{publication.publication_id}/{filename}",
                        detail="publication metadata path is not a regular file",
                    )
                )
                continue
            expected = store.signed_envelope_bytes(category, record)
            try:
                current = path.read_bytes()
            except OSError as exc:
                issues.append(
                    _issue(
                        "publication_metadata_unreadable",
                        severity="blocker",
                        recoverable=False,
                        destination_id=destination_id,
                        publication_id=publication.publication_id,
                        relative_path=f"{publication.publication_id}/{filename}",
                        detail=str(exc),
                    )
                )
            else:
                if current != expected:
                    issues.append(
                        _issue(
                            "publication_metadata_mismatch",
                            severity="blocker",
                            recoverable=False,
                            destination_id=destination_id,
                            publication_id=publication.publication_id,
                            relative_path=f"{publication.publication_id}/{filename}",
                            detail="publication metadata differs from verified signed state",
                        )
                    )

        for artifact in publication.artifacts:
            path = directory / artifact.published_filename
            if path.is_symlink() or not path.is_file():
                issues.append(
                    _issue(
                        "publication_artifact_missing",
                        severity="blocker",
                        recoverable=False,
                        destination_id=destination_id,
                        publication_id=publication.publication_id,
                        relative_path=f"{publication.publication_id}/{artifact.published_filename}",
                        detail="published artifact is missing or unsafe",
                    )
                )
                continue
            try:
                raw = path.read_bytes()
            except OSError as exc:
                issues.append(
                    _issue(
                        "publication_artifact_unreadable",
                        severity="blocker",
                        recoverable=False,
                        destination_id=destination_id,
                        publication_id=publication.publication_id,
                        relative_path=f"{publication.publication_id}/{artifact.published_filename}",
                        detail=str(exc),
                    )
                )
                continue
            if len(raw) != artifact.size_bytes or hashlib.sha256(raw).hexdigest() != artifact.sha256:
                issues.append(
                    _issue(
                        "publication_artifact_mismatch",
                        severity="blocker",
                        recoverable=False,
                        destination_id=destination_id,
                        publication_id=publication.publication_id,
                        relative_path=f"{publication.publication_id}/{artifact.published_filename}",
                        detail="published artifact failed size or digest verification",
                    )
                )

    return PublicationRecoveryReport(inspected_at=inspected_at, issues=tuple(issues))


def _write_new_file(path: Path, raw: bytes) -> None:
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        return
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
    except Exception:
        path.unlink(missing_ok=True)
        raise


def recover_publication_operations(
    store: PublicationStore,
    destinations: tuple[PublicationDestinationConfig, ...],
    *,
    apply_safe: bool = False,
    now: datetime | None = None,
    stale_after: timedelta = timedelta(hours=1),
) -> PublicationRecoveryReport:
    """Inspect or repair only deterministic metadata and stale staging state."""

    inspected_at = (now or datetime.now(UTC)).astimezone(UTC)
    initial = inspect_publication_operations(
        store,
        destinations,
        now=inspected_at,
        stale_after=stale_after,
    )
    if not apply_safe:
        return initial

    configs = {item.destination_id: item for item in destinations}
    _, _, publications, corrections, revocations = _load_verified_state(store)
    actions: list[str] = []
    for issue in initial.issues:
        if not issue.recoverable or issue.destination_id is None:
            continue
        config = configs.get(issue.destination_id)
        if config is None:
            continue
        root = config.resolved_root()
        if issue.code == "stale_staging_directory" and issue.relative_path:
            candidate = root / issue.relative_path
            if (
                candidate.parent.resolve() == root
                and candidate.name.startswith(".publication-")
                and candidate.is_dir()
                and not candidate.is_symlink()
            ):
                modified = datetime.fromtimestamp(candidate.stat().st_mtime, tz=UTC)
                if inspected_at - modified >= stale_after:
                    shutil.rmtree(candidate)
                    actions.append(
                        f"removed stale staging directory {issue.destination_id}/{candidate.name}"
                    )
            continue
        if issue.publication_id is None:
            continue
        publication = publications.get(issue.publication_id)
        if publication is None:
            continue
        directory = root / publication.publication_id
        if directory.is_symlink() or not directory.is_dir():
            continue
        if issue.code == "missing_publication_notice":
            _write_new_file(
                directory / "publication-manifest.json",
                store.signed_envelope_bytes("publications", publication),
            )
            actions.append(f"restored manifest for {publication.publication_id}")
        elif issue.code == "missing_correction_notice":
            correction = corrections.get(publication.publication_id)
            if correction is not None:
                _write_new_file(
                    directory / "correction.json",
                    store.signed_envelope_bytes("corrections", correction),
                )
                actions.append(f"restored correction notice for {publication.publication_id}")
        elif issue.code == "missing_revocation_notice":
            revocation = revocations.get(publication.publication_id)
            if revocation is not None:
                _write_new_file(
                    directory / "revocation.json",
                    store.signed_envelope_bytes("revocations", revocation),
                )
                actions.append(f"restored revocation notice for {publication.publication_id}")

    final = inspect_publication_operations(
        store,
        destinations,
        now=inspected_at,
        stale_after=stale_after,
    )
    return PublicationRecoveryReport(
        inspected_at=final.inspected_at,
        issues=final.issues,
        actions=tuple(actions),
    )


def assess_publication_readiness(
    governance_store: GovernanceStore,
    publication_store: PublicationStore,
    destinations: tuple[PublicationDestinationConfig, ...],
    release_authority_ids: frozenset[str],
    *,
    probe_writes: bool = False,
    minimum_free_bytes: int = 64 * 1024 * 1024,
    stale_after: timedelta = timedelta(hours=1),
) -> PublicationReadinessReport:
    """Assess full publication lifecycle readiness without publishing anything."""

    if minimum_free_bytes < 0:
        raise ValueError("minimum publication free bytes must be non-negative")
    checked_at = datetime.now(UTC)
    blockers: list[str] = []
    warnings: list[str] = []
    checks: list[PublicationReadinessCheck] = []
    authorities = tuple(sorted(release_authority_ids))
    destination_ids = tuple(sorted(item.destination_id for item in destinations))

    authority_problems: list[str] = []
    if len(authorities) < 3:
        authority_problems.append("at least three distinct publication authorities are required")
    if len(authorities) == 3:
        warnings.append(
            "only three authorities are configured; independent revocation requires a fourth"
        )
    for authority_id in authorities:
        try:
            identity = governance_store.get_identity(authority_id)
        except GovernanceNotFoundError:
            authority_problems.append(f"configured authority {authority_id} does not exist")
            continue
        except (GovernanceError, OSError, RuntimeError, ValueError) as exc:
            authority_problems.append(
                f"configured authority {authority_id} could not be verified: {exc}"
            )
            continue
        if identity.status != "active":
            authority_problems.append(f"configured authority {authority_id} is {identity.status}")
        if "campaign_admin" not in identity.roles:
            authority_problems.append(
                f"configured authority {authority_id} lacks campaign_admin role"
            )
    if authority_problems:
        blockers.extend(authority_problems)
        checks.append(
            PublicationReadinessCheck("authorities", "failed", "; ".join(authority_problems))
        )
    else:
        state: CheckState = "warning" if len(authorities) == 3 else "ok"
        checks.append(
            PublicationReadinessCheck(
                "authorities",
                state,
                f"{len(authorities)} active configured publication authorities verified",
            )
        )

    destination_problems: list[str] = []
    if not destinations:
        destination_problems.append("at least one publication destination is required")
    if len(set(destination_ids)) != len(destination_ids):
        destination_problems.append("publication destination IDs must be unique")
    for config in destinations:
        root = config.resolved_root()
        problem = _private_directory_problem(root)
        if problem is not None:
            destination_problems.append(f"destination {config.destination_id}: {problem}")
            continue
        try:
            free_bytes = shutil.disk_usage(root).free
        except OSError as exc:
            destination_problems.append(
                f"destination {config.destination_id}: disk usage unavailable: {exc}"
            )
            continue
        if free_bytes < minimum_free_bytes:
            destination_problems.append(
                f"destination {config.destination_id}: only {free_bytes} free bytes remain"
            )
        if probe_writes:
            try:
                _probe_destination_write(root)
            except OSError as exc:
                destination_problems.append(
                    f"destination {config.destination_id}: write probe failed: {exc}"
                )
    if destination_problems:
        blockers.extend(destination_problems)
        checks.append(
            PublicationReadinessCheck(
                "destinations", "failed", "; ".join(destination_problems)
            )
        )
    else:
        probe_detail = " with write probes" if probe_writes else ""
        checks.append(
            PublicationReadinessCheck(
                "destinations",
                "ok",
                f"{len(destinations)} owner-private destination(s) verified{probe_detail}",
            )
        )

    state_counts: dict[str, int] = {}
    try:
        audit = audit_publication_state(publication_store)
    except PublicationStoreError as exc:
        blockers.append(f"publication state integrity failed: {exc}")
        checks.append(PublicationReadinessCheck("signed_state", "failed", str(exc)))
    else:
        state_counts = audit.counts
        checks.append(
            PublicationReadinessCheck(
                "signed_state",
                "ok",
                "all signed publication records and cross-record digests verified",
            )
        )

    recovery = inspect_publication_operations(
        publication_store,
        destinations,
        now=checked_at,
        stale_after=stale_after,
    )
    recovery_blockers = [item.detail for item in recovery.blockers]
    recovery_warnings = [item.detail for item in recovery.warnings]
    if recovery_blockers:
        blockers.extend(f"publication recovery required: {item}" for item in recovery_blockers)
        checks.append(
            PublicationReadinessCheck(
                "recovery",
                "failed",
                f"{len(recovery_blockers)} blocking recovery issue(s) detected",
            )
        )
    elif recovery_warnings:
        warnings.extend(recovery_warnings)
        checks.append(
            PublicationReadinessCheck(
                "recovery",
                "warning",
                f"{len(recovery_warnings)} active-operation warning(s) detected",
            )
        )
    else:
        checks.append(
            PublicationReadinessCheck(
                "recovery",
                "ok",
                "no interrupted publication operation requires recovery",
            )
        )

    return PublicationReadinessReport(
        enabled=True,
        ready=not blockers,
        checked_at=checked_at,
        checks=tuple(checks),
        blockers=tuple(blockers),
        warnings=tuple(warnings),
        authority_ids=authorities,
        destination_ids=destination_ids,
        state_counts=state_counts,
    )


__all__ = [
    "PublicationReadinessCheck",
    "PublicationReadinessReport",
    "PublicationRecoveryIssue",
    "PublicationRecoveryReport",
    "PublicationStateAudit",
    "assess_publication_readiness",
    "audit_publication_state",
    "disabled_publication_readiness",
    "failed_publication_readiness",
    "inspect_publication_operations",
    "recover_publication_operations",
]
