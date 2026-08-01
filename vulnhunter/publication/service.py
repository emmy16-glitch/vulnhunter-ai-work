"""Separate human-authorised release, correction, and revocation service."""

from __future__ import annotations

import hashlib
import os
import shutil
import tempfile
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

from vulnhunter.exceptions import (
    GovernanceAuthenticationError,
    GovernanceError,
    GovernancePolicyError,
)
from vulnhunter.governance.service import authenticate_identity
from vulnhunter.governance.store import GovernanceStore
from vulnhunter.publication.models import (
    PublicationCorrection,
    PublicationDestination,
    PublicationManifest,
    PublicationRevocation,
    PublishedArtifactReference,
    ReleaseApproval,
    ReleaseRequest,
)
from vulnhunter.publication.store import PublicationStore
from vulnhunter.reports.final_remediation import (
    FinalReportBundle,
    FinalReportFormat,
    FinalReportStore,
)
from vulnhunter.security import redact_text


class PublicationServiceError(RuntimeError):
    """A release operation violated publication authority or integrity policy."""


@dataclass(frozen=True)
class PublicationDestinationConfig:
    """Operator-owned local destination configuration; never model supplied."""

    destination_id: str
    label: str
    root: Path
    allowed_formats: tuple[FinalReportFormat, ...]

    def resolved_root(self) -> Path:
        return self.root.expanduser().resolve()

    def policy(self) -> PublicationDestination:
        root = self.resolved_root()
        return PublicationDestination(
            destination_id=self.destination_id,
            label=self.label,
            root_sha256=hashlib.sha256(str(root).encode()).hexdigest(),
            allowed_formats=self.allowed_formats,
        )


@dataclass
class PublicationService:
    """Require separate requester, approver, and publisher identities."""

    report_store: FinalReportStore
    governance_store: GovernanceStore
    publication_store: PublicationStore
    destinations: tuple[PublicationDestinationConfig, ...]
    release_authority_ids: frozenset[str]
    clock: Callable[[], datetime] = lambda: datetime.now(UTC)

    def __post_init__(self) -> None:
        if not self.release_authority_ids:
            raise PublicationServiceError("publication authorities must be configured")
        normalized = {item.strip().casefold() for item in self.release_authority_ids}
        if normalized != set(self.release_authority_ids):
            raise PublicationServiceError("publication authority IDs must be normalized")
        policies = tuple(config.policy() for config in self.destinations)
        if len({item.destination_id for item in policies}) != len(policies):
            raise PublicationServiceError("publication destination IDs must be unique")
        for config in self.destinations:
            if config.root.expanduser().is_symlink():
                raise PublicationServiceError("publication destination must not be a symlink")
            root = config.resolved_root()
            root.mkdir(parents=True, exist_ok=True)
            os.chmod(root, 0o700)

    def request_release(
        self,
        *,
        report_id: str,
        destination_id: str,
        formats: Iterable[str | FinalReportFormat],
        requester_id: str,
        requester_secret: str,
        reason: str,
        expires_at: datetime,
        correction_of_publication_id: str | None = None,
    ) -> ReleaseRequest:
        bundle = self.report_store.load(report_id)
        requester = self._authenticate(requester_id, requester_secret)
        self._reject_report_actor(requester.reviewer_id, bundle, "request release")
        destination = self._destination_config(destination_id).policy()
        selected = self._formats(formats)
        available = {item.format for item in bundle.manifest.artifacts}
        if not set(selected).issubset(available):
            raise PublicationServiceError("requested artifact is absent from source manifest")
        if not set(selected).issubset(set(destination.allowed_formats)):
            raise PublicationServiceError("destination policy forbids a requested format")

        now = self._now()
        if now < bundle.report.generated_at.astimezone(UTC):
            raise PublicationServiceError("release request predates the source report")
        if expires_at.tzinfo is None or expires_at.utcoffset() is None:
            raise PublicationServiceError("release expiry must be timezone-aware")
        expiry = expires_at.astimezone(UTC)
        if expiry <= now or expiry > now + timedelta(days=7):
            raise PublicationServiceError("release expiry must be within the next seven days")
        if correction_of_publication_id is not None:
            self._validate_correction(correction_of_publication_id, bundle)

        request = ReleaseRequest.create(
            source_report_id=bundle.report.report_id,
            source_manifest_id=bundle.manifest.manifest_id,
            source_report_sha256=bundle.report.fingerprint(),
            source_manifest_sha256=bundle.manifest.fingerprint(),
            source_finding_id=bundle.report.finding.finding_id,
            destination=destination,
            formats=selected,
            requester_id=requester.reviewer_id,
            requester_identity_sha256=requester.record_sha256,
            reason=self._reason(reason),
            correction_of_publication_id=correction_of_publication_id,
            created_at=now,
            expires_at=expiry,
        )
        self.publication_store.save_request(request)
        return request

    def approve_release(
        self,
        *,
        request_id: str,
        approver_id: str,
        approver_secret: str,
    ) -> ReleaseApproval:
        request = self.publication_store.load_request(request_id)
        now = self._now()
        if now >= request.expires_at.astimezone(UTC):
            raise PublicationServiceError("release request has expired")
        bundle = self._load_bound_report(request)
        approver = self._authenticate(approver_id, approver_secret)
        if approver.reviewer_id == request.requester_id:
            raise PublicationServiceError("release requester cannot approve their request")
        self._reject_report_actor(approver.reviewer_id, bundle, "approve release")
        approval = ReleaseApproval.create(
            request=request,
            approver_id=approver.reviewer_id,
            approver_identity_sha256=approver.record_sha256,
            approved_at=now,
        )
        self.publication_store.save_approval(approval)
        return approval

    def publish(
        self,
        *,
        request_id: str,
        approval_id: str,
        publisher_id: str,
        publisher_secret: str,
    ) -> PublicationManifest:
        request = self.publication_store.load_request(request_id)
        approval = self.publication_store.load_approval(approval_id)
        if approval.request_id != request.request_id:
            raise PublicationServiceError("release approval belongs to another request")
        if approval.request_sha256 != request.fingerprint():
            raise PublicationServiceError("release approval digest does not match")
        now = self._now()
        if now >= min(request.expires_at, approval.expires_at).astimezone(UTC):
            raise PublicationServiceError("release authority has expired")

        bundle = self._load_bound_report(request)
        publisher = self._authenticate(publisher_id, publisher_secret)
        if publisher.reviewer_id in {request.requester_id, approval.approver_id}:
            raise PublicationServiceError("publisher must differ from requester and approver")
        self._reject_report_actor(publisher.reviewer_id, bundle, "publish release")
        config = self._destination_config(request.destination.destination_id)
        if config.policy() != request.destination:
            raise PublicationServiceError("publication destination configuration changed")

        staging = Path(tempfile.mkdtemp(prefix=".publication-", dir=config.resolved_root()))
        os.chmod(staging, 0o700)
        destination: Path | None = None
        try:
            artifacts = self._copy_artifacts(bundle, request, staging)
            manifest = PublicationManifest.create(
                request=request,
                approval=approval,
                artifacts=artifacts,
                publisher_id=publisher.reviewer_id,
                publisher_identity_sha256=publisher.record_sha256,
                published_at=now,
            )
            correction = self._correction_for(request, manifest, publisher.record_sha256, now)
            self._write_new_file(
                staging / "publication-manifest.json",
                self.publication_store.signed_envelope_bytes("publications", manifest),
            )
            destination = config.resolved_root() / manifest.publication_id
            if destination.exists():
                raise PublicationServiceError("publication destination already exists")
            os.replace(staging, destination)
            self._persist_publication(manifest, correction, destination)
            return manifest
        except Exception:
            shutil.rmtree(staging, ignore_errors=True)
            if destination is not None and destination.exists():
                shutil.rmtree(destination, ignore_errors=True)
            raise

    def revoke(
        self,
        *,
        publication_id: str,
        authority_id: str,
        authority_secret: str,
        reason: str,
    ) -> PublicationRevocation:
        publication = self.publication_store.load_publication(publication_id)
        if self.publication_store.status(publication_id) != "published":
            raise PublicationServiceError("only a current publication can be revoked")
        authority = self._authenticate(authority_id, authority_secret)
        bundle = self.report_store.load(publication.source_report_id)
        self._reject_report_actor(authority.reviewer_id, bundle, "revoke release")
        release_actors = {
            publication.requester_id,
            publication.approver_id,
            publication.publisher_id,
        }
        if authority.reviewer_id in release_actors:
            raise PublicationServiceError("revoker must be independent from release actors")
        revocation = PublicationRevocation.create(
            publication=publication,
            authority_id=authority.reviewer_id,
            authority_identity_sha256=authority.record_sha256,
            reason=self._reason(reason),
            revoked_at=self._now(),
        )
        created = self.publication_store.save_revocation(revocation)
        try:
            self._write_notice(
                publication_id,
                "revocation.json",
                self.publication_store.signed_envelope_bytes("revocations", revocation),
            )
        except Exception:
            if created:
                self.publication_store.rollback_revocation(revocation)
            raise
        return revocation

    def status(self, publication_id: str) -> str:
        return self.publication_store.status(publication_id)

    def _persist_publication(
        self,
        manifest: PublicationManifest,
        correction: PublicationCorrection | None,
        destination: Path,
    ) -> None:
        publication_created = False
        correction_created = False
        notice: Path | None = None
        try:
            publication_created = self.publication_store.save_publication(manifest)
            if correction is not None:
                correction_created = self.publication_store.save_correction(correction)
                notice = self._write_notice(
                    correction.superseded_publication_id,
                    "correction.json",
                    self.publication_store.signed_envelope_bytes("corrections", correction),
                )
        except Exception:
            if notice is not None:
                notice.unlink(missing_ok=True)
            if correction_created and correction is not None:
                self.publication_store.rollback_correction(correction)
            if publication_created:
                self.publication_store.rollback_publication(manifest)
            shutil.rmtree(destination, ignore_errors=True)
            raise

    def _validate_correction(self, publication_id: str, bundle: FinalReportBundle) -> None:
        previous = self.publication_store.load_publication(publication_id)
        if self.publication_store.status(publication_id) != "published":
            raise PublicationServiceError("correction target is not currently published")
        if previous.source_finding_id != bundle.report.finding.finding_id:
            raise PublicationServiceError("correction must remain bound to one finding")
        if previous.source_report_id == bundle.report.report_id:
            raise PublicationServiceError("correction requires a newly generated report")

    @staticmethod
    def _correction_for(
        request: ReleaseRequest,
        manifest: PublicationManifest,
        publisher_identity_sha256: str,
        now: datetime,
    ) -> PublicationCorrection | None:
        if request.correction_of_publication_id is None:
            return None
        return PublicationCorrection.create(
            superseded_publication_id=request.correction_of_publication_id,
            replacement=manifest,
            authority_id=manifest.publisher_id,
            authority_identity_sha256=publisher_identity_sha256,
            created_at=now,
        )

    def _load_bound_report(self, request: ReleaseRequest) -> FinalReportBundle:
        bundle = self.report_store.load(request.source_report_id)
        checks = (
            bundle.manifest.manifest_id == request.source_manifest_id,
            bundle.report.fingerprint() == request.source_report_sha256,
            bundle.manifest.fingerprint() == request.source_manifest_sha256,
            bundle.report.finding.finding_id == request.source_finding_id,
        )
        if not all(checks):
            raise PublicationServiceError("release request failed source integrity binding")
        return bundle

    def _copy_artifacts(
        self,
        bundle: FinalReportBundle,
        request: ReleaseRequest,
        staging: Path,
    ) -> tuple[PublishedArtifactReference, ...]:
        source = {item.format: item for item in bundle.manifest.artifacts}
        published: list[PublishedArtifactReference] = []
        for format in request.formats:
            reference = source.get(format)
            if reference is None:
                raise PublicationServiceError("requested source artifact is unavailable")
            raw = self.report_store.artifact_path(request.source_report_id, format).read_bytes()
            if len(raw) != reference.size_bytes:
                raise PublicationServiceError("source artifact size verification failed")
            if hashlib.sha256(raw).hexdigest() != reference.sha256:
                raise PublicationServiceError("source artifact digest verification failed")
            self._write_new_file(staging / reference.filename, raw)
            published.append(
                PublishedArtifactReference(
                    format=format,
                    source_filename=reference.filename,
                    published_filename=reference.filename,
                    content_type=reference.content_type,
                    sha256=reference.sha256,
                    size_bytes=reference.size_bytes,
                )
            )
        return tuple(published)

    def _write_notice(self, publication_id: str, filename: str, raw: bytes) -> Path:
        publication = self.publication_store.load_publication(publication_id)
        config = self._destination_config(publication.destination.destination_id)
        if config.policy() != publication.destination:
            raise PublicationServiceError("publication destination configuration changed")
        directory = config.resolved_root() / publication.publication_id
        if not directory.is_dir() or directory.is_symlink():
            raise PublicationServiceError("published artifact directory is unavailable")
        path = directory / filename
        self._write_new_file(path, raw)
        return path

    @staticmethod
    def _write_new_file(path: Path, raw: bytes) -> None:
        try:
            descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError as exc:
            raise PublicationServiceError("publication artifact already exists") from exc
        except OSError as exc:
            raise PublicationServiceError("publication artifact could not be created") from exc
        try:
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(raw)
                handle.flush()
                os.fsync(handle.fileno())
        except Exception:
            path.unlink(missing_ok=True)
            raise

    def _destination_config(self, destination_id: str) -> PublicationDestinationConfig:
        normalized = destination_id.strip().casefold()
        for config in self.destinations:
            if config.destination_id == normalized:
                return config
        raise PublicationServiceError("publication destination is not configured")

    @staticmethod
    def _formats(values: Iterable[str | FinalReportFormat]) -> tuple[FinalReportFormat, ...]:
        formats: list[FinalReportFormat] = []
        try:
            for value in values:
                normalized = FinalReportFormat(value)
                if normalized not in formats:
                    formats.append(normalized)
        except ValueError as exc:
            raise PublicationServiceError("unsupported publication format") from exc
        if not formats:
            raise PublicationServiceError("publication requires at least one artifact")
        return tuple(formats)

    @staticmethod
    def _reason(value: str) -> str:
        normalized = " ".join(redact_text(value).split())[:1_000]
        if len(normalized) < 5:
            raise PublicationServiceError("publication reason is too short")
        return normalized

    def _authenticate(self, actor_id: str, secret: str):
        normalized = actor_id.strip().casefold()
        try:
            identity = authenticate_identity(
                self.governance_store,
                normalized,
                secret,
                required_role="campaign_admin",
            )
        except (GovernanceAuthenticationError, GovernancePolicyError, GovernanceError) as exc:
            raise PublicationServiceError(str(exc)) from exc
        if identity.reviewer_id not in self.release_authority_ids:
            raise PublicationServiceError("identity is not a configured publication authority")
        return identity

    @staticmethod
    def _reject_report_actor(
        actor_id: str,
        bundle: FinalReportBundle,
        action: str,
    ) -> None:
        report = bundle.report
        actors = {
            report.generated_by,
            report.remediation.owner_id,
            report.verification.builder_id,
            report.verification.verifier_id,
            report.retest.operator_id,
            report.review.reviewer_id,
        }
        if actor_id in actors:
            raise PublicationServiceError(f"a prior remediation/report actor cannot {action}")

    def _now(self) -> datetime:
        return self.clock().astimezone(UTC)


__all__ = [
    "PublicationDestinationConfig",
    "PublicationService",
    "PublicationServiceError",
]
