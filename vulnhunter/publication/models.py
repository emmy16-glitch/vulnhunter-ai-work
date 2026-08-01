"""Immutable contracts for separately authorised final-report publication."""

from __future__ import annotations

import re
from datetime import UTC, datetime
from typing import Literal, Self

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from vulnhunter.actions.models import sha256_json
from vulnhunter.reports.final_remediation import FinalReportFormat

_IDENTIFIER = re.compile(r"^[a-z0-9][a-z0-9._-]{1,127}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


def _identifier(value: str, field_name: str) -> str:
    if _IDENTIFIER.fullmatch(value) is None:
        raise ValueError(f"{field_name} must be a stable lowercase identifier")
    return value


def _digest(value: str, field_name: str) -> str:
    if _SHA256.fullmatch(value) is None:
        raise ValueError(f"{field_name} must be a SHA-256 digest")
    return value


def _aware(value: datetime, field_name: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{field_name} must be timezone-aware")
    return value


class _FingerprintModel(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    def fingerprint(self) -> str:
        return sha256_json(self.model_dump(mode="json"))


class PublicationDestination(_FingerprintModel):
    """Digest-bound destination policy; raw filesystem paths are not persisted."""

    destination_id: str
    label: str = Field(min_length=3, max_length=200)
    kind: Literal["local_directory"] = "local_directory"
    root_sha256: str
    allowed_formats: tuple[FinalReportFormat, ...] = Field(min_length=1, max_length=3)

    @field_validator("destination_id")
    @classmethod
    def validate_destination_id(cls, value: str) -> str:
        return _identifier(value, "publication destination ID")

    @field_validator("root_sha256")
    @classmethod
    def validate_root_sha256(cls, value: str) -> str:
        return _digest(value, "publication destination root")

    @field_validator("allowed_formats")
    @classmethod
    def validate_formats(
        cls, values: tuple[FinalReportFormat, ...]
    ) -> tuple[FinalReportFormat, ...]:
        if len(set(values)) != len(values):
            raise ValueError("publication destination formats must be unique")
        return values


class ReleaseRequest(_FingerprintModel):
    """One expiring request to release exact artifacts to one exact destination."""

    schema_version: str = "1.0"
    request_id: str
    source_report_id: str
    source_manifest_id: str
    source_report_sha256: str
    source_manifest_sha256: str
    source_finding_id: str
    destination: PublicationDestination
    formats: tuple[FinalReportFormat, ...] = Field(min_length=1, max_length=3)
    requester_id: str
    requester_identity_sha256: str
    reason: str = Field(min_length=5, max_length=1_000)
    correction_of_publication_id: str | None = None
    created_at: datetime
    expires_at: datetime
    release_state: Literal["requested"] = "requested"

    @field_validator(
        "request_id",
        "source_report_id",
        "source_manifest_id",
        "source_finding_id",
        "requester_id",
    )
    @classmethod
    def validate_identifiers(cls, value: str) -> str:
        return _identifier(value, "release request identifier")

    @field_validator("correction_of_publication_id")
    @classmethod
    def validate_correction_id(cls, value: str | None) -> str | None:
        return None if value is None else _identifier(value, "corrected publication ID")

    @field_validator(
        "source_report_sha256",
        "source_manifest_sha256",
        "requester_identity_sha256",
    )
    @classmethod
    def validate_digests(cls, value: str) -> str:
        return _digest(value, "release request digest")

    @model_validator(mode="after")
    def validate_request(self) -> Self:
        _aware(self.created_at, "release request creation time")
        _aware(self.expires_at, "release request expiry")
        if self.expires_at <= self.created_at:
            raise ValueError("release request expiry must follow creation")
        if len(set(self.formats)) != len(self.formats):
            raise ValueError("release request formats must be unique")
        if not set(self.formats).issubset(set(self.destination.allowed_formats)):
            raise ValueError("release request contains a destination-disallowed format")
        return self

    @classmethod
    def create(cls, **values) -> ReleaseRequest:
        canonical = {
            **values,
            "destination": values["destination"].model_dump(mode="json"),
            "formats": [item.value for item in values["formats"]],
            "created_at": values["created_at"].astimezone(UTC).isoformat(),
            "expires_at": values["expires_at"].astimezone(UTC).isoformat(),
            "release_state": "requested",
        }
        digest = sha256_json(canonical)
        return cls(request_id=f"release-request-{digest[:24]}", **values)


class ReleaseApproval(_FingerprintModel):
    """Independent approval of one exact unexpired release request."""

    schema_version: str = "1.0"
    approval_id: str
    request_id: str
    request_sha256: str
    approver_id: str
    approver_identity_sha256: str
    approved_at: datetime
    expires_at: datetime
    release_state: Literal["approved"] = "approved"

    @field_validator("approval_id", "request_id", "approver_id")
    @classmethod
    def validate_identifiers(cls, value: str) -> str:
        return _identifier(value, "release approval identifier")

    @field_validator("request_sha256", "approver_identity_sha256")
    @classmethod
    def validate_digests(cls, value: str) -> str:
        return _digest(value, "release approval digest")

    @model_validator(mode="after")
    def validate_approval(self) -> Self:
        _aware(self.approved_at, "release approval time")
        _aware(self.expires_at, "release approval expiry")
        if self.expires_at <= self.approved_at:
            raise ValueError("release approval must expire after approval")
        return self

    @classmethod
    def create(
        cls,
        *,
        request: ReleaseRequest,
        approver_id: str,
        approver_identity_sha256: str,
        approved_at: datetime,
    ) -> ReleaseApproval:
        values = {
            "request_id": request.request_id,
            "request_sha256": request.fingerprint(),
            "approver_id": approver_id,
            "approver_identity_sha256": approver_identity_sha256,
            "approved_at": approved_at,
            "expires_at": request.expires_at,
        }
        canonical = {
            **values,
            "approved_at": approved_at.astimezone(UTC).isoformat(),
            "expires_at": request.expires_at.astimezone(UTC).isoformat(),
            "release_state": "approved",
        }
        digest = sha256_json(canonical)
        return cls(approval_id=f"release-approval-{digest[:24]}", **values)


class PublishedArtifactReference(_FingerprintModel):
    format: FinalReportFormat
    source_filename: str = Field(min_length=3, max_length=220)
    published_filename: str = Field(min_length=3, max_length=220)
    content_type: str = Field(min_length=3, max_length=200)
    sha256: str
    size_bytes: int = Field(ge=1)

    @field_validator("sha256")
    @classmethod
    def validate_sha256(cls, value: str) -> str:
        return _digest(value, "published artifact")


class PublicationManifest(_FingerprintModel):
    """Signed final manifest for one completed, separately authorised publication."""

    schema_version: str = "1.0"
    publication_id: str
    request_id: str
    request_sha256: str
    approval_id: str
    approval_sha256: str
    source_report_id: str
    source_manifest_id: str
    source_report_sha256: str
    source_manifest_sha256: str
    source_finding_id: str
    destination: PublicationDestination
    artifacts: tuple[PublishedArtifactReference, ...] = Field(min_length=1, max_length=3)
    requester_id: str
    approver_id: str
    publisher_id: str
    publisher_identity_sha256: str
    correction_of_publication_id: str | None = None
    published_at: datetime
    release_state: Literal["published"] = "published"

    @field_validator(
        "publication_id",
        "request_id",
        "approval_id",
        "source_report_id",
        "source_manifest_id",
        "source_finding_id",
        "requester_id",
        "approver_id",
        "publisher_id",
    )
    @classmethod
    def validate_identifiers(cls, value: str) -> str:
        return _identifier(value, "publication identifier")

    @field_validator("correction_of_publication_id")
    @classmethod
    def validate_correction_id(cls, value: str | None) -> str | None:
        return None if value is None else _identifier(value, "corrected publication ID")

    @field_validator(
        "request_sha256",
        "approval_sha256",
        "source_report_sha256",
        "source_manifest_sha256",
        "publisher_identity_sha256",
    )
    @classmethod
    def validate_digests(cls, value: str) -> str:
        return _digest(value, "publication digest")

    @model_validator(mode="after")
    def validate_manifest(self) -> Self:
        _aware(self.published_at, "publication time")
        formats = tuple(item.format for item in self.artifacts)
        if len(set(formats)) != len(formats):
            raise ValueError("published artifact formats must be unique")
        if not set(formats).issubset(set(self.destination.allowed_formats)):
            raise ValueError("published artifact violates destination format policy")
        if len({self.requester_id, self.approver_id, self.publisher_id}) != 3:
            raise ValueError("release requester, approver, and publisher must be distinct")
        return self

    @classmethod
    def create(
        cls,
        *,
        request: ReleaseRequest,
        approval: ReleaseApproval,
        artifacts: tuple[PublishedArtifactReference, ...],
        publisher_id: str,
        publisher_identity_sha256: str,
        published_at: datetime,
    ) -> PublicationManifest:
        values = {
            "request_id": request.request_id,
            "request_sha256": request.fingerprint(),
            "approval_id": approval.approval_id,
            "approval_sha256": approval.fingerprint(),
            "source_report_id": request.source_report_id,
            "source_manifest_id": request.source_manifest_id,
            "source_report_sha256": request.source_report_sha256,
            "source_manifest_sha256": request.source_manifest_sha256,
            "source_finding_id": request.source_finding_id,
            "destination": request.destination,
            "artifacts": artifacts,
            "requester_id": request.requester_id,
            "approver_id": approval.approver_id,
            "publisher_id": publisher_id,
            "publisher_identity_sha256": publisher_identity_sha256,
            "correction_of_publication_id": request.correction_of_publication_id,
            "published_at": published_at,
        }
        canonical = {
            **values,
            "destination": request.destination.model_dump(mode="json"),
            "artifacts": [item.model_dump(mode="json") for item in artifacts],
            "published_at": published_at.astimezone(UTC).isoformat(),
            "release_state": "published",
        }
        digest = sha256_json(canonical)
        return cls(publication_id=f"publication-{digest[:24]}", **values)


class PublicationCorrection(_FingerprintModel):
    """Append-only link that supersedes one publication with an approved replacement."""

    schema_version: str = "1.0"
    correction_id: str
    superseded_publication_id: str
    replacement_publication_id: str
    replacement_publication_sha256: str
    authority_id: str
    authority_identity_sha256: str
    created_at: datetime
    release_state: Literal["superseded"] = "superseded"

    @field_validator(
        "correction_id",
        "superseded_publication_id",
        "replacement_publication_id",
        "authority_id",
    )
    @classmethod
    def validate_identifiers(cls, value: str) -> str:
        return _identifier(value, "publication correction identifier")

    @field_validator("replacement_publication_sha256", "authority_identity_sha256")
    @classmethod
    def validate_digests(cls, value: str) -> str:
        return _digest(value, "publication correction digest")

    @model_validator(mode="after")
    def validate_correction(self) -> Self:
        _aware(self.created_at, "publication correction time")
        if self.superseded_publication_id == self.replacement_publication_id:
            raise ValueError("a publication cannot correct itself")
        return self

    @classmethod
    def create(
        cls,
        *,
        superseded_publication_id: str,
        replacement: PublicationManifest,
        authority_id: str,
        authority_identity_sha256: str,
        created_at: datetime,
    ) -> PublicationCorrection:
        values = {
            "superseded_publication_id": superseded_publication_id,
            "replacement_publication_id": replacement.publication_id,
            "replacement_publication_sha256": replacement.fingerprint(),
            "authority_id": authority_id,
            "authority_identity_sha256": authority_identity_sha256,
            "created_at": created_at,
        }
        canonical = {
            **values,
            "created_at": created_at.astimezone(UTC).isoformat(),
            "release_state": "superseded",
        }
        digest = sha256_json(canonical)
        return cls(correction_id=f"publication-correction-{digest[:24]}", **values)


class PublicationRevocation(_FingerprintModel):
    """Non-destructive, signed revocation notice for one exact publication."""

    schema_version: str = "1.0"
    revocation_id: str
    publication_id: str
    publication_sha256: str
    authority_id: str
    authority_identity_sha256: str
    reason: str = Field(min_length=5, max_length=1_000)
    revoked_at: datetime
    release_state: Literal["revoked"] = "revoked"

    @field_validator("revocation_id", "publication_id", "authority_id")
    @classmethod
    def validate_identifiers(cls, value: str) -> str:
        return _identifier(value, "publication revocation identifier")

    @field_validator("publication_sha256", "authority_identity_sha256")
    @classmethod
    def validate_digests(cls, value: str) -> str:
        return _digest(value, "publication revocation digest")

    @field_validator("revoked_at")
    @classmethod
    def validate_revoked_at(cls, value: datetime) -> datetime:
        return _aware(value, "publication revocation time")

    @classmethod
    def create(
        cls,
        *,
        publication: PublicationManifest,
        authority_id: str,
        authority_identity_sha256: str,
        reason: str,
        revoked_at: datetime,
    ) -> PublicationRevocation:
        values = {
            "publication_id": publication.publication_id,
            "publication_sha256": publication.fingerprint(),
            "authority_id": authority_id,
            "authority_identity_sha256": authority_identity_sha256,
            "reason": reason,
            "revoked_at": revoked_at,
        }
        canonical = {
            **values,
            "revoked_at": revoked_at.astimezone(UTC).isoformat(),
            "release_state": "revoked",
        }
        digest = sha256_json(canonical)
        return cls(revocation_id=f"publication-revocation-{digest[:24]}", **values)


__all__ = [
    "PublicationCorrection",
    "PublicationDestination",
    "PublicationManifest",
    "PublicationRevocation",
    "PublishedArtifactReference",
    "ReleaseApproval",
    "ReleaseRequest",
]
