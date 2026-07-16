"""Fail-closed activation controls for a future governed Nuclei pilot.

This module validates immutable records and plans only.  It deliberately has no
subprocess launcher and no default DNS resolver, so using it cannot start a scan
or create an implicit network operation.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
import stat
import threading
import time
from collections.abc import Callable, Iterable, Mapping
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path, PurePosixPath
from typing import Literal, Protocol, Self
from urllib.parse import urlsplit, urlunsplit

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from vulnhunter.actions.models import sha256_json
from vulnhunter.scope.validator import normalize_hostname, normalize_path
from vulnhunter.security import is_sensitive_key, redact_text
from vulnhunter.security.sensitive_patterns import REDACTED

_IDENTIFIER = re.compile(r"^[a-z0-9][a-z0-9._-]{1,127}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_PROFILE = Literal["passive", "standard", "intrusive", "retest"]
_PROTOCOL = Literal["http", "https"]
_REQUIRED_PROHIBITIONS = frozenset(
    {
        "automatic-updates",
        "cloud-upload",
        "public-oast",
        "raw-command-arguments",
    }
)
_METADATA_HOSTS = frozenset(
    {
        "instance-data",
        "metadata.azure.internal",
        "metadata.google.internal",
    }
)
_METADATA_ADDRESSES = frozenset(
    {
        ipaddress.ip_address("169.254.169.254"),
        ipaddress.ip_address("169.254.170.2"),
        ipaddress.ip_address("fd00:ec2::254"),
    }
)
_URL_CREDENTIALS = re.compile(r"\bhttps?://[^\s/@:]+:[^\s/@]+@", re.IGNORECASE)
_MAX_TEMPLATE_BYTES = 2_000_000

AddressResolver = Callable[[str], Iterable[str]]


class NucleiActivationError(ValueError):
    """Raised when a future Nuclei activation gate fails closed."""


class NucleiCancellationError(RuntimeError):
    """Raised when a planned operation has been cancelled."""


class NucleiTimeoutError(RuntimeError):
    """Raised when a planned operation exceeds its monotonic deadline."""


def _utc(value: datetime, *, field: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{field} must be timezone-aware")
    return value.astimezone(UTC)


def _validate_identifier(value: str) -> str:
    normalized = value.strip().lower()
    if _IDENTIFIER.fullmatch(normalized) is None:
        raise ValueError("identifier must be a stable lowercase value")
    return normalized


def _normalize_target_reference(value: str) -> str:
    try:
        parsed = urlsplit(value.strip())
    except ValueError as exc:
        raise ValueError("approved target is malformed") from exc
    scheme = parsed.scheme.lower()
    if scheme not in {"http", "https"}:
        raise ValueError("approved targets require an exact http or https URL")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("approved targets must not contain credentials")
    if not parsed.hostname or parsed.query or parsed.fragment:
        raise ValueError("approved targets require a host and no query or fragment")
    hostname = normalize_hostname(parsed.hostname)
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError("approved target contains an invalid port") from exc
    effective_port = port or (443 if scheme == "https" else 80)
    path = normalize_path(parsed.path)
    display_host = f"[{hostname}]" if ":" in hostname else hostname
    return urlunsplit((scheme, f"{display_host}:{effective_port}", path, "", ""))


def _normalize_address(value: str) -> str:
    try:
        return str(ipaddress.ip_address(value.strip()))
    except ValueError as exc:
        raise ValueError("approved address is not a valid IP address") from exc


class EngagementAudit(BaseModel):
    """Identity-bound, hash-linked audit information for an authorization."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    recorded_at: datetime
    recorded_by: str
    approval_basis: str = Field(min_length=8, max_length=500)
    previous_record_sha256: str | None = None
    record_sha256: str

    @field_validator("recorded_at")
    @classmethod
    def validate_recorded_at(cls, value: datetime) -> datetime:
        return _utc(value, field="recorded_at")

    @field_validator("recorded_by")
    @classmethod
    def validate_recorded_by(cls, value: str) -> str:
        return _validate_identifier(value)

    @field_validator("previous_record_sha256", "record_sha256")
    @classmethod
    def validate_digest(cls, value: str | None) -> str | None:
        if value is not None and _SHA256.fullmatch(value) is None:
            raise ValueError("audit digests must be SHA-256 values")
        return value


class EngagementAuthorization(BaseModel):
    """Immutable, time-limited authorization for exact Nuclei targets."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    authorization_id: str
    target_owner: str = Field(min_length=2, max_length=200)
    approving_person: str = Field(min_length=2, max_length=200)
    approved_targets: tuple[str, ...] = Field(min_length=1)
    approved_addresses: tuple[str, ...] = Field(min_length=1)
    approved_ports: tuple[int, ...] = Field(min_length=1)
    approved_protocols: tuple[_PROTOCOL, ...] = Field(min_length=1)
    approved_scan_profiles: tuple[_PROFILE, ...] = Field(min_length=1)
    starts_at: datetime
    expires_at: datetime
    private_network_approved: bool = False
    prohibited_actions: tuple[str, ...] = Field(min_length=4)
    audit: EngagementAudit

    @field_validator("authorization_id")
    @classmethod
    def validate_authorization_id(cls, value: str) -> str:
        return _validate_identifier(value)

    @field_validator("approved_targets")
    @classmethod
    def validate_targets(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        normalized = tuple(sorted({_normalize_target_reference(value) for value in values}))
        if not normalized:
            raise ValueError("at least one approved target is required")
        return normalized

    @field_validator("approved_addresses")
    @classmethod
    def validate_addresses(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        normalized = tuple(sorted({_normalize_address(value) for value in values}))
        if not normalized:
            raise ValueError("at least one approved address is required")
        return normalized

    @field_validator("approved_ports")
    @classmethod
    def validate_ports(cls, values: tuple[int, ...]) -> tuple[int, ...]:
        if any(isinstance(value, bool) or value < 1 or value > 65535 for value in values):
            raise ValueError("approved ports must be between 1 and 65535")
        return tuple(sorted(set(values)))

    @field_validator("approved_protocols", "approved_scan_profiles")
    @classmethod
    def validate_unique_strings(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        return tuple(sorted(set(values)))

    @field_validator("prohibited_actions")
    @classmethod
    def validate_prohibitions(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        normalized = tuple(sorted({value.strip().lower() for value in values if value.strip()}))
        missing = _REQUIRED_PROHIBITIONS - set(normalized)
        if missing:
            raise ValueError("authorization omits mandatory prohibited actions")
        return normalized

    @field_validator("starts_at", "expires_at")
    @classmethod
    def validate_times(cls, value: datetime, info) -> datetime:
        return _utc(value, field=info.field_name)

    @model_validator(mode="after")
    def validate_authorization(self) -> Self:
        if self.expires_at <= self.starts_at:
            raise ValueError("authorization expiry must be later than its start")
        target_schemes: set[str] = set()
        target_ports: set[int] = set()
        for target in self.approved_targets:
            parsed = urlsplit(target)
            target_schemes.add(parsed.scheme)
            target_ports.add(parsed.port or (443 if parsed.scheme == "https" else 80))
        if not target_schemes <= set(self.approved_protocols):
            raise ValueError("approved target protocol is absent from authorization")
        if not target_ports <= set(self.approved_ports):
            raise ValueError("approved target port is absent from authorization")
        if self.audit.recorded_at > self.starts_at:
            raise ValueError("authorization cannot start before its audit record")
        expected = self._audit_digest()
        if self.audit.record_sha256 != expected:
            raise ValueError("authorization audit digest does not match the record")
        return self

    def _audit_digest(self) -> str:
        payload = self.model_dump(mode="json")
        payload["audit"].pop("record_sha256")
        return sha256_json(payload)

    @classmethod
    def issue(cls, **values: object) -> Self:
        """Create a record whose digest binds every authorization field."""
        audit_value = values.get("audit")
        if not isinstance(audit_value, Mapping):
            raise ValueError("audit information is required")
        audit = dict(audit_value)
        if "record_sha256" in audit:
            raise ValueError("record_sha256 is calculated, not caller supplied")
        provisional = {
            **values,
            "authorization_id": _validate_identifier(str(values["authorization_id"])),
            "approved_targets": tuple(
                sorted(
                    {
                        _normalize_target_reference(str(value))
                        for value in values["approved_targets"]  # type: ignore[union-attr]
                    }
                )
            ),
            "approved_addresses": tuple(
                sorted(
                    {
                        _normalize_address(str(value))
                        for value in values["approved_addresses"]  # type: ignore[union-attr]
                    }
                )
            ),
            "approved_ports": tuple(sorted(set(values["approved_ports"]))),  # type: ignore[arg-type]
            "approved_protocols": tuple(
                sorted(set(values["approved_protocols"]))  # type: ignore[arg-type]
            ),
            "approved_scan_profiles": tuple(
                sorted(set(values["approved_scan_profiles"]))  # type: ignore[arg-type]
            ),
            "starts_at": _utc(values["starts_at"], field="starts_at"),  # type: ignore[arg-type]
            "expires_at": _utc(values["expires_at"], field="expires_at"),  # type: ignore[arg-type]
            "prohibited_actions": tuple(
                sorted(
                    {
                        str(value).strip().lower()
                        for value in values["prohibited_actions"]  # type: ignore[union-attr]
                        if str(value).strip()
                    }
                )
            ),
        }
        normalized_audit = {
            **audit,
            "recorded_at": _utc(audit["recorded_at"], field="recorded_at"),
            "recorded_by": _validate_identifier(str(audit["recorded_by"])),
        }
        audit_model = EngagementAudit(
            **normalized_audit,
            record_sha256="0" * 64,
        )
        unchecked_values = {key: value for key, value in provisional.items() if key != "audit"}
        unchecked = cls.model_construct(**unchecked_values, audit=audit_model)
        payload = unchecked.model_dump(mode="json")
        payload["audit"].pop("record_sha256")
        digest = sha256_json(payload)
        provisional["audit"] = {**normalized_audit, "record_sha256": digest}
        return cls(**provisional)

    def require_active(self, *, now: datetime) -> None:
        current = _utc(now, field="now")
        if current < self.starts_at or current >= self.expires_at:
            raise NucleiActivationError("engagement authorization is not active")


class ScopedNucleiTarget(BaseModel):
    """An exact URL plus the DNS addresses validated for this decision."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    url: str
    protocol: _PROTOCOL
    hostname: str
    port: int = Field(ge=1, le=65535)
    path: str
    resolved_addresses: tuple[str, ...] = Field(min_length=1)
    address_class: Literal["public", "private"]


def _classify_address(value: str) -> tuple[str, Literal["public", "private"]]:
    try:
        address = ipaddress.ip_address(value)
    except ValueError as exc:
        raise NucleiActivationError("resolver returned an invalid address") from exc
    if address in _METADATA_ADDRESSES or address.is_link_local:
        raise NucleiActivationError("metadata and link-local addresses are prohibited")
    if address.is_loopback:
        raise NucleiActivationError("loopback addresses are prohibited for Nuclei")
    if address.is_unspecified or address.is_multicast or address.is_reserved:
        raise NucleiActivationError("non-routable or reserved addresses are prohibited")
    if address.is_private:
        return str(address), "private"
    if address.is_global:
        return str(address), "public"
    raise NucleiActivationError("address classification is ambiguous")


def validate_nuclei_target_scope(
    target: str,
    *,
    authorization: EngagementAuthorization,
    resolver: AddressResolver,
    now: datetime,
) -> ScopedNucleiTarget:
    """Validate one exact target and its current DNS result without defaults."""
    authorization.require_active(now=now)
    try:
        normalized = _normalize_target_reference(target)
    except ValueError as exc:
        raise NucleiActivationError("target is malformed or ambiguous") from exc
    if normalized not in authorization.approved_targets:
        raise NucleiActivationError("target is not exactly authorized")
    parsed = urlsplit(normalized)
    hostname = normalize_hostname(parsed.hostname or "")
    if hostname in _METADATA_HOSTS or hostname == "localhost" or hostname.endswith(".localhost"):
        raise NucleiActivationError("localhost and metadata hostnames are prohibited")
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    if parsed.scheme not in authorization.approved_protocols:
        raise NucleiActivationError("target protocol is not authorized")
    if port not in authorization.approved_ports:
        raise NucleiActivationError("target port is not authorized")
    try:
        direct = ipaddress.ip_address(hostname)
    except ValueError:
        try:
            raw_addresses = tuple(resolver(hostname))
        except (OSError, ValueError) as exc:
            raise NucleiActivationError("target resolution failed closed") from exc
    else:
        raw_addresses = (str(direct),)
    if not raw_addresses:
        raise NucleiActivationError("target resolution returned no addresses")
    classified = tuple(sorted({_classify_address(value) for value in raw_addresses}))
    classes = {kind for _, kind in classified}
    if len(classes) != 1:
        raise NucleiActivationError("mixed public and private resolution is ambiguous")
    addresses = tuple(value for value, _ in classified)
    if not set(addresses) <= set(authorization.approved_addresses):
        raise NucleiActivationError("DNS resolution escaped the approved address set")
    address_class = next(iter(classes))
    if address_class == "private" and not authorization.private_network_approved:
        raise NucleiActivationError("private target lacks explicit private-network approval")
    return ScopedNucleiTarget(
        url=normalized,
        protocol=parsed.scheme,
        hostname=hostname,
        port=port,
        path=parsed.path,
        resolved_addresses=addresses,
        address_class=address_class,
    )


def validate_nuclei_redirect_scope(
    source: ScopedNucleiTarget,
    redirect_target: str,
    *,
    authorization: EngagementAuthorization,
    resolver: AddressResolver,
    now: datetime,
) -> ScopedNucleiTarget:
    """Revalidate every redirect as a separately authorized exact target."""
    if source.url not in authorization.approved_targets:
        raise NucleiActivationError("redirect source is no longer authorized")
    return validate_nuclei_target_scope(
        redirect_target,
        authorization=authorization,
        resolver=resolver,
        now=now,
    )


class TemplateRiskClass(StrEnum):
    PASSIVE = "passive"
    STANDARD = "standard"
    INTRUSIVE = "intrusive"


class TemplateApprovalLevel(StrEnum):
    REVIEWED = "reviewed"
    EXPLICIT = "explicit"
    INTRUSIVE = "intrusive"


_APPROVAL_RANK = {
    TemplateApprovalLevel.REVIEWED: 1,
    TemplateApprovalLevel.EXPLICIT: 2,
    TemplateApprovalLevel.INTRUSIVE: 3,
}


class NucleiTemplateManifestEntry(BaseModel):
    """One reviewed, content-addressed template."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    template_id: str
    relative_path: str
    sha256: str
    template_release: str = Field(min_length=1, max_length=100)
    risk_class: TemplateRiskClass
    required_approval_level: TemplateApprovalLevel
    enabled: bool = False
    reviewed_by: str | None = None
    reviewed_at: datetime | None = None

    @field_validator("template_id")
    @classmethod
    def validate_template_id(cls, value: str) -> str:
        return _validate_identifier(value)

    @field_validator("relative_path")
    @classmethod
    def validate_relative_path(cls, value: str) -> str:
        path = PurePosixPath(value)
        if (
            path.is_absolute()
            or not path.parts
            or any(part in {"", ".", ".."} for part in path.parts)
        ):
            raise ValueError("template path must be a safe relative path")
        return path.as_posix()

    @field_validator("sha256")
    @classmethod
    def validate_sha256(cls, value: str) -> str:
        if _SHA256.fullmatch(value) is None:
            raise ValueError("template digest must be SHA-256")
        return value

    @field_validator("reviewed_at")
    @classmethod
    def validate_reviewed_at(cls, value: datetime | None) -> datetime | None:
        return None if value is None else _utc(value, field="reviewed_at")

    @model_validator(mode="after")
    def validate_risk_approval(self) -> Self:
        if (
            self.risk_class == TemplateRiskClass.INTRUSIVE
            and self.required_approval_level != TemplateApprovalLevel.INTRUSIVE
        ):
            raise ValueError("intrusive templates require intrusive approval")
        return self

    def fingerprint(self) -> str:
        return sha256_json(self.model_dump(mode="json"))


class NucleiTemplateManifest(BaseModel):
    """Closed registry: an absent entry is denied."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    schema_version: Literal["1.0"] = "1.0"
    template_release: str = Field(min_length=1, max_length=100)
    entries: tuple[NucleiTemplateManifestEntry, ...] = ()

    @model_validator(mode="after")
    def validate_unique_entries(self) -> Self:
        ids = [entry.template_id for entry in self.entries]
        paths = [entry.relative_path for entry in self.entries]
        if len(ids) != len(set(ids)) or len(paths) != len(set(paths)):
            raise ValueError("template manifest IDs and paths must be unique")
        if any(entry.template_release != self.template_release for entry in self.entries):
            raise ValueError("template entry release differs from manifest release")
        return self

    def validate_selection(
        self,
        template_ids: Iterable[str],
        *,
        template_root: Path,
        approval_level: TemplateApprovalLevel,
    ) -> tuple[str, ...]:
        root = template_root.expanduser().resolve(strict=True)
        if not root.is_dir() or template_root.is_symlink():
            raise NucleiActivationError("template root is not an approved real directory")
        by_id = {entry.template_id: entry for entry in self.entries}
        requested = tuple(dict.fromkeys(template_ids))
        if not requested:
            raise NucleiActivationError("at least one exact template ID is required")
        hashes: list[str] = []
        for template_id in requested:
            entry = by_id.get(template_id)
            if entry is None:
                raise NucleiActivationError("template is not listed in the reviewed manifest")
            if not entry.enabled:
                raise NucleiActivationError("template is disabled")
            if entry.reviewed_by is None or entry.reviewed_at is None:
                raise NucleiActivationError("template has not been reviewed")
            if _APPROVAL_RANK[approval_level] < _APPROVAL_RANK[entry.required_approval_level]:
                raise NucleiActivationError("template approval level is insufficient")
            candidate = root.joinpath(*PurePosixPath(entry.relative_path).parts)
            current = root
            for part in PurePosixPath(entry.relative_path).parts:
                current /= part
                if current.is_symlink():
                    raise NucleiActivationError("template path must not contain symbolic links")
            try:
                resolved = candidate.resolve(strict=True)
                resolved.relative_to(root)
            except (OSError, ValueError) as exc:
                raise NucleiActivationError("template is missing or escapes its root") from exc
            if not resolved.is_file():
                raise NucleiActivationError("template is missing")
            digest = _bounded_template_digest(resolved)
            if digest != entry.sha256:
                raise NucleiActivationError("template digest does not match the manifest")
            hashes.append(entry.fingerprint())
        return tuple(sorted(hashes))


def _bounded_template_digest(path: Path) -> str:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise NucleiActivationError("template cannot be opened safely") from exc
    digest = hashlib.sha256()
    size = 0
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise NucleiActivationError("template is not a regular file")
        with os.fdopen(descriptor, "rb", closefd=False) as handle:
            while chunk := handle.read(min(65_536, _MAX_TEMPLATE_BYTES - size + 1)):
                size += len(chunk)
                if size > _MAX_TEMPLATE_BYTES:
                    raise NucleiActivationError("template exceeds the size limit")
                digest.update(chunk)
    finally:
        os.close(descriptor)
    return digest.hexdigest()


def validate_evidence_directory(path: Path, *, approved_root: Path) -> Path:
    """Require an existing non-symlink directory beneath the approved root."""
    try:
        lexical_root = approved_root.expanduser().absolute()
        lexical_candidate = path.expanduser().absolute()
        lexical_candidate.relative_to(lexical_root)
        root = lexical_root.resolve(strict=True)
        candidate = lexical_candidate.resolve(strict=True)
        candidate.relative_to(root)
    except (OSError, ValueError) as exc:
        raise NucleiActivationError("evidence directory is outside the approved root") from exc
    current = lexical_root
    for part in lexical_candidate.relative_to(lexical_root).parts:
        current /= part
        if current.is_symlink():
            raise NucleiActivationError("evidence directory must not contain symlink components")
    if lexical_root.is_symlink() or not root.is_dir() or not candidate.is_dir():
        raise NucleiActivationError("evidence directory must be a real directory")
    return candidate


def _contains_sensitive_value(value: object) -> bool:
    if isinstance(value, Mapping):
        for key, item in value.items():
            if is_sensitive_key(str(key)) and item != REDACTED:
                return True
            if _contains_sensitive_value(item):
                return True
    elif isinstance(value, (list, tuple)):
        return any(_contains_sensitive_value(item) for item in value)
    elif isinstance(value, str):
        return redact_text(value) != value or _URL_CREDENTIALS.search(value) is not None
    return False


def verify_redacted_evidence(path: Path, *, maximum_bytes: int) -> str:
    """Return an artifact digest only when bounded evidence contains no raw secret."""
    if path.is_symlink():
        raise NucleiActivationError("evidence artifact must not be a symbolic link")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise NucleiActivationError("evidence artifact cannot be opened safely") from exc
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > maximum_bytes:
            raise NucleiActivationError("evidence artifact is not a bounded regular file")
        with os.fdopen(descriptor, "rb", closefd=False) as handle:
            data = handle.read(maximum_bytes + 1)
    finally:
        os.close(descriptor)
    if len(data) > maximum_bytes:
        raise NucleiActivationError("evidence artifact exceeds its byte limit")
    text = data.decode("utf-8", errors="replace")
    if redact_text(text) != text or _URL_CREDENTIALS.search(text):
        raise NucleiActivationError("evidence artifact failed redaction verification")
    for line in text.splitlines():
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        if _contains_sensitive_value(item):
            raise NucleiActivationError("evidence artifact failed redaction verification")
    return hashlib.sha256(data).hexdigest()


class NucleiCommandPlan(BaseModel):
    """Exact immutable activation plan; intentionally contains no argv or shell text."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    authorization_id: str
    exact_targets: tuple[ScopedNucleiTarget, ...] = Field(min_length=1)
    exact_profile: _PROFILE
    template_manifest_hashes: tuple[str, ...] = Field(min_length=1)
    output_directory: Path
    rate_limit: int = Field(ge=1, le=10)
    concurrency: int = Field(ge=1, le=2)
    expires_at: datetime
    requires_isolation: bool = False
    plan_digest: str

    @field_validator("authorization_id")
    @classmethod
    def validate_authorization_id(cls, value: str) -> str:
        return _validate_identifier(value)

    @field_validator("template_manifest_hashes")
    @classmethod
    def validate_hashes(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        if any(_SHA256.fullmatch(value) is None for value in values):
            raise ValueError("template manifest hashes must be SHA-256 values")
        return tuple(sorted(set(values)))

    @field_validator("output_directory")
    @classmethod
    def validate_output_directory(cls, value: Path) -> Path:
        expanded = value.expanduser()
        if not expanded.is_absolute():
            raise ValueError("command-plan output directory must be absolute")
        return expanded

    @field_validator("expires_at")
    @classmethod
    def validate_expires_at(cls, value: datetime) -> datetime:
        return _utc(value, field="expires_at")

    @field_validator("plan_digest")
    @classmethod
    def validate_plan_digest(cls, value: str) -> str:
        if _SHA256.fullmatch(value) is None:
            raise ValueError("plan_digest must be SHA-256")
        return value

    @model_validator(mode="after")
    def validate_digest_and_profile(self) -> Self:
        if self.exact_profile == "intrusive" and not self.requires_isolation:
            raise ValueError("intrusive plans require isolation")
        target_urls = [target.url for target in self.exact_targets]
        if len(target_urls) != len(set(target_urls)):
            raise ValueError("command-plan targets must be unique")
        if self.plan_digest != self.fingerprint():
            raise ValueError("command-plan digest does not match its contents")
        return self

    def fingerprint(self) -> str:
        payload = self.model_dump(mode="json", exclude={"plan_digest"})
        return sha256_json(payload)

    @classmethod
    def create(cls, **values: object) -> Self:
        if "plan_digest" in values:
            raise ValueError("plan_digest is calculated, not caller supplied")
        provisional = cls.model_construct(**values, plan_digest="0" * 64)
        payload = provisional.model_dump(mode="json", exclude={"plan_digest"})
        return cls(**values, plan_digest=sha256_json(payload))


class NucleiPlanApproval(BaseModel):
    """Expiring human approval bound to one exact plan digest."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    approval_id: str
    authorization_id: str
    command_plan_digest: str
    approved_by: str = Field(min_length=2, max_length=200)
    approved_at: datetime
    expires_at: datetime
    intrusive_approved: bool = False
    isolated_runtime_id: str | None = None

    @field_validator("approval_id", "authorization_id")
    @classmethod
    def validate_ids(cls, value: str) -> str:
        return _validate_identifier(value)

    @field_validator("command_plan_digest")
    @classmethod
    def validate_digest(cls, value: str) -> str:
        if _SHA256.fullmatch(value) is None:
            raise ValueError("command_plan_digest must be SHA-256")
        return value

    @field_validator("isolated_runtime_id")
    @classmethod
    def validate_runtime_id(cls, value: str | None) -> str | None:
        return None if value is None else _validate_identifier(value)

    @field_validator("approved_at", "expires_at")
    @classmethod
    def validate_approval_times(cls, value: datetime, info) -> datetime:
        return _utc(value, field=info.field_name)

    @model_validator(mode="after")
    def validate_expiry(self) -> Self:
        if self.expires_at <= self.approved_at:
            raise ValueError("approval expiry must be later than approval time")
        return self


class NucleiActivationState(StrEnum):
    PLANNED = "planned"
    APPROVED_EXECUTION_DISABLED = "approved_execution_disabled"
    CANCELLED = "cancelled"
    TIMED_OUT = "timed_out"


class NucleiActivationDecision(BaseModel):
    """A successful approval decision that still cannot execute externally."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    state: Literal[NucleiActivationState.APPROVED_EXECUTION_DISABLED]
    plan_digest: str
    approval_id: str
    execution_enabled: Literal[False] = False


def validate_nuclei_plan_approval(
    plan: NucleiCommandPlan,
    approval: NucleiPlanApproval,
    *,
    authorization: EngagementAuthorization,
    resolver: AddressResolver,
    approved_output_root: Path,
    approved_template_manifest_hashes: tuple[str, ...],
    now: datetime,
    execution_enabled: Literal[False] = False,
) -> NucleiActivationDecision:
    """Validate exact approval while preserving the global execution block."""
    if execution_enabled is not False:
        raise NucleiActivationError("Nuclei execution remains globally disabled")
    current = _utc(now, field="now")
    authorization.require_active(now=current)
    if plan.authorization_id != authorization.authorization_id:
        raise NucleiActivationError("plan authorization does not match the engagement")
    if plan.exact_profile not in authorization.approved_scan_profiles:
        raise NucleiActivationError("plan profile is not authorized")
    if plan.expires_at > authorization.expires_at:
        raise NucleiActivationError("command plan outlives its authorization")
    if current >= plan.expires_at:
        raise NucleiActivationError("command plan has expired")
    revalidated_targets = tuple(
        validate_nuclei_target_scope(
            target.url,
            authorization=authorization,
            resolver=resolver,
            now=current,
        )
        for target in plan.exact_targets
    )
    if revalidated_targets != plan.exact_targets:
        raise NucleiActivationError("command-plan target scope changed before approval")
    validate_evidence_directory(
        plan.output_directory,
        approved_root=approved_output_root,
    )
    if plan.template_manifest_hashes != tuple(sorted(set(approved_template_manifest_hashes))):
        raise NucleiActivationError("command-plan templates differ from reviewed selection")
    if approval.authorization_id != authorization.authorization_id:
        raise NucleiActivationError("approval authorization does not match the engagement")
    if approval.command_plan_digest != plan.fingerprint():
        raise NucleiActivationError("approval does not match the exact command plan")
    if current < approval.approved_at or current >= approval.expires_at:
        raise NucleiActivationError("command-plan approval is not active")
    if plan.exact_profile == "intrusive":
        if not approval.intrusive_approved or not approval.isolated_runtime_id:
            raise NucleiActivationError(
                "intrusive plan requires explicit human approval and an isolated runtime"
            )
    return NucleiActivationDecision(
        state=NucleiActivationState.APPROVED_EXECUTION_DISABLED,
        plan_digest=plan.plan_digest,
        approval_id=approval.approval_id,
    )


class ProcessGroupTerminator(Protocol):
    """Future isolated runners must terminate the complete process group."""

    def terminate_process_group(self, process_group_id: int, *, grace_seconds: float) -> None: ...


class NucleiRunControl:
    """Thread-safe cancellation/deadline interface with injectable termination."""

    def __init__(
        self,
        *,
        timeout_seconds: float,
        terminator: ProcessGroupTerminator,
        monotonic: Callable[[], float] = time.monotonic,
        grace_seconds: float = 2.0,
    ) -> None:
        if timeout_seconds <= 0 or grace_seconds < 0:
            raise ValueError("timeouts must be positive and grace must not be negative")
        self._terminator = terminator
        self._monotonic = monotonic
        self._deadline = monotonic() + timeout_seconds
        self._grace_seconds = grace_seconds
        self._cancelled = threading.Event()
        self._reason = "cancelled"
        self._termination_requested = False

    def cancel(self, reason: str = "cancelled") -> None:
        self._reason = redact_text(reason)[:200]
        self._cancelled.set()

    def checkpoint(self, *, process_group_id: int | None = None) -> None:
        if self._cancelled.is_set():
            self._terminate_once(process_group_id)
            raise NucleiCancellationError(self._reason)
        if self._monotonic() >= self._deadline:
            self._terminate_once(process_group_id)
            raise NucleiTimeoutError("planned Nuclei operation timed out")

    def _terminate_once(self, process_group_id: int | None) -> None:
        if process_group_id is None or self._termination_requested:
            return
        self._terminator.terminate_process_group(
            process_group_id,
            grace_seconds=self._grace_seconds,
        )
        self._termination_requested = True
