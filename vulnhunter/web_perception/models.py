"""Immutable contracts for passive browser perception and surface graphs."""

from __future__ import annotations

import ipaddress
import re
from datetime import UTC, datetime
from enum import StrEnum
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from vulnhunter.actions.models import sha256_json

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_IMAGE_DIGEST = re.compile(r"^.+@sha256:[0-9a-f]{64}$")
_KEY_ID = re.compile(r"^sha256:[0-9a-f]{64}$")
_SOURCE_COMMIT = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
_IDENTIFIER = re.compile(r"^[a-z0-9][a-z0-9._-]{1,127}$")
_GITHUB_WORKFLOW_SIGNER = re.compile(
    r"^github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/\.github/workflows/"
    r"[A-Za-z0-9_.-]+\.ya?ml$"
)


def utc_now() -> datetime:
    return datetime.now(UTC)


class BrowserPerceptionPolicy(BaseModel):
    """Bounded passive browser behavior for one authorized perception run."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    maximum_pages: int = Field(default=10, ge=1, le=100)
    maximum_depth: int = Field(default=2, ge=0, le=5)
    maximum_requests: int = Field(default=100, ge=1, le=2_000)
    maximum_links_per_page: int = Field(default=100, ge=1, le=500)
    navigation_timeout_ms: int = Field(default=10_000, ge=1_000, le=60_000)
    settle_time_ms: int = Field(default=250, ge=0, le=5_000)
    minimum_request_delay_seconds: float = Field(default=0.2, ge=0, le=10)


class PerceivedFormField(BaseModel):
    """Structure-only form input metadata. Values are intentionally impossible."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    name: str = Field(default="", max_length=200)
    input_type: str = Field(default="", max_length=80)
    required: bool = False


class PerceivedForm(BaseModel):
    """A form declaration observed without submitting it."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    form_sha256: str
    method: str = Field(max_length=16)
    action_url: str = Field(max_length=2_048)
    fields: tuple[PerceivedFormField, ...] = Field(default=(), max_length=200)

    @field_validator("form_sha256")
    @classmethod
    def validate_sha256(cls, value: str) -> str:
        if _SHA256.fullmatch(value) is None:
            raise ValueError("form_sha256 must be a SHA-256 digest")
        return value

    @field_validator("method")
    @classmethod
    def validate_method(cls, value: str) -> str:
        normalized = value.strip().upper()
        if normalized not in {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}:
            raise ValueError("form method is unsupported")
        return normalized


class PerceivedNetworkRequest(BaseModel):
    """Sanitized metadata for a read-only request allowed to reach the target."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    method: str = Field(max_length=8)
    url: str = Field(max_length=2_048)
    resource_type: str = Field(default="", max_length=80)
    status_code: int | None = Field(default=None, ge=100, le=599)

    @field_validator("method")
    @classmethod
    def validate_method(cls, value: str) -> str:
        normalized = value.strip().upper()
        if normalized not in {"GET", "HEAD"}:
            raise ValueError("perception evidence may contain only read-only network requests")
        return normalized


class PerceivedPage(BaseModel):
    """Structure-only browser observation for one in-scope page."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    url: str = Field(max_length=2_048)
    depth: int = Field(ge=0, le=10)
    status_code: int | None = Field(default=None, ge=100, le=599)
    dom_structure_sha256: str
    links: tuple[str, ...] = Field(default=(), max_length=500)
    scripts: tuple[str, ...] = Field(default=(), max_length=500)
    forms: tuple[PerceivedForm, ...] = Field(default=(), max_length=200)
    requests: tuple[PerceivedNetworkRequest, ...] = Field(default=(), max_length=2_000)

    @field_validator("dom_structure_sha256")
    @classmethod
    def validate_sha256(cls, value: str) -> str:
        if _SHA256.fullmatch(value) is None:
            raise ValueError("dom_structure_sha256 must be a SHA-256 digest")
        return value


class BrowserPerceptionEvidence(BaseModel):
    """Bounded output emitted by the untrusted browser worker."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    schema_version: int = 1
    pages: tuple[PerceivedPage, ...]
    allowed_requests: int = Field(ge=0)
    blocked_external_requests: int = Field(ge=0)
    blocked_mutating_requests: int = Field(ge=0)
    blocked_websockets: int = Field(ge=0)
    budget_exhausted: bool = False
    content_trust: str = "untrusted_target_content"

    @model_validator(mode="after")
    def validate_contract(self):
        if self.schema_version != 1:
            raise ValueError("browser perception evidence schema is unsupported")
        if self.content_trust != "untrusted_target_content":
            raise ValueError("target-derived content must remain explicitly untrusted")
        return self


class SurfaceNodeKind(StrEnum):
    PAGE = "page"
    ENDPOINT = "endpoint"
    FORM = "form"
    SCRIPT = "script"


class SurfaceEdgeKind(StrEnum):
    LINKS_TO = "links_to"
    REQUESTS = "requests"
    SUBMITS_TO = "submits_to"
    LOADS_SCRIPT = "loads_script"


class SurfaceNode(BaseModel):
    """One deterministic sanitized application-surface entity."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    node_id: str
    kind: SurfaceNodeKind
    url: str = Field(max_length=2_048)
    method: str | None = Field(default=None, max_length=16)
    detail_sha256: str | None = None

    @field_validator("node_id", "detail_sha256")
    @classmethod
    def validate_optional_sha256(cls, value: str | None) -> str | None:
        if value is not None and _SHA256.fullmatch(value) is None:
            raise ValueError("surface node hashes must be SHA-256 digests")
        return value


class SurfaceEdge(BaseModel):
    """One deterministic relationship in the application surface graph."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    edge_id: str
    kind: SurfaceEdgeKind
    source_node_id: str
    target_node_id: str

    @field_validator("edge_id", "source_node_id", "target_node_id")
    @classmethod
    def validate_sha256(cls, value: str) -> str:
        if _SHA256.fullmatch(value) is None:
            raise ValueError("surface edge identifiers must be SHA-256 digests")
        return value


class ApplicationSurfaceGraph(BaseModel):
    """Canonical structure-only graph derived from passive browser evidence."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    schema_version: int = 1
    target_url: str = Field(max_length=2_048)
    nodes: tuple[SurfaceNode, ...]
    edges: tuple[SurfaceEdge, ...]
    graph_sha256: str

    @model_validator(mode="after")
    def validate_graph(self):
        if self.schema_version != 1:
            raise ValueError("surface graph schema is unsupported")
        if _SHA256.fullmatch(self.graph_sha256) is None:
            raise ValueError("graph_sha256 must be a SHA-256 digest")
        node_ids = {node.node_id for node in self.nodes}
        if len(node_ids) != len(self.nodes):
            raise ValueError("surface graph node IDs must be unique")
        edge_ids = {edge.edge_id for edge in self.edges}
        if len(edge_ids) != len(self.edges):
            raise ValueError("surface graph edge IDs must be unique")
        for edge in self.edges:
            if edge.source_node_id not in node_ids or edge.target_node_id not in node_ids:
                raise ValueError("surface graph edges must reference existing nodes")
        expected = sha256_json(
            {
                "schema_version": self.schema_version,
                "target_url": self.target_url,
                "nodes": [node.model_dump(mode="json") for node in self.nodes],
                "edges": [edge.model_dump(mode="json") for edge in self.edges],
            }
        )
        if self.graph_sha256 != expected:
            raise ValueError("surface graph integrity hash does not match its contents")
        return self


class WebPerceptionPlan(BaseModel):
    """Immutable authorization, target, worker, and budget identity."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    request_id: str
    authorization_id: str = Field(min_length=8, max_length=80)
    target_url: str = Field(max_length=2_048)
    scheme: str
    hostname: str = Field(min_length=1, max_length=253)
    port: int = Field(ge=1, le=65_535)
    path_boundary: str = Field(min_length=1, max_length=2_048)
    approved_addresses: tuple[str, ...] = Field(min_length=1, max_length=32)
    approved_ip: str
    policy: BrowserPerceptionPolicy
    runtime_image: str
    runtime_release_id: str
    runtime_sbom_sha256: str
    runtime_provenance_sha256: str
    runtime_source_commit: str
    runtime_release_registry_sha256: str
    runtime_release_key_id: str
    runtime_github_provenance_attestation_sha256: str | None = None
    runtime_github_sbom_attestation_sha256: str | None = None
    runtime_github_attestation_signer: str | None = None

    @model_validator(mode="after")
    def validate_plan(self):
        if self.scheme not in {"http", "https"}:
            raise ValueError("web perception supports http and https only")
        if _IDENTIFIER.fullmatch(self.request_id) is None:
            raise ValueError("request_id must be a stable lowercase identifier")
        if _IMAGE_DIGEST.fullmatch(self.runtime_image) is None:
            raise ValueError("runtime_image must be pinned by SHA-256")
        if _IDENTIFIER.fullmatch(self.runtime_release_id) is None:
            raise ValueError("runtime_release_id is invalid")
        for value, label in (
            (self.runtime_sbom_sha256, "runtime_sbom_sha256"),
            (self.runtime_provenance_sha256, "runtime_provenance_sha256"),
            (self.runtime_release_registry_sha256, "runtime_release_registry_sha256"),
        ):
            if _SHA256.fullmatch(value) is None:
                raise ValueError(f"{label} must be a SHA-256 digest")
        if _SOURCE_COMMIT.fullmatch(self.runtime_source_commit) is None:
            raise ValueError("runtime_source_commit must be a Git commit digest")
        if _KEY_ID.fullmatch(self.runtime_release_key_id) is None:
            raise ValueError("runtime_release_key_id must be a SHA-256 key identifier")

        try:
            approved = tuple(str(ipaddress.ip_address(value)) for value in self.approved_addresses)
            selected = str(ipaddress.ip_address(self.approved_ip))
        except ValueError as exc:
            raise ValueError(
                "web perception approved addresses must be valid IP addresses"
            ) from exc
        if selected not in approved:
            raise ValueError("approved_ip must belong to the immutable approved address set")
        if ipaddress.ip_address(selected).version != 4:
            raise ValueError("first web perception worker supports IPv4 only")

        parsed = urlsplit(self.target_url)
        effective_port = parsed.port or (443 if parsed.scheme == "https" else 80)
        if (
            parsed.scheme != self.scheme
            or parsed.hostname is None
            or parsed.hostname.rstrip(".").casefold() != self.hostname
            or effective_port != self.port
        ):
            raise ValueError("target URL does not match the bound origin")

        attestations = (
            self.runtime_github_provenance_attestation_sha256,
            self.runtime_github_sbom_attestation_sha256,
            self.runtime_github_attestation_signer,
        )
        if any(value is not None for value in attestations):
            if any(value is None for value in attestations):
                raise ValueError("GitHub attestation identity must be complete")
            if _SHA256.fullmatch(self.runtime_github_provenance_attestation_sha256 or "") is None:
                raise ValueError("GitHub provenance attestation hash is invalid")
            if _SHA256.fullmatch(self.runtime_github_sbom_attestation_sha256 or "") is None:
                raise ValueError("GitHub SBOM attestation hash is invalid")
            if (
                _GITHUB_WORKFLOW_SIGNER.fullmatch(self.runtime_github_attestation_signer or "")
                is None
            ):
                raise ValueError("GitHub attestation signer is invalid")
        return self

    def fingerprint(self) -> str:
        return sha256_json(self.model_dump(mode="json"))


class WebPerceptionResult(BaseModel):
    """Trusted host-side result after validation, redaction, hashing, and graphing."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    target_url: str
    started_at: datetime
    completed_at: datetime
    plan_sha256: str
    evidence_sha256: str
    runtime_image: str
    runtime_release_id: str
    runtime_release_key_id: str
    evidence: BrowserPerceptionEvidence
    graph: ApplicationSurfaceGraph

    @field_validator("started_at", "completed_at")
    @classmethod
    def normalize_time(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("web perception timestamps must include a timezone")
        return value.astimezone(UTC)

    @field_validator("plan_sha256", "evidence_sha256")
    @classmethod
    def validate_sha256(cls, value: str) -> str:
        if _SHA256.fullmatch(value) is None:
            raise ValueError("web perception hashes must be SHA-256 digests")
        return value
