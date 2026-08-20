from __future__ import annotations

import re
from collections.abc import Iterable, Mapping, Sequence
from enum import StrEnum
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field

from vulnhunter.actions.models import sha256_json
from vulnhunter.mobile.static_toolchain import MobileToolCapture


class MobileRecordType(StrEnum):
    OBSERVATION = "observation"
    FINDING = "finding"
    CANDIDATE = "candidate"
    OPERATIONAL_ISSUE = "operational_issue"


class MobileEvidenceState(StrEnum):
    VERIFIED_CONFIGURATION = "verified_configuration"
    VERIFIED_SECURITY_FINDING = "verified_security_finding"
    EVIDENCE_REQUIRED = "evidence_required"
    OPERATIONAL_FAILURE = "operational_failure"
    PARTIAL_TOOL_RESULT = "partial_tool_result"
    NOT_APPLICABLE = "not_applicable"
    BLOCKED = "blocked"
    REJECTED = "rejected"
    INCONCLUSIVE = "inconclusive"


class MobileOwnership(StrEnum):
    APP_OWNED = "app_owned"
    SDK_OWNED = "sdk_owned"
    PLATFORM_FRAMEWORK = "platform_framework"
    UNKNOWN = "unknown"


class MobileHypothesisState(StrEnum):
    OPEN = "open"
    EVIDENCE_REQUIRED = "evidence_required"
    REVIEWING = "reviewing"
    VERIFIED = "verified"
    REJECTED = "rejected"
    INCONCLUSIVE = "inconclusive"


class MobileToolExecutionStatus(StrEnum):
    COMPLETED = "completed"
    PARTIAL = "partial"
    NOT_RUN = "not_run"
    NOT_APPLICABLE = "not_applicable"
    BLOCKED = "blocked"
    FAILED = "failed"


class MobileSecurityRecord(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    record_id: str
    record_type: MobileRecordType
    weakness_id: str | None = None
    title: str
    severity: str = "unknown"
    evidence_state: MobileEvidenceState
    ownership: MobileOwnership = MobileOwnership.UNKNOWN
    confidence: str = "unknown"
    security_property: str | None = None
    affected_component: str | None = None
    source: dict[str, object] = Field(default_factory=dict)
    evidence_references: tuple[str, ...] = ()
    related_record_ids: tuple[str, ...] = ()
    details: dict[str, object] = Field(default_factory=dict)


class MobileCandidateHypothesis(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    hypothesis_id: str
    title: str
    summary: str
    related_observation_ids: tuple[str, ...] = ()
    related_evidence_ids: tuple[str, ...] = ()
    ownership: MobileOwnership = MobileOwnership.UNKNOWN
    affected_component: str | None = None
    security_property: str | None = None
    confidence: str = "candidate"
    required_validation: tuple[str, ...] = ()
    status: MobileHypothesisState = MobileHypothesisState.EVIDENCE_REQUIRED


class MobileToolExecution(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    tool: str
    status: MobileToolExecutionStatus
    version: str | None = None
    started_at: str | None = None
    finished_at: str | None = None
    exit_code: int | None = None
    partial: bool = False
    evidence_references: tuple[str, ...] = ()
    failure_reason: str | None = None
    generated_files: int | None = Field(default=None, ge=0)
    processed_units: int | None = Field(default=None, ge=0)
    total_units: int | None = Field(default=None, ge=0)
    coverage_limitations: tuple[str, ...] = ()
    downstream_usable: bool = False
    applicability_reason: str | None = None


class MobileOperationalIssue(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    issue_id: str
    tool: str | None = None
    title: str
    evidence_state: MobileEvidenceState
    failure_type: str
    retryable: bool = False
    partial_output: bool = False
    evidence_references: tuple[str, ...] = ()
    details: dict[str, object] = Field(default_factory=dict)


class MobileCapabilityStatus(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    capability: str
    status: MobileToolExecutionStatus
    evidence_references: tuple[str, ...] = ()
    detail: str | None = None


class MobileEndpointReference(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    endpoint_id: str
    endpoint: str
    normalized_endpoint: str
    host: str | None = None
    port: int | None = Field(default=None, ge=0, le=65535)
    protocol: str
    likely_role: str
    ownership: MobileOwnership = MobileOwnership.UNKNOWN
    source_file: str
    source_offset: int | None = Field(default=None, ge=0)
    source_references: tuple[str, ...] = ()
    static_or_runtime: str = "static"
    confidence: str = "confirmed"
    reachability: str = "unknown"
    evidence_references: tuple[str, ...] = ()


class MobileTransportCorrelation(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    correlation_id: str
    title: str
    summary: str
    observation_ids: tuple[str, ...] = ()
    endpoint_ids: tuple[str, ...] = ()
    ownership: MobileOwnership = MobileOwnership.UNKNOWN
    security_property: str = "transport_confidentiality"
    priority: str = "medium"
    confidence: str = "candidate"
    status: MobileHypothesisState = MobileHypothesisState.EVIDENCE_REQUIRED
    limitations: tuple[str, ...] = ()


class MobileComponentSurface(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    component_id: str
    name: str
    kind: str
    exported: bool
    permission: str | None = None
    ownership: MobileOwnership = MobileOwnership.UNKNOWN
    intent_filters: tuple[dict[str, object], ...] = ()
    validation_scope: tuple[str, ...] = ()
    security_impact: str = "requires_code_path_validation"
    evidence_references: tuple[str, ...] = ()


class MobileCoverageSummary(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    state: str
    completed: int = Field(ge=0)
    partial: int = Field(ge=0)
    not_run: int = Field(ge=0)
    not_applicable: int = Field(ge=0)
    blocked: int = Field(ge=0)
    failed: int = Field(ge=0)
    capabilities: tuple[MobileCapabilityStatus, ...] = ()


class MobileAnalysisIntelligence(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    schema_version: str = "1.0"
    artifact_sha256: str
    observations: tuple[MobileSecurityRecord, ...] = ()
    verified_configurations: tuple[MobileSecurityRecord, ...] = ()
    verified_findings: tuple[MobileSecurityRecord, ...] = ()
    candidates: tuple[MobileSecurityRecord, ...] = ()
    operational_issues: tuple[MobileOperationalIssue, ...] = ()
    tool_executions: tuple[MobileToolExecution, ...] = ()
    hypotheses: tuple[MobileCandidateHypothesis, ...] = ()
    endpoint_references: tuple[MobileEndpointReference, ...] = ()
    transport_correlations: tuple[MobileTransportCorrelation, ...] = ()
    exported_component_surfaces: tuple[MobileComponentSurface, ...] = ()
    bounded_negative_claims: tuple[str, ...] = ()
    remediation_recommendations: tuple[str, ...] = ()
    ai_context: dict[str, object] = Field(default_factory=dict)
    coverage: MobileCoverageSummary
    intelligence_sha256: str

    @property
    def observation_count(self) -> int:
        return len(self.observations)

    @property
    def verified_configuration_count(self) -> int:
        return len(self.verified_configurations)

    @property
    def verified_security_finding_count(self) -> int:
        return len(self.verified_findings)

    @property
    def evidence_required_count(self) -> int:
        return len(self.candidates)

    @property
    def operational_issue_count(self) -> int:
        return len(self.operational_issues)


def _text(value: object, fallback: str = "") -> str:
    text = str(value or "").strip()
    return text or fallback


def _mapping(value: object) -> Mapping[str, object]:
    return value if isinstance(value, Mapping) else {}


def _tuple_strings(value: object) -> tuple[str, ...]:
    if not isinstance(value, (list, tuple, set, frozenset)):
        return ()
    return tuple(str(item) for item in value if str(item).strip())


def _ownership(component: str | None, package_name: str | None) -> tuple[MobileOwnership, str]:
    if not component:
        return MobileOwnership.UNKNOWN, "component_not_available"
    if package_name and component.startswith(package_name):
        return MobileOwnership.APP_OWNED, "component_namespace_matches_manifest_package"
    if component.startswith(("android.", "androidx.", "java.", "javax.", "kotlin.")):
        return MobileOwnership.PLATFORM_FRAMEWORK, "platform_namespace"
    known_sdk_prefixes = (
        "com.facebook.",
        "com.google.android.",
        "com.huawei.",
        "com.linecorp.",
        "com.mbridge.",
        "com.yandex.",
        "com.bytedance.",
        "io.appmetrica.",
        "cn.jpush.",
        "cn.android.",
        "sg.bigo.",
        "com.vk.",
    )
    if component.startswith(known_sdk_prefixes):
        return MobileOwnership.SDK_OWNED, "known_sdk_namespace"
    return MobileOwnership.UNKNOWN, "namespace_not_sufficient_for_attribution"


def _endpoint_ownership(source_file: str, package_name: str | None) -> MobileOwnership:
    source = source_file.casefold()
    if package_name and package_name.casefold().replace(".", "/") in source:
        return MobileOwnership.APP_OWNED
    sdk_markers = (
        "google",
        "facebook",
        "jpush",
        "huawei",
        "bytedance",
        "yandex",
        "bigo",
        "sdk",
        "ads",
    )
    if any(marker in source for marker in sdk_markers):
        return MobileOwnership.SDK_OWNED
    return MobileOwnership.UNKNOWN


def _property(weakness_id: str | None, title: str) -> str | None:
    value = f"{weakness_id or ''} {title}".casefold()
    if "cleartext" in value or "http" in value or "transport" in value:
        return "transport_confidentiality"
    if "exported" in value or "component" in value:
        return "component_exposure"
    if "webview" in value or "javascript" in value:
        return "webview_origin_trust"
    if "dynamic" in value or "dexclassloader" in value:
        return "dynamic_code_trust"
    if "permission" in value:
        return "permission_scope"
    return None


def _record_from_observation(
    observation: Mapping[str, object],
    *,
    package_name: str | None,
) -> MobileSecurityRecord:
    record_id = _text(observation.get("observation_id"), "observation-unknown")
    title = _text(observation.get("title"), "Static mobile observation")
    status = _text(observation.get("status"), MobileEvidenceState.INCONCLUSIVE.value)
    try:
        evidence_state = MobileEvidenceState(status)
    except ValueError:
        evidence_state = MobileEvidenceState.INCONCLUSIVE
    component = _text(observation.get("component")) or None
    ownership, ownership_basis = _ownership(component, package_name)
    evidence = _mapping(observation.get("evidence"))
    evidence_references = _tuple_strings(
        observation.get("evidence_references") or observation.get("evidence_receipts")
    )
    if not evidence_references and evidence:
        evidence_references = (f"observation:{sha256_json(dict(observation))}",)
    source = {
        key: evidence[key]
        for key in ("tool", "source_file", "class_name", "method", "source_sha256")
        if key in evidence
    }
    details = {
        key: value
        for key, value in observation.items()
        if key
        not in {
            "observation_id",
            "weakness_id",
            "title",
            "severity",
            "status",
            "component",
            "evidence",
            "tool_ids",
            "evidence_references",
            "evidence_receipts",
        }
    }
    details["ownership_basis"] = ownership_basis
    if evidence:
        details["evidence_metadata"] = dict(evidence)
    return MobileSecurityRecord(
        record_id=record_id,
        record_type=MobileRecordType.OBSERVATION,
        weakness_id=_text(observation.get("weakness_id")) or None,
        title=title,
        severity=_text(observation.get("severity"), "unknown"),
        evidence_state=evidence_state,
        ownership=ownership,
        confidence=_text(observation.get("confidence"), status),
        security_property=_property(_text(observation.get("weakness_id")) or None, title),
        affected_component=component,
        source=source,
        evidence_references=evidence_references,
        details=details,
    )


def _safe_url_parts(endpoint: str):
    try:
        return urlsplit(endpoint)
    except ValueError:
        return None


def _safe_url_port(parts: object) -> int | None:
    if parts is None:
        return None
    try:
        value = parts.port
    except (AttributeError, ValueError):
        return None
    return value if isinstance(value, int) and 0 <= value <= 65535 else None


def _endpoint_references(
    layered_report: Mapping[str, object] | None,
    *,
    package_name: str | None,
    artifact_sha256: str,
) -> tuple[MobileEndpointReference, ...]:
    if not layered_report:
        return ()
    rows = _mapping(layered_report).get("network_endpoints")
    if not isinstance(rows, (list, tuple)):
        return ()
    groups: dict[tuple[str, str, str, MobileOwnership], dict[str, object]] = {}
    for row in rows:
        if not isinstance(row, Mapping):
            continue
        endpoint = _text(row.get("endpoint"))
        if not endpoint:
            continue
        parsed = _safe_url_parts(endpoint)
        protocol = _text(
            row.get("protocol"),
            parsed.scheme
            if parsed is not None and parsed.scheme
            else (endpoint.split(":", 1)[0] if ":" in endpoint else "unknown"),
        ).casefold()
        normalized = endpoint.rstrip("/").casefold()
        source_file = _text(row.get("source_file"), "unknown-source")
        likely_role = _text(row.get("likely_role"), "api_or_unknown_backend")
        ownership = _endpoint_ownership(source_file, package_name)
        key = (normalized, protocol, likely_role, ownership)
        group = groups.setdefault(key, {"row": row, "sources": []})
        sources = group["sources"]
        if isinstance(sources, list):
            source_offset = row.get("source_offset")
            suffix = f":{source_offset}" if isinstance(source_offset, int) else ""
            sources.append(f"{source_file}{suffix}")
    result: list[MobileEndpointReference] = []
    for key, group in groups.items():
        row = group["row"]
        if not isinstance(row, Mapping):
            continue
        endpoint = _text(row.get("endpoint"))
        parsed = _safe_url_parts(endpoint)
        source_file = _text(row.get("source_file"), "unknown-source")
        source_offset = row.get("source_offset")
        sources = tuple(sorted(set(group.get("sources", []))))
        evidence_key = {
            "artifact": artifact_sha256,
            "endpoint": key[0],
            "protocol": key[1],
            "role": key[2],
            "ownership": key[3].value,
            "sources": sources,
        }
        result.append(
            MobileEndpointReference(
                endpoint_id=f"endpoint:{sha256_json(evidence_key)[:24]}",
                endpoint=endpoint,
                normalized_endpoint=key[0],
                host=_text(row.get("host")) or (parsed.hostname if parsed is not None else None),
                port=(
                    int(row["port"])
                    if isinstance(row.get("port"), int) and 0 <= row["port"] <= 65535
                    else _safe_url_port(parsed)
                ),
                protocol=key[1],
                likely_role=key[2],
                ownership=key[3],
                source_file=source_file,
                source_offset=source_offset if isinstance(source_offset, int) else None,
                source_references=sources,
                static_or_runtime=_text(row.get("static_or_runtime"), "static"),
                confidence=_text(row.get("confidence"), "confirmed"),
                reachability="unknown",
                evidence_references=(f"endpoint:{sha256_json(evidence_key)}",),
            )
        )
    return tuple(result)


def _component_surfaces(
    layered_report: Mapping[str, object] | None,
    *,
    package_name: str | None,
) -> tuple[MobileComponentSurface, ...]:
    if not layered_report:
        return ()
    manifest = _mapping(_mapping(layered_report).get("manifest"))
    rows = manifest.get("components")
    if not isinstance(rows, (list, tuple)):
        return ()
    surfaces: list[MobileComponentSurface] = []
    for row in rows:
        if not isinstance(row, Mapping) or row.get("exported") != "true":
            continue
        name = _text(row.get("name"), "unnamed-component")
        permission = _text(row.get("permission")) or None
        ownership, _ = _ownership(name, package_name)
        surfaces.append(
            MobileComponentSurface(
                component_id=(
                    f"component:{sha256_json({'name': name, 'kind': row.get('type')})[:24]}"
                ),
                name=name,
                kind=_text(row.get("type"), "unknown"),
                exported=True,
                permission=permission,
                ownership=ownership,
                intent_filters=tuple(
                    item for item in row.get("intent_filters", ()) if isinstance(item, Mapping)
                ),
                validation_scope=(
                    "intent extras and caller validation",
                    "permission and authentication/session checks",
                    "URI/deep-link and redirect handling",
                    "sensitive downstream action reachability",
                ),
                evidence_references=("manifest:attack-surface",),
            )
        )
    return tuple(surfaces)


def _transport_correlations(
    observations: Sequence[MobileSecurityRecord],
    endpoints: Sequence[MobileEndpointReference],
) -> tuple[MobileTransportCorrelation, ...]:
    cleartext = tuple(
        item for item in observations if item.weakness_id == "android-cleartext-traffic"
    )
    http = tuple(item for item in endpoints if item.protocol == "http")
    if not cleartext or not http:
        return ()
    roles = sorted({item.likely_role for item in http})
    return (
        MobileTransportCorrelation(
            correlation_id="correlation:cleartext-http-source",
            title="Cleartext policy correlates with app-owned HTTP source references",
            summary=(
                "The manifest permits cleartext traffic and static source contains HTTP literals; "
                "runtime reachability and transmitted-data impact remain unknown."
            ),
            observation_ids=tuple(item.record_id for item in cleartext),
            endpoint_ids=tuple(item.endpoint_id for item in http),
            ownership=MobileOwnership.APP_OWNED
            if any(item.ownership == MobileOwnership.APP_OWNED for item in http)
            else MobileOwnership.UNKNOWN,
            priority="high",
            confidence="high_confidence",
            limitations=(
                "Static literals do not prove endpoint reachability.",
                "No live traffic interception was performed.",
                "Credentials or sensitive data transmission were not established.",
                f"Observed service families: {', '.join(roles) or 'unknown'}.",
            ),
        ),
    )


_DYNAMIC_ENDPOINT_ASSIGNMENT = re.compile(
    r"(?P<destination>[A-Za-z_$][A-Za-z0-9_$]*(?:endpoint|server|host|url|scheme)[A-Za-z0-9_$]*)"
    r"\s*=\s*(?P<source>[^;]+)",
    re.IGNORECASE,
)


def detect_dynamic_endpoint_assignments(
    source_snippets: Iterable[Mapping[str, object]],
) -> tuple[dict[str, object], ...]:
    """Detect bounded source-level endpoint assignment candidates without proving impact."""

    observations: list[dict[str, object]] = []
    for snippet in source_snippets:
        text = _text(snippet.get("text"))
        source_file = _text(snippet.get("source_file"), "unknown-source")
        if not text:
            continue
        for line_number, line in enumerate(text.splitlines(), start=1):
            lowered = line.casefold()
            if not any(
                marker in lowered
                for marker in (
                    "response",
                    "network",
                    "json",
                    "server",
                    "endpoint",
                    "http://",
                    "https://",
                )
            ):
                continue
            match = _DYNAMIC_ENDPOINT_ASSIGNMENT.search(line)
            if match is None:
                continue
            destination = match.group("destination")
            scheme = (
                "http" if "http://" in lowered else "https" if "https://" in lowered else "unknown"
            )
            digest = sha256_json(
                {"file": source_file, "line": line_number, "destination": destination}
            )[:24]
            observation_id = f"dynamic-endpoint:{digest}"
            observations.append(
                {
                    "observation_id": observation_id,
                    "weakness_id": "mobile-dynamic-endpoint-assignment",
                    "title": "Network-derived value influences endpoint assignment",
                    "severity": "medium",
                    "status": "evidence_required",
                    "confidence": "candidate",
                    "component": _text(snippet.get("class_name")) or None,
                    "evidence": {
                        "source_file": source_file,
                        "source_line": line_number,
                        "destination": destination,
                        "scheme": scheme,
                        "source_kind": _text(snippet.get("source_kind"), "unknown"),
                        "validation_evidence": _text(snippet.get("validation_evidence")) or None,
                        "downstream_use": _text(snippet.get("downstream_use")) or None,
                    },
                }
            )
    return tuple(observations)


def _tool_execution(capture: MobileToolCapture) -> MobileToolExecution:
    evidence = capture.evidence
    generated_files = evidence.get("generated_files")
    partial = capture.tool == "jadx" and capture.return_code == 124
    status = (
        MobileToolExecutionStatus.COMPLETED
        if capture.return_code == 0
        else MobileToolExecutionStatus.FAILED
    )
    if partial:
        status = MobileToolExecutionStatus.PARTIAL
    failure_reason = (
        None
        if capture.return_code == 0
        else f"{capture.tool} returned exit code {capture.return_code}."
    )
    return MobileToolExecution(
        tool=capture.tool,
        status=status,
        started_at=capture.started_at.isoformat(),
        finished_at=capture.completed_at.isoformat(),
        exit_code=capture.return_code,
        partial=partial,
        evidence_references=(f"tool:{capture.tool}:{capture.output_sha256}",),
        failure_reason=failure_reason,
        generated_files=int(generated_files) if isinstance(generated_files, int) else None,
        coverage_limitations=(
            ("Whole-APK absence claims are not supported by a bounded partial source tree.",)
            if partial
            else ()
        ),
        downstream_usable=partial and isinstance(generated_files, int) and generated_files > 0,
    )


def _capabilities(
    captures: Sequence[MobileToolCapture],
    *,
    planned_tools: Iterable[str],
    native_library_count: int,
    dynamic_block_reason: str,
) -> tuple[MobileCapabilityStatus, ...]:
    by_tool = {capture.tool: capture for capture in captures}
    values: list[MobileCapabilityStatus] = []
    for tool in planned_tools:
        capture = by_tool.get(tool)
        if capture is not None:
            execution = _tool_execution(capture)
            values.append(
                MobileCapabilityStatus(
                    capability=tool,
                    status=execution.status,
                    evidence_references=execution.evidence_references,
                    detail=execution.failure_reason,
                )
            )
        elif tool in {"radare2", "ghidra"} and native_library_count == 0:
            values.append(
                MobileCapabilityStatus(
                    capability=tool,
                    status=MobileToolExecutionStatus.NOT_APPLICABLE,
                    detail="No native libraries were discovered in the APK.",
                )
            )
        else:
            values.append(
                MobileCapabilityStatus(
                    capability=tool,
                    status=MobileToolExecutionStatus.NOT_RUN,
                    detail="The configured tool did not produce a capture.",
                )
            )
    values.append(
        MobileCapabilityStatus(
            capability="dynamic-analysis",
            status=MobileToolExecutionStatus.BLOCKED,
            detail=dynamic_block_reason,
        )
    )
    return tuple(values)


def _coverage(capabilities: tuple[MobileCapabilityStatus, ...]) -> MobileCoverageSummary:
    counts = {status.value: 0 for status in MobileToolExecutionStatus}
    for item in capabilities:
        counts[item.status.value] += 1
    if counts[MobileToolExecutionStatus.PARTIAL.value]:
        state = "completed_with_partial_stage"
    elif (
        counts[MobileToolExecutionStatus.FAILED.value]
        or counts[MobileToolExecutionStatus.BLOCKED.value]
    ):
        state = "completed_with_boundaries"
    else:
        state = "completed"
    return MobileCoverageSummary(
        state=state,
        completed=counts[MobileToolExecutionStatus.COMPLETED.value],
        partial=counts[MobileToolExecutionStatus.PARTIAL.value],
        not_run=counts[MobileToolExecutionStatus.NOT_RUN.value],
        not_applicable=counts[MobileToolExecutionStatus.NOT_APPLICABLE.value],
        blocked=counts[MobileToolExecutionStatus.BLOCKED.value],
        failed=counts[MobileToolExecutionStatus.FAILED.value],
        capabilities=capabilities,
    )


def _hypotheses(
    observations: Sequence[MobileSecurityRecord],
    *,
    endpoints: Sequence[Mapping[str, object]],
) -> tuple[MobileCandidateHypothesis, ...]:
    result: list[MobileCandidateHypothesis] = []
    cleartext = tuple(
        item for item in observations if item.weakness_id == "android-cleartext-traffic"
    )
    http_endpoints = tuple(
        item for item in endpoints if _text(item.get("protocol")).casefold() == "http"
    )
    if cleartext and http_endpoints:
        related = cleartext[0]
        result.append(
            MobileCandidateHypothesis(
                hypothesis_id="hypothesis-transport-http-correlation",
                title="Cleartext configuration correlates with app-owned HTTP source references",
                summary=(
                    "Manifest cleartext policy and static HTTP endpoint evidence justify "
                    "service-specific transport review."
                ),
                related_observation_ids=tuple(item.record_id for item in cleartext),
                related_evidence_ids=related.evidence_references,
                ownership=MobileOwnership.APP_OWNED,
                security_property="transport_confidentiality",
                confidence="high_confidence",
                required_validation=(
                    "Confirm which HTTP paths are reachable in supported configurations.",
                    "Determine whether authenticated, update, or device-control data uses HTTP.",
                    "Verify HTTPS-only enforcement in an approved isolated runtime.",
                ),
            )
        )
    webview = tuple(
        item for item in observations if item.security_property == "webview_origin_trust"
    )
    exported_webview = tuple(
        item
        for item in observations
        if item.weakness_id == "android-exported-component" and "webview" in item.title.casefold()
    )
    if webview and exported_webview:
        result.append(
            MobileCandidateHypothesis(
                hypothesis_id="hypothesis-exported-webview-route",
                title="Exported WebView route requires origin and intent validation",
                summary=(
                    "An exported WebView component and a WebView bridge surface justify "
                    "bounded deep-link review."
                ),
                related_observation_ids=tuple(
                    item.record_id for item in (*webview, *exported_webview)
                ),
                ownership=exported_webview[0].ownership,
                affected_component=exported_webview[0].affected_component,
                security_property="webview_origin_trust",
                confidence="candidate",
                required_validation=(
                    "Inspect intent extras and URL allowlists.",
                    "Review JavaScript bridge annotations and loaded origins.",
                    "Confirm navigation and authentication/session handling.",
                ),
            )
        )
    for item in observations:
        if item.weakness_id == "mobile-dynamic-endpoint-assignment":
            result.append(
                MobileCandidateHypothesis(
                    hypothesis_id=f"hypothesis-{item.record_id}",
                    title="Network-derived endpoint assignment requires integrity review",
                    summary=(
                        "A source-level endpoint assignment pattern may influence service "
                        "routing, but impact is not established."
                    ),
                    related_observation_ids=(item.record_id,),
                    related_evidence_ids=item.evidence_references,
                    ownership=item.ownership,
                    affected_component=item.affected_component,
                    security_property="endpoint_integrity",
                    confidence="candidate",
                    required_validation=(
                        "Trace the response source and authentication.",
                        "Check scheme/host allowlisting and redirect restrictions.",
                        "Confirm downstream use in sensitive operations.",
                    ),
                )
            )
    return tuple(result)


def build_mobile_intelligence(
    *,
    artifact_sha256: str,
    observations: Iterable[Mapping[str, object]],
    captures: Sequence[MobileToolCapture],
    layered_report: Mapping[str, object] | None,
    planned_tools: Iterable[str],
    native_library_count: int,
    dynamic_block_reason: str = "Approved isolated runtime unavailable.",
    source_snippets: Iterable[Mapping[str, object]] = (),
) -> MobileAnalysisIntelligence:
    package_name = (
        _text(_mapping(_mapping(layered_report).get("manifest")).get("package_name")) or None
    )
    raw_observations = tuple(observations) + detect_dynamic_endpoint_assignments(source_snippets)
    normalized = tuple(
        _record_from_observation(item, package_name=package_name) for item in raw_observations
    )
    verified_configurations = tuple(
        item
        for item in normalized
        if item.evidence_state == MobileEvidenceState.VERIFIED_CONFIGURATION
    )
    verified_findings = tuple(
        item
        for item in normalized
        if item.evidence_state == MobileEvidenceState.VERIFIED_SECURITY_FINDING
    )
    candidates = tuple(
        item
        for item in normalized
        if item.evidence_state
        in {
            MobileEvidenceState.EVIDENCE_REQUIRED,
            MobileEvidenceState.INCONCLUSIVE,
        }
    )
    operational: list[MobileOperationalIssue] = []
    for item in normalized:
        if item.evidence_state == MobileEvidenceState.OPERATIONAL_FAILURE:
            operational.append(
                MobileOperationalIssue(
                    issue_id=item.record_id,
                    tool=_text(item.source.get("tool")) or None,
                    title=item.title,
                    evidence_state=MobileEvidenceState.OPERATIONAL_FAILURE,
                    failure_type="tool_failure",
                    retryable=True,
                    partial_output=False,
                    evidence_references=item.evidence_references,
                    details=item.details,
                )
            )
    executions = tuple(_tool_execution(capture) for capture in captures)
    for execution in executions:
        if execution.status == MobileToolExecutionStatus.PARTIAL:
            operational.append(
                MobileOperationalIssue(
                    issue_id=f"partial:{execution.tool}:{execution.evidence_references[0]}",
                    tool=execution.tool,
                    title=f"{execution.tool} produced a partial tool result",
                    evidence_state=MobileEvidenceState.PARTIAL_TOOL_RESULT,
                    failure_type="bounded_timeout_or_partial_output",
                    retryable=True,
                    partial_output=True,
                    evidence_references=execution.evidence_references,
                    details={
                        "exit_code": execution.exit_code,
                        "generated_files": execution.generated_files,
                    },
                )
            )
    endpoint_rows = (
        tuple(
            item
            for item in _mapping(layered_report).get("network_endpoints", ())
            if isinstance(item, Mapping)
        )
        if layered_report
        else ()
    )
    capabilities = _capabilities(
        captures,
        planned_tools=tuple(planned_tools),
        native_library_count=native_library_count,
        dynamic_block_reason=dynamic_block_reason,
    )
    coverage = _coverage(capabilities)
    endpoint_references = _endpoint_references(
        layered_report,
        package_name=package_name,
        artifact_sha256=artifact_sha256,
    )
    transport_correlations = _transport_correlations(normalized, endpoint_references)
    component_surfaces = _component_surfaces(layered_report, package_name=package_name)
    hypotheses = _hypotheses(normalized, endpoints=endpoint_rows)
    bounded_negative_claims = (
        (
            (
                "No app-owned matching JavaScript bridge call was found in the retained partial "
                "source inspected; this is not whole-APK absence."
            ),
            (
                "No app-owned dynamic class-loader match was found in the retained partial "
                "source inspected; this is not whole-APK absence."
            ),
        )
        if any(item.tool == "jadx" and item.partial for item in executions)
        else ()
    )
    remediation_recommendations: list[str] = []
    if any(item.weakness_id == "android-cleartext-traffic" for item in normalized):
        remediation_recommendations.extend(
            (
                (
                    "Prefer HTTPS-only transport and remove HTTP fallback where operationally "
                    "possible."
                ),
                (
                    "Constrain any network-security-config exceptions to the narrowest "
                    "required hosts."
                ),
                (
                    "Validate dynamically assigned hosts, schemes, redirects, and authenticated "
                    "configuration sources."
                ),
            )
        )
    if component_surfaces:
        remediation_recommendations.append(
            "For exported components, remove export or add appropriate permission where not "
            "required, then validate intents, URI/origin, authentication, and sensitive "
            "downstream actions."
        )
    if any(item.ownership == MobileOwnership.SDK_OWNED for item in normalized):
        remediation_recommendations.append(
            "For SDK-owned surfaces, identify the dependency/version and apply "
            "vendor-supported configuration or upgrade guidance before changing app-owned code."
        )
    unsigned = {
        "schema_version": "1.0",
        "artifact_sha256": artifact_sha256,
        "observations": [item.model_dump(mode="json") for item in normalized],
        "verified_configurations": [
            item.model_dump(mode="json") for item in verified_configurations
        ],
        "verified_findings": [item.model_dump(mode="json") for item in verified_findings],
        "candidates": [item.model_dump(mode="json") for item in candidates],
        "operational_issues": [item.model_dump(mode="json") for item in operational],
        "tool_executions": [item.model_dump(mode="json") for item in executions],
        "hypotheses": [item.model_dump(mode="json") for item in hypotheses],
        "endpoint_references": [item.model_dump(mode="json") for item in endpoint_references],
        "transport_correlations": [item.model_dump(mode="json") for item in transport_correlations],
        "exported_component_surfaces": [
            item.model_dump(mode="json") for item in component_surfaces
        ],
        "bounded_negative_claims": list(bounded_negative_claims),
        "remediation_recommendations": remediation_recommendations,
        "coverage": coverage.model_dump(mode="json"),
    }
    unsigned["ai_context"] = build_mobile_intelligence_context(unsigned)
    return MobileAnalysisIntelligence(
        **unsigned,
        intelligence_sha256=sha256_json(unsigned),
    )


def build_mobile_intelligence_context(
    intelligence: Mapping[str, object] | MobileAnalysisIntelligence,
) -> dict[str, object]:
    """Return bounded structured context for correlation prompts and safe summaries."""

    payload = (
        intelligence.model_dump(mode="json")
        if isinstance(intelligence, MobileAnalysisIntelligence)
        else intelligence
    )

    def record_summary(item: object) -> dict[str, object]:
        row = item if isinstance(item, Mapping) else {}
        return {
            key: row.get(key)
            for key in (
                "record_id",
                "weakness_id",
                "title",
                "severity",
                "evidence_state",
                "ownership",
                "confidence",
                "security_property",
                "affected_component",
                "evidence_references",
            )
            if row.get(key) is not None
        }

    tool_limitations = []
    for item in payload.get("tool_executions", ()):
        if isinstance(item, Mapping) and (
            item.get("partial") or item.get("failure_reason") or item.get("status") != "completed"
        ):
            tool_limitations.append(
                {
                    "tool": item.get("tool"),
                    "status": item.get("status"),
                    "partial": bool(item.get("partial")),
                    "failure_reason": item.get("failure_reason"),
                    "coverage_limitations": item.get("coverage_limitations", []),
                    "downstream_usable": bool(item.get("downstream_usable")),
                    "evidence_references": item.get("evidence_references", []),
                }
            )
    return {
        "artifact_sha256": payload.get("artifact_sha256"),
        "coverage": payload.get("coverage", {}),
        "verified_configurations": [
            record_summary(item) for item in payload.get("verified_configurations", [])
        ],
        "verified_findings": [
            record_summary(item) for item in payload.get("verified_findings", [])
        ],
        "open_candidates": [record_summary(item) for item in payload.get("candidates", [])],
        "operational_issues": [
            record_summary(item) for item in payload.get("operational_issues", [])
        ],
        "hypotheses": payload.get("hypotheses", []),
        "transport_correlations": payload.get("transport_correlations", []),
        "ownership": {
            "app_owned": sum(
                item.get("ownership") == MobileOwnership.APP_OWNED.value
                for item in payload.get("observations", [])
                if isinstance(item, Mapping)
            ),
            "sdk_owned": sum(
                item.get("ownership") == MobileOwnership.SDK_OWNED.value
                for item in payload.get("observations", [])
                if isinstance(item, Mapping)
            ),
            "unknown": sum(
                item.get("ownership") == MobileOwnership.UNKNOWN.value
                for item in payload.get("observations", [])
                if isinstance(item, Mapping)
            ),
        },
        "tool_limitations": tool_limitations,
        "bounded_negative_rules": [
            "JADX partial coverage does not support whole-APK absence claims.",
            "YARA surface matches are candidates for validation, not verification authority.",
            "Exported configuration does not establish exploitability.",
            "Dynamic analysis remains blocked unless governed runtime prerequisites are satisfied.",
        ],
        "remediation_recommendations": payload.get("remediation_recommendations", []),
    }


def intelligence_counts(
    intelligence: Mapping[str, object] | MobileAnalysisIntelligence,
) -> dict[str, int]:
    payload: Mapping[str, object]
    if isinstance(intelligence, MobileAnalysisIntelligence):
        payload = intelligence.model_dump(mode="json")
    else:
        payload = intelligence
    return {
        "observation_count": len(payload.get("observations", ()))
        if isinstance(payload.get("observations"), list)
        else 0,
        "verified_configuration_count": len(payload.get("verified_configurations", ()))
        if isinstance(payload.get("verified_configurations"), list)
        else sum(
            item.get("evidence_state") == MobileEvidenceState.VERIFIED_CONFIGURATION.value
            for item in payload.get("observations", ())
            if isinstance(item, Mapping)
        )
        if isinstance(payload.get("observations"), list)
        else 0,
        "verified_security_finding_count": len(payload.get("verified_findings", ()))
        if isinstance(payload.get("verified_findings"), list)
        else 0,
        "evidence_required_count": len(payload.get("candidates", ()))
        if isinstance(payload.get("candidates"), list)
        else 0,
        "operational_issue_count": len(payload.get("operational_issues", ()))
        if isinstance(payload.get("operational_issues"), list)
        else 0,
        "hypothesis_count": len(payload.get("hypotheses", ()))
        if isinstance(payload.get("hypotheses"), list)
        else 0,
        "endpoint_count": len(payload.get("endpoint_references", ()))
        if isinstance(payload.get("endpoint_references"), list)
        else 0,
        "transport_correlation_count": len(payload.get("transport_correlations", ()))
        if isinstance(payload.get("transport_correlations"), list)
        else 0,
        "exported_component_surface_count": len(payload.get("exported_component_surfaces", ()))
        if isinstance(payload.get("exported_component_surfaces"), list)
        else 0,
    }


__all__ = [
    "MobileAnalysisIntelligence",
    "MobileCandidateHypothesis",
    "MobileCapabilityStatus",
    "MobileCoverageSummary",
    "MobileEvidenceState",
    "MobileHypothesisState",
    "MobileOperationalIssue",
    "MobileOwnership",
    "MobileRecordType",
    "MobileSecurityRecord",
    "MobileToolExecution",
    "MobileToolExecutionStatus",
    "build_mobile_intelligence",
    "build_mobile_intelligence_context",
    "detect_dynamic_endpoint_assignments",
    "intelligence_counts",
]
