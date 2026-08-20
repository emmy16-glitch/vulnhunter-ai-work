"""Deterministic Source Hunt over retained APK source/evidence.

This module deliberately does not execute APKs, contact discovered endpoints, or treat
AI output as verification authority. It consumes the normalized APK intelligence
receipt and a retained source tree, then produces a bounded evidence graph and
coverage-aware results.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Iterable, Mapping
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field

from vulnhunter.actions.models import sha256_json
from vulnhunter.mobile.intelligence import MobileOwnership
from vulnhunter.source_hunt.models import SourceReference

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_MAX_SOURCE_FILE_BYTES = 2_000_000
_DEFAULT_EXTENSIONS = frozenset({".java", ".kt", ".xml", ".smali", ".json", ".properties"})


class MobileSourceHuntState(StrEnum):
    VERIFIED = "verified"
    REJECTED = "rejected"
    INCONCLUSIVE = "inconclusive"
    EVIDENCE_REQUIRED = "evidence_required"
    BLOCKED = "blocked"


class MobileGraphNodeType(StrEnum):
    ARTIFACT = "artifact"
    COMPONENT = "manifest_component"
    SOURCE_FILE = "source_file"
    ENTRY_POINT = "entry_point"
    SOURCE = "source"
    TRANSFORMATION = "transformation"
    VALIDATION = "validation"
    AUTHENTICATION = "authentication_check"
    AUTHORIZATION = "authorization_check"
    PERMISSION = "permission_check"
    TRUST_BOUNDARY = "trust_boundary"
    NETWORK_ENDPOINT = "network_endpoint"
    WEBVIEW = "webview"
    FILE_OPERATION = "file_operation"
    DATABASE_OPERATION = "database_operation"
    PROCESS_EXECUTION = "process_execution"
    DESERIALIZATION = "deserialization"
    DYNAMIC_LOADER = "dynamic_loader"
    CRYPTOGRAPHIC_OPERATION = "cryptographic_operation"
    SECURITY_SINK = "security_sink"
    TOOL_EVIDENCE = "tool_evidence"
    OBSERVATION = "observation"
    HYPOTHESIS = "security_hypothesis"
    FINDING = "finding"
    REMEDIATION = "remediation"


class MobileGraphEdgeType(StrEnum):
    EXPOSES = "exposes"
    RECEIVES = "receives"
    CALLS = "calls"
    FLOWS_TO = "flows_to"
    RETURNS_TO = "returns_to"
    DERIVES_FROM = "derives_from"
    ASSIGNS_TO = "assigns_to"
    LOADS_URL = "loads_url"
    REQUESTS = "requests"
    OPENS = "opens"
    WRITES = "writes"
    READS = "reads"
    EXECUTES = "executes"
    DESERIALIZES = "deserializes"
    LOADS_CODE = "loads_code"
    REDIRECTS_TO = "redirects_to"
    AUTHENTICATES_WITH = "authenticates_with"
    AUTHORIZED_BY = "authorized_by"
    GUARDED_BY = "guarded_by"
    VALIDATED_BY = "validated_by"
    SANITIZED_BY = "sanitized_by"
    PERMISSIONED_BY = "permissioned_by"
    CROSSES_TRUST_BOUNDARY = "crosses_trust_boundary"
    DELEGATES_TO = "delegates_to"
    RESOLVES_TO = "resolves_to"
    CORROBORATES = "corroborates"
    EVIDENCE_FOR = "evidence_for"
    CANDIDATE_FOR = "candidate_for"
    REMEDIATES = "remediates"


class MobileSourceHuntCoverage(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    status: str = Field(pattern=r"^(complete|partial|blocked|unavailable)$")
    source_file_count: int = Field(ge=0)
    source_bytes: int = Field(ge=0)
    limitations: tuple[str, ...] = ()
    evidence_references: tuple[str, ...] = ()


class MobileGraphProvenance(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    artifact_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    source_identity: str
    source_path: str | None = None
    source_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    line_start: int | None = Field(default=None, ge=1)
    line_end: int | None = Field(default=None, ge=1)
    analysis_run_id: str
    confidence: str = "confirmed"
    coverage: str = "complete"
    evidence_references: tuple[str, ...] = ()


class MobileGraphNode(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    node_id: str
    node_type: MobileGraphNodeType
    label: str
    ownership: MobileOwnership = MobileOwnership.UNKNOWN
    state: MobileSourceHuntState | None = None
    evidence_references: tuple[str, ...] = ()
    provenance: tuple[MobileGraphProvenance, ...] = ()
    attributes: dict[str, object] = Field(default_factory=dict)


class MobileGraphEdge(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    edge_id: str
    source_node_id: str
    target_node_id: str
    relation: MobileGraphEdgeType
    confidence: str = "confirmed"
    state: MobileSourceHuntState | None = None
    evidence_references: tuple[str, ...] = ()
    provenance: tuple[MobileGraphProvenance, ...] = ()
    attributes: dict[str, object] = Field(default_factory=dict)


class MobileAttackGraph(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    graph_id: str
    artifact_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    source_identity: str
    analysis_run_id: str
    nodes: tuple[MobileGraphNode, ...]
    edges: tuple[MobileGraphEdge, ...]
    coverage: MobileSourceHuntCoverage
    graph_sha256: str


class MobileSourceHuntSeed(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    seed_id: str
    seed_type: str
    title: str
    weakness_id: str | None = None
    component_name: str | None = None
    ownership: MobileOwnership = MobileOwnership.UNKNOWN
    evidence_references: tuple[str, ...] = ()
    source_intelligence_record_id: str | None = None
    attributes: dict[str, object] = Field(default_factory=dict)


class MobileSourceHuntResult(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    seed: MobileSourceHuntSeed
    state: MobileSourceHuntState
    summary: str
    entry_point: str | None = None
    source_symbols: tuple[str, ...] = ()
    sink_symbols: tuple[str, ...] = ()
    controls_observed: tuple[str, ...] = ()
    missing_evidence: tuple[str, ...] = ()
    source_references: tuple[SourceReference, ...] = ()
    graph_node_ids: tuple[str, ...] = ()
    graph_edge_ids: tuple[str, ...] = ()
    bounded_negative: bool = False
    verified_finding: bool = False
    remediation: str | None = None
    deterministic_validation: str | None = None


class MobileSourceHuntReport(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    report_id: str = Field(pattern=r"^source-mobile-report-[0-9a-f]{24}$")
    artifact_id: str
    artifact_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    source_identity: str
    analysis_run_id: str
    coverage: MobileSourceHuntCoverage
    seeds_examined: int = Field(ge=0)
    results: tuple[MobileSourceHuntResult, ...]
    graph: MobileAttackGraph
    verified_finding_count: int = Field(ge=0)
    rejected_count: int = Field(ge=0)
    inconclusive_count: int = Field(ge=0)
    evidence_required_count: int = Field(ge=0)
    blocked_count: int = Field(ge=0)
    created_at: datetime
    safe_error: str | None = None


class _SourceFile:
    def __init__(self, *, path: str, absolute: Path, raw: bytes, sha256: str) -> None:
        self.path = path
        self.absolute = absolute
        self.raw = raw
        self.sha256 = sha256
        try:
            self.text = raw.decode("utf-8")
        except UnicodeDecodeError:
            self.text = ""
        self.lines = self.text.splitlines()

    @property
    def line_count(self) -> int:
        return len(self.lines)

    def line_for(self, pattern: str) -> int | None:
        expression = re.compile(pattern, re.IGNORECASE)
        for number, line in enumerate(self.lines, 1):
            if expression.search(line):
                return number
        return None


class _GraphBuilder:
    def __init__(
        self,
        *,
        artifact_sha256: str,
        source_identity: str,
        analysis_run_id: str,
        coverage: MobileSourceHuntCoverage,
    ) -> None:
        self.artifact_sha256 = artifact_sha256
        self.source_identity = source_identity
        self.analysis_run_id = analysis_run_id
        self.coverage = coverage
        self.nodes: dict[tuple[str, str, str], MobileGraphNode] = {}
        self.edges: dict[tuple[str, str, str], MobileGraphEdge] = {}

    def provenance(
        self,
        *,
        source: _SourceFile | None = None,
        line: int | None = None,
        confidence: str = "confirmed",
        evidence_references: Iterable[str] = (),
    ) -> MobileGraphProvenance:
        return MobileGraphProvenance(
            artifact_sha256=self.artifact_sha256,
            source_identity=self.source_identity,
            source_path=source.path if source else None,
            source_sha256=source.sha256 if source else None,
            line_start=line,
            line_end=line,
            analysis_run_id=self.analysis_run_id,
            confidence=confidence,
            coverage=self.coverage.status,
            evidence_references=tuple(dict.fromkeys(evidence_references)),
        )

    def node(
        self,
        *,
        node_type: MobileGraphNodeType,
        label: str,
        ownership: MobileOwnership = MobileOwnership.UNKNOWN,
        state: MobileSourceHuntState | None = None,
        evidence_references: Iterable[str] = (),
        provenance: Iterable[MobileGraphProvenance] = (),
        attributes: Mapping[str, object] | None = None,
    ) -> MobileGraphNode:
        key = (node_type.value, label, ownership.value)
        existing = self.nodes.get(key)
        if existing is not None:
            merged_evidence = tuple(
                dict.fromkeys((*existing.evidence_references, *evidence_references))
            )
            merged_provenance = tuple(dict.fromkeys((*existing.provenance, *provenance)))
            merged_attributes = dict(existing.attributes)
            merged_attributes.update(attributes or {})
            replacement = existing.model_copy(
                update={
                    "state": state or existing.state,
                    "evidence_references": merged_evidence,
                    "provenance": merged_provenance,
                    "attributes": merged_attributes,
                }
            )
            self.nodes[key] = replacement
            return replacement
        node_id = f"mnode-{hashlib.sha256(json.dumps(key).encode()).hexdigest()[:24]}"
        value = MobileGraphNode(
            node_id=node_id,
            node_type=node_type,
            label=label,
            ownership=ownership,
            state=state,
            evidence_references=tuple(dict.fromkeys(evidence_references)),
            provenance=tuple(dict.fromkeys(provenance)),
            attributes=dict(attributes or {}),
        )
        self.nodes[key] = value
        return value

    def edge(
        self,
        *,
        source: MobileGraphNode,
        target: MobileGraphNode,
        relation: MobileGraphEdgeType,
        confidence: str = "confirmed",
        state: MobileSourceHuntState | None = None,
        evidence_references: Iterable[str] = (),
        provenance: Iterable[MobileGraphProvenance] = (),
        attributes: Mapping[str, object] | None = None,
    ) -> MobileGraphEdge:
        key = (source.node_id, target.node_id, relation.value)
        existing = self.edges.get(key)
        if existing is not None:
            merged_evidence = tuple(
                dict.fromkeys((*existing.evidence_references, *evidence_references))
            )
            merged_provenance = tuple(dict.fromkeys((*existing.provenance, *provenance)))
            merged_attributes = dict(existing.attributes)
            merged_attributes.update(attributes or {})
            replacement = existing.model_copy(
                update={
                    "state": state or existing.state,
                    "confidence": confidence,
                    "evidence_references": merged_evidence,
                    "provenance": merged_provenance,
                    "attributes": merged_attributes,
                }
            )
            self.edges[key] = replacement
            return replacement
        edge_id = f"medge-{hashlib.sha256(json.dumps(key).encode()).hexdigest()[:24]}"
        value = MobileGraphEdge(
            edge_id=edge_id,
            source_node_id=source.node_id,
            target_node_id=target.node_id,
            relation=relation,
            confidence=confidence,
            state=state,
            evidence_references=tuple(dict.fromkeys(evidence_references)),
            provenance=tuple(dict.fromkeys(provenance)),
            attributes=dict(attributes or {}),
        )
        self.edges[key] = value
        return value

    def build(self) -> MobileAttackGraph:
        nodes = tuple(sorted(self.nodes.values(), key=lambda item: item.node_id))
        edges = tuple(sorted(self.edges.values(), key=lambda item: item.edge_id))
        payload = {
            "artifact_sha256": self.artifact_sha256,
            "source_identity": self.source_identity,
            "analysis_run_id": self.analysis_run_id,
            "nodes": [item.model_dump(mode="json") for item in nodes],
            "edges": [item.model_dump(mode="json") for item in edges],
            "coverage": self.coverage.model_dump(mode="json"),
        }
        graph_sha256 = sha256_json(payload)
        return MobileAttackGraph(
            graph_id=f"source-mobile-graph-{graph_sha256[:24]}",
            artifact_sha256=self.artifact_sha256,
            source_identity=self.source_identity,
            analysis_run_id=self.analysis_run_id,
            nodes=nodes,
            edges=edges,
            coverage=self.coverage,
            graph_sha256=graph_sha256,
        )


class MobileSourceHuntEngine:
    """Run bounded deterministic Source Hunt against a retained APK source tree."""

    def __init__(
        self,
        *,
        source_root: Path,
        intelligence: Mapping[str, object],
        analysis_run_id: str,
        max_source_files: int = 25_000,
        max_seed_count: int = 64,
        selected_seed_ids: Iterable[str] | None = None,
    ) -> None:
        self.source_root = source_root.expanduser().resolve(strict=True)
        self.intelligence = intelligence
        self.analysis_run_id = analysis_run_id
        self.max_source_files = max_source_files
        self.max_seed_count = max_seed_count
        self.selected_seed_ids = frozenset(
            str(item).strip() for item in (selected_seed_ids or ()) if str(item).strip()
        )
        self._files: tuple[_SourceFile, ...] = ()
        self._by_name: dict[str, tuple[_SourceFile, ...]] = {}

    def available_seeds(self) -> tuple[MobileSourceHuntSeed, ...]:
        """Return deterministic seed identities for a governed selection check."""
        self._load_source_files()
        return self._seeds()

    def run(self) -> MobileSourceHuntReport:
        artifact_sha256 = str(self.intelligence.get("artifact_sha256") or "")
        if _SHA256.fullmatch(artifact_sha256) is None:
            raise ValueError("Source Hunt requires the intelligence artifact SHA-256")
        self._load_source_files()
        coverage = self._coverage()
        source_identity = self._source_identity()
        graph = _GraphBuilder(
            artifact_sha256=artifact_sha256,
            source_identity=source_identity,
            analysis_run_id=self.analysis_run_id,
            coverage=coverage,
        )
        artifact_node = graph.node(
            node_type=MobileGraphNodeType.ARTIFACT,
            label=f"APK {artifact_sha256[:16]}",
            state=MobileSourceHuntState.VERIFIED,
            evidence_references=(f"artifact:{artifact_sha256}",),
            provenance=(graph.provenance(evidence_references=(f"artifact:{artifact_sha256}",)),),
        )
        seeds = self._seeds()
        if self.selected_seed_ids:
            available = {seed.seed_id for seed in seeds}
            unknown = self.selected_seed_ids - available
            if unknown:
                raise ValueError("Source Hunt selection contains an unknown persisted seed")
            seeds = tuple(seed for seed in seeds if seed.seed_id in self.selected_seed_ids)
        results: list[MobileSourceHuntResult] = []
        for seed in seeds:
            result = self._investigate(seed, graph, artifact_node, coverage)
            results.append(result)
        built_graph = graph.build()
        report_seed = {
            "artifact_sha256": artifact_sha256,
            "source_identity": source_identity,
            "analysis_run_id": self.analysis_run_id,
            "graph_sha256": built_graph.graph_sha256,
            "seed_ids": [item.seed.seed_id for item in results],
        }
        report_id = f"source-mobile-report-{sha256_json(report_seed)[:24]}"
        return MobileSourceHuntReport(
            report_id=report_id,
            artifact_id=str(self.intelligence.get("artifact_id") or f"apk-{artifact_sha256[:24]}"),
            artifact_sha256=artifact_sha256,
            source_identity=source_identity,
            analysis_run_id=self.analysis_run_id,
            coverage=coverage,
            seeds_examined=len(results),
            results=tuple(results),
            graph=built_graph,
            verified_finding_count=sum(item.verified_finding for item in results),
            rejected_count=sum(item.state == MobileSourceHuntState.REJECTED for item in results),
            inconclusive_count=sum(
                item.state == MobileSourceHuntState.INCONCLUSIVE for item in results
            ),
            evidence_required_count=sum(
                item.state == MobileSourceHuntState.EVIDENCE_REQUIRED for item in results
            ),
            blocked_count=sum(item.state == MobileSourceHuntState.BLOCKED for item in results),
            created_at=datetime.now(UTC),
        )

    def _load_source_files(self) -> None:
        files: list[_SourceFile] = []
        by_name: dict[str, list[_SourceFile]] = {}
        for path in sorted(self.source_root.rglob("*")):
            if len(files) >= self.max_source_files:
                break
            if (
                not path.is_file()
                or path.is_symlink()
                or path.suffix.casefold() not in _DEFAULT_EXTENSIONS
            ):
                continue
            try:
                stat = path.stat()
                if stat.st_size > _MAX_SOURCE_FILE_BYTES:
                    continue
                raw = path.read_bytes()
            except OSError:
                continue
            relative = path.relative_to(self.source_root).as_posix()
            source = _SourceFile(
                path=relative,
                absolute=path,
                raw=raw,
                sha256=hashlib.sha256(raw).hexdigest(),
            )
            files.append(source)
            by_name.setdefault(path.name, []).append(source)
        self._files = tuple(files)
        self._by_name = {key: tuple(value) for key, value in by_name.items()}

    def _source_identity(self) -> str:
        payload = [(item.path, item.sha256, len(item.raw)) for item in self._files]
        return sha256_json(payload)

    def _coverage(self) -> MobileSourceHuntCoverage:
        intelligence_coverage = self.intelligence.get("coverage")
        limitations: list[str] = []
        references: list[str] = []
        status = "complete"
        if isinstance(intelligence_coverage, Mapping):
            capabilities = intelligence_coverage.get("capabilities")
            for item in capabilities if isinstance(capabilities, list) else ():
                if not isinstance(item, Mapping):
                    continue
                capability_status = str(item.get("status") or "")
                if capability_status in {"partial", "blocked", "not_applicable"}:
                    status = "partial" if capability_status == "partial" else status
                    detail = str(item.get("detail") or capability_status)
                    limitations.append(f"{item.get('capability', 'capability')}: {detail}")
                references.extend(str(ref) for ref in item.get("evidence_references", ()) if ref)
        if not self._files:
            if status == "complete":
                status = "unavailable"
            limitations.append("No retained source files were available for Source Hunt.")
        return MobileSourceHuntCoverage(
            status=status,
            source_file_count=len(self._files),
            source_bytes=sum(len(item.raw) for item in self._files),
            limitations=tuple(dict.fromkeys(limitations)),
            evidence_references=tuple(dict.fromkeys(references)),
        )

    def _seeds(self) -> tuple[MobileSourceHuntSeed, ...]:
        seeds: list[MobileSourceHuntSeed] = []
        components = self.intelligence.get("exported_component_surfaces")
        for item in components if isinstance(components, list) else ():
            if (
                not isinstance(item, Mapping)
                or item.get("ownership") != MobileOwnership.APP_OWNED.value
            ):
                continue
            name = str(item.get("name") or "")
            if not name:
                continue
            seed_key = {
                "type": "component",
                "name": name,
                "artifact": self.intelligence.get("artifact_sha256"),
            }
            seeds.append(
                MobileSourceHuntSeed(
                    seed_id=f"seed-{sha256_json(seed_key)[:24]}",
                    seed_type="component",
                    title=f"Investigate exported component {name}",
                    weakness_id="android-exported-component",
                    component_name=name,
                    ownership=MobileOwnership.APP_OWNED,
                    evidence_references=tuple(
                        str(ref) for ref in item.get("evidence_references", ()) if ref
                    ),
                    source_intelligence_record_id=str(item.get("component_id") or "") or None,
                    attributes={
                        "kind": item.get("kind"),
                        "permission": item.get("permission"),
                        "intent_filters": item.get("intent_filters", []),
                    },
                )
            )
        observations = self.intelligence.get("verified_configurations")
        for item in observations if isinstance(observations, list) else ():
            if not isinstance(item, Mapping):
                continue
            weakness = str(item.get("weakness_id") or "")
            if weakness not in {"android-cleartext-traffic", "android-exported-component"}:
                continue
            seed_key = {"type": "configuration", "record": item.get("record_id")}
            seeds.append(
                MobileSourceHuntSeed(
                    seed_id=f"seed-{sha256_json(seed_key)[:24]}",
                    seed_type="configuration",
                    title=str(item.get("title") or weakness),
                    weakness_id=weakness,
                    ownership=MobileOwnership(str(item.get("ownership") or "unknown")),
                    evidence_references=tuple(
                        str(ref) for ref in item.get("evidence_references", ()) if ref
                    ),
                    source_intelligence_record_id=str(item.get("record_id") or "") or None,
                    attributes={"security_property": item.get("security_property")},
                )
            )
        candidates = self.intelligence.get("candidates")
        for item in candidates if isinstance(candidates, list) else ():
            if not isinstance(item, Mapping):
                continue
            weakness = str(item.get("weakness_id") or "")
            title = str(item.get("title") or "")
            candidate_text = f"{weakness} {title}".casefold()
            if not any(
                token in candidate_text for token in ("webview", "dynamic", "endpoint", "loader")
            ):
                continue

            seed_key = {"type": "candidate", "record": item.get("record_id"), "weakness": weakness}
            seeds.append(
                MobileSourceHuntSeed(
                    seed_id=f"seed-{sha256_json(seed_key)[:24]}",
                    seed_type="candidate",
                    title=str(item.get("title") or weakness or "APK candidate"),
                    weakness_id=weakness or None,
                    ownership=MobileOwnership(str(item.get("ownership") or "unknown")),
                    evidence_references=tuple(
                        str(ref) for ref in item.get("evidence_references", ()) if ref
                    ),
                    source_intelligence_record_id=str(item.get("record_id") or "") or None,
                    attributes={"security_property": item.get("security_property")},
                )
            )
        unique: dict[str, MobileSourceHuntSeed] = {}
        for seed in seeds:
            unique.setdefault(seed.seed_id, seed)
        return tuple(unique.values())[: self.max_seed_count]

    def _investigate(
        self,
        seed: MobileSourceHuntSeed,
        graph: _GraphBuilder,
        artifact_node: MobileGraphNode,
        coverage: MobileSourceHuntCoverage,
    ) -> MobileSourceHuntResult:
        seed_node = graph.node(
            node_type=(
                MobileGraphNodeType.COMPONENT
                if seed.seed_type == "component"
                else MobileGraphNodeType.OBSERVATION
            ),
            label=seed.title,
            ownership=seed.ownership,
            state=MobileSourceHuntState.EVIDENCE_REQUIRED,
            evidence_references=seed.evidence_references,
            provenance=(
                graph.provenance(
                    confidence="confirmed",
                    evidence_references=seed.evidence_references,
                ),
            ),
            attributes=seed.attributes,
        )
        graph.edge(
            source=artifact_node,
            target=seed_node,
            relation=MobileGraphEdgeType.EVIDENCE_FOR,
            evidence_references=seed.evidence_references,
            provenance=(graph.provenance(evidence_references=seed.evidence_references),),
        )
        if seed.seed_type == "component":
            return self._investigate_component(seed, seed_node, graph, coverage)
        if seed.weakness_id == "android-cleartext-traffic":
            return self._investigate_cleartext(seed, seed_node, graph, coverage)
        if (
            "dynamic" in (seed.weakness_id or "").casefold()
            or "endpoint" in (seed.weakness_id or "").casefold()
        ):
            return self._investigate_dynamic_endpoint(seed, seed_node, graph, coverage)
        return self._investigate_bounded_candidate(seed, seed_node, graph, coverage)

    def _investigate_component(
        self,
        seed: MobileSourceHuntSeed,
        seed_node: MobileGraphNode,
        graph: _GraphBuilder,
        coverage: MobileSourceHuntCoverage,
    ) -> MobileSourceHuntResult:
        simple_name = (seed.component_name or "").rsplit(".", 1)[-1]
        source = self._find_class_source(simple_name)
        if source is None:
            state = (
                MobileSourceHuntState.INCONCLUSIVE
                if coverage.status == "partial"
                else MobileSourceHuntState.EVIDENCE_REQUIRED
            )
            missing = (
                "The retained partial source tree does not contain the component implementation.",
                "Intent-to-sink data flow and guard coverage remain unresolved.",
            )
            return MobileSourceHuntResult(
                seed=seed,
                state=state,
                summary=(
                    f"{seed.component_name} is manifest-resolved and app-owned, but its "
                    "implementation was not present in the retained source tree. No "
                    "vulnerability was promoted."
                ),
                entry_point=seed.component_name,
                missing_evidence=missing,
                graph_node_ids=(seed_node.node_id,),
                bounded_negative=coverage.status == "partial",
                deterministic_validation=(
                    "Manifest ownership/exported state was verified; source path "
                    "resolution was not."
                ),
            )
        source_node = graph.node(
            node_type=MobileGraphNodeType.SOURCE_FILE,
            label=source.path,
            ownership=seed.ownership,
            state=MobileSourceHuntState.EVIDENCE_REQUIRED,
            provenance=(
                graph.provenance(
                    source=source, line=1, evidence_references=seed.evidence_references
                ),
            ),
        )
        resolved_edge = graph.edge(
            source=seed_node,
            target=source_node,
            relation=MobileGraphEdgeType.RESOLVES_TO,
            evidence_references=seed.evidence_references,
            provenance=(
                graph.provenance(
                    source=source, line=1, evidence_references=seed.evidence_references
                ),
            ),
        )
        sources = tuple(
            sorted(
                {
                    name
                    for name in ("getIntent", "getData", "getStringExtra", "getExtras")
                    if re.search(rf"\b{re.escape(name)}\s*\(", source.text)
                }
            )
        )
        sinks = tuple(
            sorted(
                {
                    name
                    for name in (
                        "loadUrl",
                        "evaluateJavascript",
                        "addJavascriptInterface",
                        "startActivity",
                        "startService",
                        "sendBroadcast",
                    )
                    if re.search(rf"\.{re.escape(name)}\s*\(", source.text)
                }
            )
        )
        controls = tuple(
            sorted(
                {
                    marker
                    for marker in (
                        "https",
                        "allowlist",
                        "validate",
                        "signature",
                        "nonce",
                        "auth",
                        "permission",
                        "checkCalling",
                    )
                    if marker.casefold() in source.text.casefold()
                }
            )
        )
        node_ids = [seed_node.node_id, source_node.node_id]
        edge_ids = [resolved_edge.edge_id]
        if sources:
            source_value = graph.node(
                node_type=MobileGraphNodeType.SOURCE,
                label=", ".join(sources),
                ownership=seed.ownership,
                state=MobileSourceHuntState.EVIDENCE_REQUIRED,
                provenance=(
                    graph.provenance(
                        source=source,
                        line=source.line_for(sources[0]),
                        evidence_references=seed.evidence_references,
                    ),
                ),
            )
            source_edge = graph.edge(
                source=source_node,
                target=source_value,
                relation=MobileGraphEdgeType.RECEIVES,
                provenance=(
                    graph.provenance(
                        source=source,
                        line=source.line_for(sources[0]),
                        evidence_references=seed.evidence_references,
                    ),
                ),
            )
            node_ids.append(source_value.node_id)
            edge_ids.append(source_edge.edge_id)
        if sinks:
            sink_value = graph.node(
                node_type=MobileGraphNodeType.SECURITY_SINK,
                label=", ".join(sinks),
                ownership=seed.ownership,
                state=MobileSourceHuntState.EVIDENCE_REQUIRED,
                provenance=(
                    graph.provenance(
                        source=source,
                        line=source.line_for(sinks[0]),
                        evidence_references=seed.evidence_references,
                    ),
                ),
            )
            sink_edge = graph.edge(
                source=source_node,
                target=sink_value,
                relation=MobileGraphEdgeType.FLOWS_TO,
                state=MobileSourceHuntState.EVIDENCE_REQUIRED,
                provenance=(
                    graph.provenance(
                        source=source,
                        line=source.line_for(sinks[0]),
                        evidence_references=seed.evidence_references,
                    ),
                ),
            )
            node_ids.append(sink_value.node_id)
            edge_ids.append(sink_edge.edge_id)
        if sources and sinks and not controls:
            state = MobileSourceHuntState.EVIDENCE_REQUIRED
            summary = (
                "Source and sink symbols were found, but no deterministic guard was observed "
                "in the bounded file review."
            )
            missing = ("Complete interprocedural path and authentication/authorization coverage.",)
        elif sources and sinks:
            state = MobileSourceHuntState.INCONCLUSIVE
            summary = (
                "Source and sink symbols were found with guard-like code, but bounded static "
                "review cannot prove all paths are protected."
            )
            missing = ("Complete path coverage and a deterministic guard test.",)
        else:
            state = (
                MobileSourceHuntState.INCONCLUSIVE
                if coverage.status == "partial"
                else MobileSourceHuntState.EVIDENCE_REQUIRED
            )
            summary = (
                "The implementation source was resolved, but a complete source-to-sensitive-sink "
                "path was not established."
            )
            missing = (
                "A complete attacker-input to sensitive-sink path and deterministic validation.",
            )
        return MobileSourceHuntResult(
            seed=seed,
            state=state,
            summary=summary,
            entry_point=seed.component_name,
            source_symbols=sources,
            sink_symbols=sinks,
            controls_observed=controls,
            missing_evidence=missing,
            source_references=(
                SourceReference(
                    path=source.path,
                    source_sha256=source.sha256,
                    line_start=1,
                    line_end=max(1, source.line_count),
                    symbol=simple_name,
                ),
            ),
            graph_node_ids=tuple(node_ids),
            graph_edge_ids=tuple(edge_ids),
            bounded_negative=coverage.status == "partial",
            deterministic_validation=(
                "Lexical source/sink/guard correlation only; no runtime execution or exploit "
                "test performed."
            ),
        )

    def _investigate_cleartext(
        self,
        seed: MobileSourceHuntSeed,
        seed_node: MobileGraphNode,
        graph: _GraphBuilder,
        coverage: MobileSourceHuntCoverage,
    ) -> MobileSourceHuntResult:
        http_endpoints = [
            item
            for item in self.intelligence.get("endpoint_references", [])
            if isinstance(item, Mapping) and str(item.get("protocol") or "").casefold() == "http"
        ]
        source = self._find_named_source(("HttpUrlDefines.java", "OkHttpUtil.java"))
        node_ids = [seed_node.node_id]
        edge_ids: list[str] = []
        source_refs: list[SourceReference] = []
        source_symbols = ("android:usesCleartextTraffic=true",)
        sink_symbols = ("HTTP endpoint reference",)
        if source is not None:
            line = source.line_for(r"http://") or 1
            source_node = graph.node(
                node_type=MobileGraphNodeType.SOURCE_FILE,
                label=source.path,
                ownership=MobileOwnership.APP_OWNED,
                state=MobileSourceHuntState.EVIDENCE_REQUIRED,
                provenance=(
                    graph.provenance(
                        source=source, line=line, evidence_references=seed.evidence_references
                    ),
                ),
            )
            edge = graph.edge(
                source=seed_node,
                target=source_node,
                relation=MobileGraphEdgeType.RESOLVES_TO,
                provenance=(
                    graph.provenance(
                        source=source, line=line, evidence_references=seed.evidence_references
                    ),
                ),
            )
            node_ids.append(source_node.node_id)
            edge_ids.append(edge.edge_id)
            source_refs.append(
                SourceReference(
                    path=source.path,
                    source_sha256=source.sha256,
                    line_start=line,
                    line_end=line,
                    symbol="HTTP endpoint literal",
                )
            )
        endpoint_nodes = []
        for item in http_endpoints[:24]:
            label = str(
                item.get("normalized_endpoint") or item.get("endpoint") or "unknown HTTP endpoint"
            )
            endpoint_node = graph.node(
                node_type=MobileGraphNodeType.NETWORK_ENDPOINT,
                label=label,
                ownership=MobileOwnership(str(item.get("ownership") or "unknown")),
                state=MobileSourceHuntState.EVIDENCE_REQUIRED,
                evidence_references=tuple(
                    str(ref) for ref in item.get("evidence_references", ()) if ref
                ),
                attributes={"likely_role": item.get("likely_role"), "reachability": "unknown"},
                provenance=(
                    graph.provenance(
                        confidence=str(item.get("confidence") or "confirmed"),
                        evidence_references=tuple(
                            str(ref) for ref in item.get("evidence_references", ()) if ref
                        ),
                    ),
                ),
            )
            endpoint_nodes.append(endpoint_node)
            node_ids.append(endpoint_node.node_id)
            if source is not None:
                edge_ids.append(
                    graph.edge(
                        source=source_node,
                        target=endpoint_node,
                        relation=MobileGraphEdgeType.LOADS_URL,
                        state=MobileSourceHuntState.EVIDENCE_REQUIRED,
                        confidence=str(item.get("confidence") or "confirmed"),
                        evidence_references=tuple(
                            str(ref) for ref in item.get("evidence_references", ()) if ref
                        ),
                        attributes={"likely_role": item.get("likely_role")},
                    ).edge_id
                )
        return MobileSourceHuntResult(
            seed=seed,
            state=MobileSourceHuntState.EVIDENCE_REQUIRED,
            summary=(
                f"Verified cleartext configuration is corroborated by {len(http_endpoints)} "
                "normalized HTTP endpoint references. Source Hunt did not claim live "
                "reachability or interception."
            ),
            source_symbols=source_symbols,
            sink_symbols=sink_symbols,
            controls_observed=("manifest cleartext policy",),
            missing_evidence=(
                "Request-builder and response-consumer path coverage for each service family.",
            ),
            source_references=tuple(source_refs),
            graph_node_ids=tuple(node_ids),
            graph_edge_ids=tuple(edge_ids),
            bounded_negative=coverage.status == "partial",
            deterministic_validation=(
                "Manifest configuration plus normalized static endpoint inventory; no network "
                "requests performed."
            ),
            remediation=(
                "Prefer HTTPS-only transport and validate any dynamic host, scheme, redirect, "
                "and authenticated configuration source."
            ),
        )

    def _investigate_dynamic_endpoint(
        self,
        seed: MobileSourceHuntSeed,
        seed_node: MobileGraphNode,
        graph: _GraphBuilder,
        coverage: MobileSourceHuntCoverage,
    ) -> MobileSourceHuntResult:
        source = self._find_named_source(
            ("GlobalDefines.java", "GlobalConfiguration.java", "OkHttpUtil.java")
        )
        if source is None:
            return MobileSourceHuntResult(
                seed=seed,
                state=MobileSourceHuntState.INCONCLUSIVE,
                summary=(
                    "Dynamic endpoint assignment remains evidence-required because the retained "
                    "source file was not available."
                ),
                missing_evidence=(
                    "Configuration origin, validation, allowlist, and downstream request "
                    "construction.",
                ),
                graph_node_ids=(seed_node.node_id,),
                bounded_negative=coverage.status == "partial",
            )
        assign_line = source.line_for(r"sDynamicAssign|sAssign") or 1
        source_node = graph.node(
            node_type=MobileGraphNodeType.SOURCE_FILE,
            label=source.path,
            ownership=MobileOwnership.APP_OWNED,
            state=MobileSourceHuntState.EVIDENCE_REQUIRED,
            provenance=(
                graph.provenance(
                    source=source, line=assign_line, evidence_references=seed.evidence_references
                ),
            ),
        )
        assignment_node = graph.node(
            node_type=MobileGraphNodeType.TRANSFORMATION,
            label="network-derived endpoint assignment",
            ownership=MobileOwnership.APP_OWNED,
            state=MobileSourceHuntState.EVIDENCE_REQUIRED,
            provenance=(
                graph.provenance(
                    source=source, line=assign_line, evidence_references=seed.evidence_references
                ),
            ),
        )
        source_edge = graph.edge(
            source=seed_node,
            target=source_node,
            relation=MobileGraphEdgeType.RESOLVES_TO,
            provenance=(
                graph.provenance(
                    source=source, line=assign_line, evidence_references=seed.evidence_references
                ),
            ),
        )
        assignment_edge = graph.edge(
            source=source_node,
            target=assignment_node,
            relation=MobileGraphEdgeType.ASSIGNS_TO,
            state=MobileSourceHuntState.EVIDENCE_REQUIRED,
            provenance=(
                graph.provenance(
                    source=source, line=assign_line, evidence_references=seed.evidence_references
                ),
            ),
        )
        return MobileSourceHuntResult(
            seed=seed,
            state=MobileSourceHuntState.EVIDENCE_REQUIRED,
            summary=(
                "App-owned dynamic endpoint assignment symbols were found, but origin validation "
                "and complete downstream request paths require further source coverage."
            ),
            source_symbols=("network/configuration response",),
            sink_symbols=("sDynamicAssign*", "downstream network request"),
            controls_observed=tuple(
                marker
                for marker in ("signature", "allowlist", "https", "authentication")
                if marker.casefold() in source.text.casefold()
            ),
            missing_evidence=(
                "Configuration origin and transport authentication.",
                "Signature or integrity validation.",
                "Scheme/host/port allowlist enforcement.",
                "Complete downstream service-specific request path.",
            ),
            source_references=(
                SourceReference(
                    path=source.path,
                    source_sha256=source.sha256,
                    line_start=assign_line,
                    line_end=min(source.line_count, assign_line + 8),
                    symbol="sDynamicAssign",
                ),
            ),
            graph_node_ids=(seed_node.node_id, source_node.node_id, assignment_node.node_id),
            graph_edge_ids=(source_edge.edge_id, assignment_edge.edge_id),
            bounded_negative=coverage.status == "partial",
            deterministic_validation=(
                "Static symbol and assignment correlation only; no endpoint contact or runtime "
                "execution."
            ),
            remediation=(
                "Validate dynamically assigned schemes, hosts, ports, redirects, integrity, "
                "and authenticated configuration before use."
            ),
        )

    def _investigate_bounded_candidate(
        self,
        seed: MobileSourceHuntSeed,
        seed_node: MobileGraphNode,
        graph: _GraphBuilder,
        coverage: MobileSourceHuntCoverage,
    ) -> MobileSourceHuntResult:
        return MobileSourceHuntResult(
            seed=seed,
            state=MobileSourceHuntState.INCONCLUSIVE,
            summary=(
                "The candidate is retained as an evidence-required Source Hunt seed; the "
                "available partial source does not establish a verified path."
            ),
            missing_evidence=(
                "App-owned source path, security-sensitive sink, effective controls, and "
                "deterministic validation.",
            ),
            graph_node_ids=(seed_node.node_id,),
            bounded_negative=coverage.status == "partial",
            deterministic_validation=(
                "Candidate provenance was preserved without promoting the discovery signal."
            ),
        )

    def _find_class_source(self, simple_name: str) -> _SourceFile | None:
        matches = self._by_name.get(f"{simple_name}.java", ())
        if matches:
            return matches[0]
        pattern = re.compile(rf"\bclass\s+{re.escape(simple_name)}\b")
        return next((item for item in self._files if pattern.search(item.text)), None)

    def _find_named_source(self, names: tuple[str, ...]) -> _SourceFile | None:
        for name in names:
            matches = self._by_name.get(name, ())
            app_owned = tuple(
                item for item in matches if "/com/macrovideo/v380pro/" in f"/{item.path}"
            )
            if app_owned:
                return app_owned[0]
            if matches:
                return matches[0]
        for item in self._files:
            if any(name.removesuffix(".java") in item.text for name in names):
                return item
        return None


class MobileSourceHuntStore:
    """Atomic persistence for APK Source Hunt reports, separate from remote Groq jobs."""

    def __init__(self, root: Path) -> None:
        self.root = root.expanduser().resolve()

    def save(self, report: MobileSourceHuntReport) -> Path:
        self.root.mkdir(parents=True, exist_ok=True)
        destination = self.root / f"{report.report_id}.json"
        payload = json.dumps(report.model_dump(mode="json"), sort_keys=True, indent=2) + "\n"
        if destination.exists():
            existing = MobileSourceHuntReport.model_validate_json(
                destination.read_text(encoding="utf-8")
            )
            if existing != report:
                raise ValueError(
                    "mobile Source Hunt report identifier already contains different evidence"
                )
            return destination
        temporary = destination.with_suffix(".json.tmp")
        temporary.write_text(payload, encoding="utf-8")
        temporary.replace(destination)
        return destination

    def load(self, report_id: str) -> MobileSourceHuntReport:
        if (
            not report_id.startswith("source-mobile-report-")
            or "/" in report_id
            or "\\" in report_id
        ):
            raise ValueError("mobile Source Hunt report identifier is invalid")
        return MobileSourceHuntReport.model_validate_json(
            (self.root / f"{report_id}.json").read_text(encoding="utf-8")
        )
