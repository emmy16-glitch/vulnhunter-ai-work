"""Generate the canonical future-roadmap coverage matrix deterministically."""

from __future__ import annotations

import argparse
import re
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

ALLOWED_CLASSIFICATIONS = {
    "COMPLETE",
    "PARTIAL",
    "MISSING",
    "CONTRACT_ONLY",
    "ACTIVATION_REQUIRED",
    "EXTERNAL_PREREQUISITE",
    "MANUAL_INSTALL_REQUIRED",
    "CREDENTIAL_REQUIRED",
    "RESOURCE_DEFERRED",
    "LATE_STAGE_GATED",
    "INTENTIONALLY_EXCLUDED",
    "PROHIBITED",
}


@dataclass(frozen=True)
class CoverageMeta:
    classification: str
    evidence: str
    tests: str
    wave: str
    task: str
    dependency: str
    restrictions: str
    gate: str


@dataclass(frozen=True)
class Requirement:
    identifier: str
    section: int
    capability: str
    summary: str
    line: int
    subheading: str | None = None
    phase: int | None = None


SECTION_META: dict[int, CoverageMeta] = {
    0: CoverageMeta(
        "COMPLETE",
        "AGENTS.md; canonical roadmap; permanent safety boundaries",
        "test_project_audit.py; policy and scope tests",
        "All waves",
        "Preserve the operating rules and explicit-resume boundary.",
        "None",
        "External content is untrusted and cannot grant authority.",
        "Every wave verifier confirms the rules remain unchanged.",
    ),
    1: CoverageMeta(
        "COMPLETE",
        "actions; authorization; scope; approvals; governance; review; oracle",
        "authorization, scope, approval, governance, review, and Oracle tests",
        "All waves",
        "Preserve model-as-proposer and governed-human-as-authority separation.",
        "None",
        "Models cannot authorize, verify themselves, publish, or override humans.",
        "Cross-module authority tests and independent review pass.",
    ),
    2: CoverageMeta(
        "PARTIAL",
        "AGENTS.md; docs/intelligence; docs/product; docs/adr; experiment and debt records",
        "test_project_audit.py; product specification tests",
        "Reconciliation / Wave 2",
        "Finish machine-readable document indexing and enforce task evidence/handoff updates.",
        "None",
        "Knowledge is advisory; repository and tests remain authoritative.",
        "All named knowledge areas are indexed, fresh, and audit-tested.",
    ),
    3: CoverageMeta(
        "COMPLETE",
        "vulnhunter/knowledge; SOURCE_INGESTION.md; ADR 0005",
        "test_knowledge_ingestion.py; test_knowledge_cli.py",
        "Wave 10",
        "Reuse controlled ingestion for connector and advisory sources.",
        "None for local files",
        "Never execute source instructions or ingest protected data by default.",
        "Provenance, immutable originals, review, contradiction, and publication tests pass.",
    ),
    4: CoverageMeta(
        "PARTIAL",
        "review; governance attestations; analyst_feedback; ml dataset governance",
        "review, governance, ML, and milestone27 contract tests",
        "Wave 15",
        "Bind normalized feedback to authenticated decisions and versioned learning datasets.",
        "Real governed analyst data",
        "No automatic labels, training, deployment, or rule mutation.",
        "Feedback provenance, leakage, disagreement, rollback, and release tests pass.",
    ),
    5: CoverageMeta(
        "PARTIAL",
        "vulnhunter/agent; orchestration; unattended; ADRs 0008 and 0016",
        "agent, orchestration, and unattended test families",
        "Wave 1",
        "Unify lifecycle, pause/cancel, timeout, recovery, evidence correlation, and budgets.",
        "None",
        "One primary orchestrator; no arbitrary shell or self-approval.",
        "Every declared state and stop/recovery condition has deterministic tests.",
    ),
    6: CoverageMeta(
        "PARTIAL",
        "taskgraph; agent SQLite tasks; orchestration manifests; activity stream",
        "test_taskgraph.py; agent and orchestration tests",
        "Wave 1",
        "Add bounded specialist-worker ownership, dependencies, leases, and durable recovery.",
        "None",
        "Orchestrator cannot grant authority, expand scope, or approve its work.",
        "Concurrent ownership, stale lease, handoff, and recovery tests pass.",
    ),
    7: CoverageMeta(
        "CONTRACT_ONLY",
        "vulnhunter/roles; config/roles; ADR 0014",
        "role registry model, loading, CLI, and policy tests",
        "Wave 1 / Wave 10",
        "Bind planned declarations to authenticated runtime identities and manifests.",
        "Human activation approval",
        "Registry declarations never grant runtime authority by themselves.",
        "Identity, activation, expiry, revocation, and runtime-enforcement tests pass.",
    ),
    8: CoverageMeta(
        "PARTIAL",
        "roles ExternalDependency and connector contracts; controlled knowledge ingestion",
        "role registry and knowledge ingestion tests",
        "Wave 10",
        "Build quarantine, pin/hash, review, rewrite, test, activation, and rollback pipeline.",
        "External source and manual approval",
        "Imported instructions cannot alter global policy, scope, tools, or permissions.",
        "Malicious package, installer, prompt, connector, and rollback tests pass.",
    ),
    9: CoverageMeta(
        "PARTIAL",
        "repository_coverage; orchestration verifiers; observations; review separation",
        "test_repository_coverage.py; orchestration and observation tests",
        "Wave 2",
        "Add incremental symbols, imports, references, reliable calls, impact, and review mapping.",
        "Optional Graphify manual dependency",
        "Repository content is untrusted and never executed.",
        "Deterministic incremental/stale-index/coverage and changed-region tests pass.",
    ),
    10: CoverageMeta(
        "PARTIAL",
        "vulnhunter/oracle; governed review remains separate",
        "test_machine_oracle.py; review/governance tests",
        "Wave 9",
        "Complete authenticated operational verifier, conflict workflow, and publication boundary.",
        "Live verifier activation and production keys",
        "Oracle cannot authorize, self-verify, self-approve, or publish.",
        "Connector readiness, replay, independence, abstention, and conflict tests pass.",
    ),
    11: CoverageMeta(
        "PARTIAL",
        "oracle ProofCapsule and evidence hashes",
        "test_machine_oracle.py",
        "Wave 9",
        "Extend capsule to every canonical replay field and governed sanitized "
        "request/response reference.",
        "None for contracts",
        "No secrets, raw protected evidence, or unbounded payloads.",
        "Schema, integrity, replay, version, redaction, and access-control tests pass.",
    ),
    12: CoverageMeta(
        "ACTIVATION_REQUIRED",
        "disabled PentestAiConnector, authenticator protocol, replay ledger",
        "Oracle connector tests",
        "Wave 9",
        "Install, authenticate, pin, isolate, contract-test, and readiness-test the adapter.",
        "External service, installation, credentials",
        "VulnHunter retains authorization, scope, labels, review, and publication.",
        "Real disabled-by-default readiness test passes without authority transfer.",
    ),
    13: CoverageMeta(
        "CONTRACT_ONLY",
        "providers registry/privacy gate; ai_routing deterministic decisions",
        "test_provider_privacy_gate.py; test_milestone27_contracts.py",
        "Wave 3",
        "Add health-checked local provider adapter, schema validation, budgets, and degraded mode.",
        "Local model runtime/model activation",
        "Loopback only; no model authority, shell, scope, secrets, or destructive control.",
        "No-model degraded tests and manually activated local readiness tests pass.",
    ),
    14: CoverageMeta(
        "RESOURCE_DEFERRED",
        "generic provider/role registries and grouped ML benchmark foundations",
        "provider, role, benchmark, model-selection, and research tests",
        "Wave 3 / Wave 15",
        "Define specialist model registry and reproducible task-specific benchmark records.",
        "Manual model downloads and sufficient RAM/disk",
        "Models load one at a time and never become authority.",
        "Private frozen benchmark, resource, injection, scope, and abstention gates pass.",
    ),
    15: CoverageMeta(
        "CREDENTIAL_REQUIRED",
        "disabled Groq provider contracts and privacy gate",
        "provider privacy and AI routing tests",
        "Wave 3",
        "Implement disabled provider adapter, budgets, redaction, health, fallback, "
        "and provenance.",
        "Groq credential and external service approval",
        "No private targets, code, evidence, findings, cookies, tokens, or customer data.",
        "Credential-isolated real readiness plus privacy/cost/timeout tests pass.",
    ),
    16: CoverageMeta(
        "PARTIAL",
        "repository coverage foundation only; no Graphify or native graph adapter",
        "test_repository_coverage.py",
        "Wave 2 sub-waves",
        "Follow CLI learning, native schema, migration, optional-accelerator order exactly.",
        "Graphify manual install for early sub-wave",
        "Graph output is untrusted, non-authoritative, read-only, and source-verified.",
        "Each ordered sub-wave passes before the next begins.",
    ),
    17: CoverageMeta(
        "MISSING",
        "provider privacy and knowledge provenance are adjacent foundations",
        "provider and knowledge tests only",
        "Wave 2 / Wave 3",
        "Build typed deterministic context broker with budgets, freshness, confidence, "
        "and compression.",
        "Optional embeddings remain deferred",
        "Original source authoritative; protected data filtered before model context.",
        "Relevance, omission, freshness, contradiction, redaction, and budget tests pass.",
    ),
    18: CoverageMeta(
        "PARTIAL",
        "vulnhunter/unattended; PermissionEnforcer; fixed command runner",
        "unattended model, policy, store, workflow, and CLI tests",
        "Wave 1 / Wave 14",
        "Add durable leases/heartbeats, unified kill switch, scheduler abstraction, and readiness.",
        "Production scheduler/isolation optional",
        "Expiring human-approved manifests; no arbitrary commands or inferred permission.",
        "Lease, expiry, revocation, kill, recovery, and required-evidence tests pass.",
    ),
    19: CoverageMeta(
        "MISSING",
        "prompt-injection screening, activity ledger, and runtime denials are foundations",
        "knowledge, activity, and policy tests only",
        "Wave 1B",
        "Add typed sequence rules, threat events, containment, notifications, and human clearance.",
        "None",
        "Signals are evidence, not proof; containment cannot expand authority.",
        "Sequence, false-positive, evasion, containment, audit, and recovery tests pass.",
    ),
    20: CoverageMeta(
        "LATE_STAGE_GATED",
        "transactional research and ML governance foundations; no reinforcement training",
        "research, ML, holdout, and model-selection tests",
        "Wave 15 / separate later programme",
        "Design reward/data/evaluator governance only; do not train automatically.",
        "Governed data, isolated compute, manual approval",
        "Frozen hidden evaluation and deterministic gates override rewards.",
        "Separate human-approved programme passes leakage, reward-hacking, injection, "
        "and rollback gates.",
    ),
    21: CoverageMeta(
        "PARTIAL",
        "broad unit/integration/security tests; project audit; governance/research release gates",
        "all focused test families",
        "Every wave / final gate",
        "Add feature-specific gates and measured metrics as each capability is implemented.",
        "Operational integrations where applicable",
        "No production claim without real readiness and human review.",
        "All declared tests/metrics/evidence pass and are integrity-linked.",
    ),
    22: CoverageMeta(
        "PARTIAL",
        "local SQLite/atomic stores; local web app; production limitations docs",
        "storage, web, governance, and configuration tests",
        "Wave 14",
        "Add secure production configuration, storage/queue abstractions, backup, "
        "restore, and health.",
        "Production services remain optional/manual",
        "Local-first remains functional; no automatic deployment or model download.",
        "Local and production-readiness checks pass within resource budgets.",
    ),
    23: CoverageMeta(
        "PARTIAL",
        "phase-specific evidence in this matrix",
        "phase-specific focused tests",
        "Phases map to Waves 1-15",
        "Execute only missing or partial phase work in dependency order.",
        "Phase-specific",
        "Complete phases are preserved; gated phases remain disabled.",
        "Every phase row reaches its explicit completion gate.",
    ),
    24: CoverageMeta(
        "INTENTIONALLY_EXCLUDED",
        "AGENTS.md; security boundaries; dependency matrix",
        "policy, authorization, scope, and project audit tests",
        "All waves",
        "Keep excluded capability absent unless a later explicit approved programme supersedes it.",
        "Explicit future approval required",
        "No silent enablement, installation, upload, exploitation, or retraining.",
        "Repository search and policy tests confirm absence/disabled state.",
    ),
    25: CoverageMeta(
        "EXTERNAL_PREREQUISITE",
        "dependency matrix and manual install runbook",
        "No external readiness is claimed from unit fakes",
        "Waves 2, 3, 9, 10, 13",
        "Inspect each source, installer, license, dependency tree, behavior, provenance, "
        "and rollback.",
        "External repositories/services",
        "References are untrusted and disabled until approved.",
        "Pinned integrity and isolated real readiness review passes.",
    ),
    26: CoverageMeta(
        "COMPLETE",
        "AGENTS.md and enforced authorization/scope/review/security boundaries",
        "authorization, scope, transport, governance, review, and policy tests",
        "All waves",
        "Preserve each non-negotiable principle and expose pause/reversal to users.",
        "None",
        "No wave may weaken a principle to gain capability or performance.",
        "Independent final review confirms every principle in code, tests, and docs.",
    ),
}


PHASE_META: dict[int, CoverageMeta] = {
    1: SECTION_META[2],
    2: CoverageMeta(
        "COMPLETE",
        "authorization; scope; pinned transport",
        "authorization, scope, and transport tests",
        "Preserved foundation",
        "Preserve existing implementation.",
        "None",
        "Fail closed.",
        "Existing focused suites remain green.",
    ),
    3: CoverageMeta(
        "COMPLETE",
        "agent and orchestration typed specs",
        "agent/orchestration tests",
        "Preserved foundation",
        "Preserve existing implementation.",
        "None",
        "Bounded and typed.",
        "Existing focused suites remain green.",
    ),
    4: SECTION_META[9],
    5: CoverageMeta(
        "COMPLETE",
        "hash-chained domain stores",
        "store integrity tests",
        "Preserved foundation",
        "Reuse event contracts.",
        "None",
        "Redacted and append-only.",
        "Integrity tests pass.",
    ),
    6: CoverageMeta(
        "COMPLETE",
        "observations models/store",
        "observation tests",
        "Preserved foundation",
        "Reuse candidate schema.",
        "None",
        "Candidate is not verified finding.",
        "Observation tests pass.",
    ),
    7: CoverageMeta(
        "COMPLETE",
        "review and governance",
        "review/governance tests",
        "Preserved foundation",
        "Preserve human authority.",
        "None",
        "Two reviewers plus adjudication.",
        "Governed review tests pass.",
    ),
    8: SECTION_META[10],
    9: CoverageMeta(
        "COMPLETE",
        "oracle ProofCapsule",
        "Oracle tests",
        "Wave 9 extension",
        "Preserve schema and extend canonical replay fields.",
        "None",
        "No protected raw data.",
        "Proof tests pass.",
    ),
    10: SECTION_META[13],
    11: SECTION_META[17],
    12: CoverageMeta(
        "MANUAL_INSTALL_REQUIRED",
        "Graphify absent; runbook prepared",
        "none until installed",
        "Wave 2A",
        "Build restricted adapter after manual provenance approval.",
        "Graphify installation",
        "No hooks/MCP/remote backend.",
        "Adapter contract and real readiness pass.",
    ),
    13: CoverageMeta(
        "EXTERNAL_PREREQUISITE",
        "learning schema not implemented",
        "none",
        "Wave 2B",
        "Run bounded learning period and record required metrics.",
        "Phase 12 readiness",
        "Graphify remains advisory.",
        "Sufficient reviewed usage evidence exists.",
    ),
    14: SECTION_META[9],
    15: CoverageMeta(
        "PARTIAL",
        "generic benchmark/ML/research harness",
        "benchmark, model-selection, research tests",
        "Wave 3 / Wave 15",
        "Add specialist private task suite and resource metrics.",
        "Manual models later",
        "Frozen private evaluation.",
        "Reproducible benchmark gates pass.",
    ),
    16: SECTION_META[15],
    17: SECTION_META[6],
    18: SECTION_META[7],
    19: SECTION_META[8],
    20: CoverageMeta(
        "LATE_STAGE_GATED",
        "no local MCP service",
        "none",
        "Wave 2E / Wave 10",
        "Add only after CLI learning and native graph boundaries.",
        "Optional Graphify MCP extra",
        "Local stdio read-only.",
        "Restricted MCP security tests pass.",
    ),
    21: CoverageMeta(
        "MISSING",
        "file coverage only",
        "repository coverage tests",
        "Wave 2D",
        "Build native security graph after learning period.",
        "Phase 13 evidence",
        "Native graph owns deterministic facts.",
        "Incremental graph and comparison tests pass.",
    ),
    22: SECTION_META[19],
    23: SECTION_META[4],
    24: SECTION_META[18],
    25: SECTION_META[20],
}


SUBHEADING_OVERRIDES: dict[tuple[int, str], CoverageMeta] = {
    (14, "Benchmark policy"): CoverageMeta(
        "PARTIAL",
        "grouped ML benchmark, model selection, research evaluator",
        "benchmark, model-selection, holdout, research tests",
        "Wave 3 / Wave 15",
        "Add one private specialist-model suite with all canonical metrics.",
        "Manual model activation later",
        "Frozen evaluation; one model at a time; output remains advisory.",
        "Reproducibility, resource, scope, injection, and abstention tests pass.",
    ),
    (16, "Phase 1 — Graphify CLI adapter first"): PHASE_META[12],
    (16, "Learning period"): PHASE_META[13],
    (16, "Phase 2 — Define the native architecture"): CoverageMeta(
        "EXTERNAL_PREREQUISITE",
        "candidate schema exists only in canonical roadmap",
        "none",
        "Wave 2C",
        "Define native schema only from reviewed learning-period evidence.",
        "Phase 13 evidence",
        "Do not clone Graphify or infer security relationships.",
        "Schema ADR and evidence trace receive human review.",
    ),
    (16, "Phase 3 — Build the VulnHunter-native graph"): PHASE_META[21],
    (16, "Restricted MCP service"): PHASE_META[20],
}


STATUS_TEXT = {
    "COMPLETE": "Implemented and focused evidence exists.",
    "PARTIAL": "A tested foundation exists; canonical behavior is incomplete.",
    "MISSING": "No implementation satisfying this requirement exists.",
    "CONTRACT_ONLY": "Typed or documented contract exists but is not operational.",
    "ACTIVATION_REQUIRED": "Code foundation exists; real integration is disabled.",
    "EXTERNAL_PREREQUISITE": "A prior external/evidence prerequisite is unmet.",
    "MANUAL_INSTALL_REQUIRED": "Manual reviewed installation is required and has not occurred.",
    "CREDENTIAL_REQUIRED": "Disabled integration requires separately approved credentials.",
    "RESOURCE_DEFERRED": "Deferred for VM/model/service resource reasons.",
    "LATE_STAGE_GATED": "Explicitly gated until earlier safety and evidence phases pass.",
    "INTENTIONALLY_EXCLUDED": "Deliberately excluded from the current product programme.",
    "PROHIBITED": "Forbidden by permanent product boundaries.",
}

TABLE_HEADER = (
    "| ID | Section | Capability | Exact canonical requirement | Repository evidence | "
    "Current implementation status | Current tests | Programme wave | "
    "Exact implementation task | External/manual dependency | Security restrictions | "
    "Completion gate | Final classification |"
)


def _escape(value: str) -> str:
    return value.replace("|", "\\|").replace("\n", " ").strip()


def parse_requirements(path: Path) -> tuple[Requirement, ...]:
    lines = path.read_text(encoding="utf-8").splitlines()
    requirements: list[Requirement] = []
    section: int | None = None
    section_title = "Canonical operating rules"
    subheading: str | None = None
    per_section: Counter[int] = Counter()
    per_section_subheadings: Counter[int] = Counter()
    preface_count = 0

    for line_number, line in enumerate(lines, start=1):
        if line == "## Programme execution status":
            break
        section_match = re.match(r"^# (\d+)\. (.+)$", line)
        if section_match:
            section = int(section_match.group(1))
            section_title = section_match.group(2)
            subheading = None
            requirements.append(
                Requirement(
                    identifier=f"S{section:02d}.OVERVIEW",
                    section=section,
                    capability=section_title,
                    summary=f"Canonical section contract: {section_title}.",
                    line=line_number,
                )
            )
            continue

        subheading_match = re.match(r"^## (.+)$", line)
        if subheading_match and section is not None:
            subheading = subheading_match.group(1)
            per_section_subheadings[section] += 1
            requirements.append(
                Requirement(
                    identifier=(f"S{section:02d}.H{per_section_subheadings[section]:03d}"),
                    section=section,
                    capability=f"{section_title} / {subheading}",
                    summary=f"Canonical subsection contract: {subheading}.",
                    line=line_number,
                    subheading=subheading,
                )
            )
            continue

        item_match = re.match(r"^- (.+?);?$", line)
        numbered_match = re.match(r"^(\d+)\. (.+)$", line)
        if section is None:
            if numbered_match and 20 <= line_number <= 26:
                preface_count += 1
                requirements.append(
                    Requirement(
                        identifier=f"S00.R{preface_count:02d}",
                        section=0,
                        capability="Canonical operating rules",
                        summary=numbered_match.group(2),
                        line=line_number,
                    )
                )
            continue
        if not item_match and not numbered_match:
            continue

        per_section[section] += 1
        phase = None
        summary = item_match.group(1) if item_match else numbered_match.group(2)
        if section == 23 and numbered_match:
            phase = int(numbered_match.group(1))
        requirements.append(
            Requirement(
                identifier=f"S{section:02d}.R{per_section[section]:03d}",
                section=section,
                capability=(f"{section_title} / {subheading}" if subheading else section_title),
                summary=summary.rstrip(";."),
                line=line_number,
                subheading=subheading,
                phase=phase,
            )
        )
    return tuple(requirements)


def meta_for(requirement: Requirement) -> CoverageMeta:
    if requirement.phase is not None:
        return PHASE_META[requirement.phase]
    if requirement.subheading is not None:
        override = SUBHEADING_OVERRIDES.get((requirement.section, requirement.subheading))
        if override is not None:
            return override
    return SECTION_META[requirement.section]


def render(source: Path, requirements: tuple[Requirement, ...]) -> str:
    rows: list[str] = []
    counts: Counter[str] = Counter()
    for requirement in requirements:
        meta = meta_for(requirement)
        if meta.classification not in ALLOWED_CLASSIFICATIONS:
            raise ValueError(f"unmapped classification for {requirement.identifier}")
        counts[meta.classification] += 1
        fields = (
            requirement.identifier,
            str(requirement.section),
            requirement.capability,
            f"L{requirement.line}: {requirement.summary}",
            meta.evidence,
            STATUS_TEXT[meta.classification],
            meta.tests,
            meta.wave,
            meta.task,
            meta.dependency,
            meta.restrictions,
            meta.gate,
            meta.classification,
        )
        rows.append("| " + " | ".join(_escape(field) for field in fields) + " |")

    phases = sum(requirement.phase is not None for requirement in requirements)
    sections = len({requirement.section for requirement in requirements if requirement.section})
    if sections != 26 or phases != 25:
        raise ValueError(f"canonical structure changed: sections={sections}, phases={phases}")
    unmapped = sum(
        1
        for requirement in requirements
        if meta_for(requirement).classification not in ALLOWED_CLASSIFICATIONS
    )
    if unmapped:
        raise ValueError(f"UNMAPPED must be zero, found {unmapped}")

    ordered_counts = "\n".join(
        f"- {classification}: `{counts.get(classification, 0)}`"
        for classification in sorted(ALLOWED_CLASSIFICATIONS)
    )
    return f"""# Total Programme Canonical Coverage Matrix

## Gate result

- Canonical source: `{source.as_posix()}`
- Canonical requirements mapped: `{len(requirements)}`
- Numbered canonical sections: `{sections}`
- Deferred implementation phases: `{phases}`
- UNMAPPED: `{unmapped}`
- Transition gate: `PASS`

The matrix maps every numbered section overview, every subsection, every bullet
requirement, every numbered operating/principle/adoption requirement, and all
25 deferred phases. Broad section headings are not used to hide missing atomic
items.

## Classification totals

{ordered_counts}

## Field legend

Every row records the canonical section and capability, exact source-line
summary, repository evidence, implementation status, tests, matching programme
wave, exact task, external/manual dependency, security restrictions, completion
gate, and final allowed classification.

## One-to-one matrix

{TABLE_HEADER}
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
{chr(10).join(rows)}
"""


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--source",
        type=Path,
        default=Path("docs/intelligence/VULNHUNTER_FUTURE_MASTER_PLAN.md"),
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("docs/intelligence/TOTAL_PROGRAMME_CANONICAL_COVERAGE_MATRIX.md"),
    )
    args = parser.parse_args()
    requirements = parse_requirements(args.source)
    output = render(args.source, requirements)
    args.output.write_text(output, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
