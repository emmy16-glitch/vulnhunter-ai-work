from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from vulnhunter.providers import ProviderKind, ProviderOutputKind, ProviderResponse
from vulnhunter.source_hunt.benchmark_v2 import (
    BenchmarkCorpusKind,
    SourceBenchmarkCorpus,
    SourceGroundTruthCase,
    SourceHuntBenchmarkEvaluator,
)
from vulnhunter.source_hunt.fix_verify import FixVerificationInput, VerifierReceipt
from vulnhunter.source_hunt.headless_v2 import (
    HeadlessManifestLedger,
    HeadlessPermissionManifest,
    HeadlessSourceHuntService,
)
from vulnhunter.source_hunt.intelligence import (
    AnalysisCoverage,
    HunterRole,
    SecurityProofPlan,
    SourceHuntV2,
)
from vulnhunter.source_hunt.jobs import SourceHuntJobStore
from vulnhunter.source_hunt.models import (
    RemoteSourceProcessingApproval,
    RepositoryVisibility,
    SourceHuntStage,
)
from vulnhunter.source_hunt.service import RepositorySnapshotBuilder, SourceHuntPolicy
from vulnhunter.source_hunt.strict_fix_verify import (
    ReproductionReceipt,
    StrictFixVerificationInput,
    StrictReadOnlyFixVerifier,
)


class _FakeGroq:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str | None]] = []

    def invoke(self, invocation, content, *, cancelled=None):
        envelope = json.loads(content[content.index("{") :])
        capability = invocation.capability.value
        role = envelope.get("specialist_role")
        self.calls.append((capability, role))
        if capability == "source_reconnaissance":
            output = {"summary": "Two bounded web-to-file paths.", "priority_surface_ids": []}
        elif capability == "attack_path_analysis":
            surface = envelope["surface"]
            entry = dict(surface["entry_point"])
            sink = dict(surface["reachable_sinks"][0])
            output = {
                "title": f"Untrusted path reaches file open ({role or 'general'})",
                "vulnerability_class": "path_traversal",
                "summary": "A route argument reaches filesystem access without a proven boundary.",
                "entry_point": entry,
                "sink": sink,
                "path": surface["call_path"],
                "assumptions": ["The supplied route is attacker reachable."],
                "evidence_refs": [entry, sink],
                "confidence": 90 if role == "navigation" else 70,
            }
        elif capability == "candidate_falsification":
            output = {
                "disposition": "survived",
                "reason": "No supplied guard proves containment of the selected file path.",
                "blocking_controls": [],
                "unsupported_assumptions": [],
                "contradicting_evidence": [],
            }
        elif capability == "capability_assessment":
            output = {
                "meaningful": True,
                "required_attacker_capability": "Access to the supplied route",
                "resulting_capability": "Select a file outside the intended application boundary",
                "impact_boundary": "Files readable by the application account",
                "reason": "The supplied path crosses the intended filesystem selection boundary.",
            }
        elif capability == "remediation_planning":
            output = {
                "summary": "Resolve under a fixed root and reject path escapes.",
                "target_files": [envelope["hypothesis"]["sink"]["path"]],
                "regression_test": "Assert a parent-directory path is rejected before file access.",
                "compatibility_risks": ["Absolute-path callers will be rejected."],
                "verification_recipe": (
                    "Run the security test and confirm resolution stays in root."
                ),
            }
        else:  # pragma: no cover
            raise AssertionError(capability)
        encoded = json.dumps(output, sort_keys=True)
        return ProviderResponse(
            invocation_id=invocation.invocation_id,
            provider=ProviderKind.GROQ_ADVISORY,
            model=invocation.model,
            content=encoded,
            output_sha256=hashlib.sha256(encoded.encode()).hexdigest(),
            output_kind=ProviderOutputKind.CANDIDATE_ANALYSIS,
            trusted=False,
        )


def _repository(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
    root.mkdir()
    (root / "app.py").write_text(
        """\
class App:
    def route(self, _path):
        def decorate(function):
            return function
        return decorate

app = App()

@app.route('/download')
def download(request):
    return read_file(request.args.get('name'))

@app.route('/preview')
def preview(request):
    return preview_file(request.args.get('name'))

def read_file(name):
    return open(name).read()

def preview_file(name):
    return open(name).read()
""",
        encoding="utf-8",
    )
    (root / "client.ts").write_text("export const enabled = true;\n", encoding="utf-8")
    return root


def _policy(tmp_path: Path) -> SourceHuntPolicy:
    return SourceHuntPolicy(
        approved_roots=(tmp_path,),
        maximum_prompt_bytes=100_000,
        maximum_model_calls=24,
        maximum_surfaces=10,
        maximum_candidates=10,
    )


def _approval(snapshot):
    now = datetime.now(UTC)
    return RemoteSourceProcessingApproval.create(
        repository_id=snapshot.repository_id,
        revision=snapshot.revision,
        snapshot_sha256=snapshot.snapshot_sha256,
        visibility=RepositoryVisibility.PRIVATE,
        permitted_paths=(".",),
        customer_data_confirmed_absent=True,
        provider_retention_reviewed=True,
        approved_by="source-reviewer",
        approved_at=now,
        expires_at=now + timedelta(minutes=30),
    )


def test_v2_runs_independent_specialists_and_builds_sweep_proof_graph_and_language_inventory(
    tmp_path,
):
    repository = _repository(tmp_path)
    policy = _policy(tmp_path)
    snapshot = RepositorySnapshotBuilder(policy).build(repository, revision="a" * 40)
    connector = _FakeGroq()

    report, bundle = SourceHuntV2(connector=connector, policy=policy).run_with_intelligence(
        repository,
        approval=_approval(snapshot),
        revision=snapshot.revision,
    )

    assert report.stage == SourceHuntStage.COMPLETE
    assert len(report.candidates) == 2
    assert len(bundle.specialist_assignments) == 2
    assert all(item.primary_role == HunterRole.NAVIGATION for item in bundle.specialist_assignments)
    assert all(
        HunterRole.SINK_BACKSTOP in item.independent_roles for item in bundle.specialist_assignments
    )
    specialist_calls = [
        role for capability, role in connector.calls if capability == "attack_path_analysis"
    ]
    assert specialist_calls.count("navigation") == 2
    assert specialist_calls.count("sink_backstop") == 2
    assert len(bundle.root_cause_sweeps) == 2
    assert all(len(sweep.occurrences) == 1 for sweep in bundle.root_cause_sweeps)
    assert len(bundle.proof_plans) == 2
    assert bundle.graph_summary.functions >= 4
    inventory = {item.language: item for item in bundle.language_inventory}
    assert inventory["python"].coverage == AnalysisCoverage.PRODUCTION
    assert inventory["typescript"].coverage == AnalysisCoverage.INVENTORY_ONLY


def test_benchmark_reports_controlled_metrics_without_production_accuracy_claim(tmp_path):
    repository = _repository(tmp_path)
    policy = _policy(tmp_path)
    snapshot = RepositorySnapshotBuilder(policy).build(repository, revision="b" * 40)
    report, _bundle = SourceHuntV2(connector=_FakeGroq(), policy=policy).run_with_intelligence(
        repository,
        approval=_approval(snapshot),
        revision=snapshot.revision,
    )
    candidate = report.candidates[0]
    sink = candidate.hypothesis.sink
    corpus = SourceBenchmarkCorpus.create(
        corpus_id="controlled-path-traversal",
        kind=BenchmarkCorpusKind.CONTROLLED_LAB,
        cases=(
            SourceGroundTruthCase(
                case_id="VH-001",
                vulnerability_class="path_traversal",
                path=sink.path,
                line_start=sink.line_start,
                line_end=sink.line_end,
                expected_vulnerable=True,
            ),
        ),
    )

    result = SourceHuntBenchmarkEvaluator().evaluate(report=report, corpus=corpus)

    assert result.metrics.true_positives == 1
    assert result.metrics.recall == 1.0
    assert result.production_accuracy_claim_permitted is False


def test_headless_manifest_is_exact_expiring_distinct_approver_and_one_use(tmp_path):
    repository = _repository(tmp_path)
    policy = _policy(tmp_path)
    snapshot = RepositorySnapshotBuilder(policy).build(repository, revision="c" * 40)
    approval = _approval(snapshot)
    now = datetime.now(UTC)
    manifest = HeadlessPermissionManifest.create(
        snapshot=snapshot,
        permitted_paths=(".",),
        requester_id="ci-requester",
        approver_id="human-approver",
        allow_remote_source_processing=True,
        created_at=now,
        expires_at=now + timedelta(minutes=10),
    )
    service = HeadlessSourceHuntService(
        policy=policy,
        job_store=SourceHuntJobStore(tmp_path / "jobs"),
        manifest_ledger=HeadlessManifestLedger(tmp_path / "ledger"),
    )

    job = service.enqueue(
        repository,
        revision=snapshot.revision,
        approval=approval,
        manifest=manifest,
        now=now + timedelta(seconds=1),
    )

    assert job.snapshot.snapshot_sha256 == snapshot.snapshot_sha256
    with pytest.raises(ValueError, match="already been consumed"):
        service.enqueue(
            repository,
            revision=snapshot.revision,
            approval=approval,
            manifest=manifest,
            now=now + timedelta(seconds=2),
        )


def test_strict_verifier_requires_red_green_and_proof_plan_binding(tmp_path):
    repository = _repository(tmp_path)
    policy = _policy(tmp_path)
    original = RepositorySnapshotBuilder(policy).build(repository, revision="d" * 40)
    report, bundle = SourceHuntV2(connector=_FakeGroq(), policy=policy).run_with_intelligence(
        repository,
        approval=_approval(original),
        revision=original.revision,
    )
    proof: SecurityProofPlan = bundle.proof_plans[0]
    target = proof.target_files[0]
    (repository / target).write_text(
        (repository / target).read_text() + "\n# fixed\n",
        encoding="utf-8",
    )
    fixed = RepositorySnapshotBuilder(policy).build(repository, revision="e" * 40)
    digest = "f" * 64
    security = VerifierReceipt(
        verifier_id="security-regression",
        passed=True,
        exit_code=0,
        output_sha256=digest,
        duration_seconds=1,
        safe_summary="security test passed",
    )
    regression = VerifierReceipt(
        verifier_id="unit-suite",
        passed=True,
        exit_code=0,
        output_sha256=digest,
        duration_seconds=2,
        safe_summary="regression suite passed",
    )
    base = FixVerificationInput(
        finding_id=report.candidates[0].candidate_id,
        original_revision=original.revision,
        fixed_snapshot=fixed,
        allowed_paths=proof.target_files,
        changed_files=proof.target_files,
        security_test=security,
        regression_tests=(regression,),
        original_attack_blocked=False,
    )
    reproduction = ReproductionReceipt.create(
        proof_plan=proof,
        original_revision=original.revision,
        fixed_revision=fixed.revision,
        vulnerable_state_reproduced=True,
        security_test_passed_after_fix=True,
        original_condition_blocked=True,
        evidence_sha256=digest,
        runner_id="isolated-test-runner",
    )

    verdict = StrictReadOnlyFixVerifier().verify(
        StrictFixVerificationInput(base=base, proof_plan=proof, reproduction=reproduction)
    )

    assert verdict.verdict.value == "fixed"


def test_headless_manifest_rejects_self_approval(tmp_path):
    repository = _repository(tmp_path)
    policy = _policy(tmp_path)
    snapshot = RepositorySnapshotBuilder(policy).build(repository, revision="f" * 40)
    now = datetime.now(UTC)
    with pytest.raises(ValueError, match="distinct identities"):
        HeadlessPermissionManifest.create(
            snapshot=snapshot,
            permitted_paths=(".",),
            requester_id="same-actor",
            approver_id="same-actor",
            allow_remote_source_processing=True,
            created_at=now,
            expires_at=now + timedelta(minutes=5),
        )


def test_v2_job_worker_persists_bound_intelligence_sidecar(tmp_path):
    from vulnhunter.source_hunt.intelligence_store import SourceHuntIntelligenceStore
    from vulnhunter.source_hunt.jobs import SourceHuntJob
    from vulnhunter.source_hunt.jobs_v2 import process_next_source_hunt_v2_job
    from vulnhunter.source_hunt.store import SourceHuntStore

    repository = _repository(tmp_path)
    policy = _policy(tmp_path)
    snapshot = RepositorySnapshotBuilder(policy).build(repository, revision="1" * 40)
    approval = _approval(snapshot)
    job_store = SourceHuntJobStore(tmp_path / "v2-jobs")
    report_store = SourceHuntStore(tmp_path / "v2-reports")
    intelligence_store = SourceHuntIntelligenceStore(tmp_path / "v2-intelligence")
    job = SourceHuntJob.create(
        repository_root=repository,
        snapshot=snapshot,
        approval=approval,
        model=policy.model,
    )
    job_store.enqueue(job)

    completed = process_next_source_hunt_v2_job(
        job_store=job_store,
        report_store=report_store,
        intelligence_store=intelligence_store,
        connector=_FakeGroq(),
        policy=policy,
    )

    assert completed is not None and completed.status.value == "completed"
    assert completed.report_id is not None
    base = report_store.load(completed.report_id)
    bundle = intelligence_store.load(completed.report_id)
    assert bundle.report_id == base.report_id
    assert bundle.snapshot_sha256 == base.snapshot.snapshot_sha256


def test_v2_worker_refuses_legacy_report_without_v2_sidecar(tmp_path):
    from vulnhunter.source_hunt.intelligence_store import SourceHuntIntelligenceStore
    from vulnhunter.source_hunt.jobs import SourceHuntJob
    from vulnhunter.source_hunt.jobs_v2 import process_next_source_hunt_v2_job
    from vulnhunter.source_hunt.service import GroqSourceHunt
    from vulnhunter.source_hunt.store import SourceHuntStore

    repository = _repository(tmp_path)
    policy = _policy(tmp_path)
    snapshot = RepositorySnapshotBuilder(policy).build(repository, revision="2" * 40)
    approval = _approval(snapshot)
    legacy = GroqSourceHunt(connector=_FakeGroq(), policy=policy).run(
        repository,
        approval=approval,
        revision=snapshot.revision,
    )
    job_store = SourceHuntJobStore(tmp_path / "legacy-jobs")
    report_store = SourceHuntStore(tmp_path / "legacy-reports")
    intelligence_store = SourceHuntIntelligenceStore(tmp_path / "legacy-intelligence")
    report_store.save(legacy)
    job = SourceHuntJob.create(
        repository_root=repository,
        snapshot=snapshot,
        approval=approval,
        model=policy.model,
    )
    job_store.enqueue(job)

    failed = process_next_source_hunt_v2_job(
        job_store=job_store,
        report_store=report_store,
        intelligence_store=intelligence_store,
        connector=_FakeGroq(),
        policy=policy,
    )

    assert failed is not None and failed.status.value == "failed"
    assert "no V2 intelligence sidecar" in (failed.safe_error or "")


def test_v2_integrity_contracts_reject_tampering(tmp_path):
    repository = _repository(tmp_path)
    policy = _policy(tmp_path)
    snapshot = RepositorySnapshotBuilder(policy).build(repository, revision="3" * 40)
    approval = _approval(snapshot)
    now = datetime.now(UTC)
    manifest = HeadlessPermissionManifest.create(
        snapshot=snapshot,
        permitted_paths=(".",),
        requester_id="ci-requester",
        approver_id="human-approver",
        allow_remote_source_processing=True,
        created_at=now,
        expires_at=now + timedelta(minutes=10),
    )
    manifest_payload = manifest.model_dump(mode="json")
    manifest_payload["approver_id"] = "different-approver"
    with pytest.raises(ValueError, match="digest"):
        HeadlessPermissionManifest.model_validate(manifest_payload)

    report, bundle = SourceHuntV2(connector=_FakeGroq(), policy=policy).run_with_intelligence(
        repository,
        approval=approval,
        revision=snapshot.revision,
    )
    proof_payload = bundle.proof_plans[0].model_dump(mode="json")
    proof_payload["red_security_test"] = "tampered security test"
    with pytest.raises(ValueError, match="digest"):
        SecurityProofPlan.model_validate(proof_payload)

    bundle_payload = bundle.model_dump(mode="json")
    bundle_payload["graph_summary"]["functions"] += 1
    with pytest.raises(ValueError, match="bundle digest"):
        type(bundle).model_validate(bundle_payload)

    sink = report.candidates[0].hypothesis.sink
    corpus = SourceBenchmarkCorpus.create(
        corpus_id="integrity-corpus",
        kind=BenchmarkCorpusKind.SYNTHETIC,
        cases=(
            SourceGroundTruthCase(
                case_id="VH-TAMPER-1",
                vulnerability_class="path_traversal",
                path=sink.path,
                line_start=sink.line_start,
                line_end=sink.line_end,
                expected_vulnerable=True,
            ),
        ),
    )
    corpus_payload = corpus.model_dump(mode="json")
    corpus_payload["cases"][0]["path"] = "tampered.py"
    with pytest.raises(ValueError, match="corpus digest"):
        SourceBenchmarkCorpus.model_validate(corpus_payload)
