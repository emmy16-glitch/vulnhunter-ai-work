from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

from vulnhunter.providers import (
    ProviderKind,
    ProviderOutputKind,
    ProviderResponse,
)
from vulnhunter.source_hunt import (
    RemoteSourceProcessingApproval,
    RepositorySnapshotBuilder,
    RepositoryVisibility,
    SourceHuntJob,
    SourceHuntJobStatus,
    SourceHuntJobStore,
    SourceHuntPolicy,
    SourceHuntStore,
    process_next_source_hunt_job,
)


class _QueueGroq:
    def invoke(self, invocation, content, *, cancelled=None):
        envelope = json.loads(content[content.index("{") :])
        capability = invocation.capability.value
        if capability == "source_reconnaissance":
            output = {"summary": "One path.", "priority_surface_ids": []}
        elif capability == "attack_path_analysis":
            surface = envelope["surface"]
            entry = surface["entry_point"]
            sink = surface["reachable_sinks"][0]
            output = {
                "title": "Untrusted path reaches open",
                "vulnerability_class": "path_traversal",
                "summary": "The supplied path reaches filesystem access.",
                "entry_point": entry,
                "sink": sink,
                "path": surface["call_path"],
                "assumptions": [],
                "evidence_refs": [entry, sink],
                "confidence": 90,
            }
        elif capability == "candidate_falsification":
            output = {
                "disposition": "survived",
                "reason": "No supplied guard blocks the exact path.",
                "blocking_controls": [],
                "unsupported_assumptions": [],
                "contradicting_evidence": [],
            }
        elif capability == "capability_assessment":
            output = {
                "meaningful": True,
                "required_attacker_capability": "Call the route",
                "resulting_capability": "Select a readable file",
                "impact_boundary": "Application filesystem permissions",
                "reason": "Attacker input controls the filesystem path.",
            }
        else:
            output = {
                "summary": "Resolve beneath an approved root.",
                "target_files": [envelope["hypothesis"]["sink"]["path"]],
                "regression_test": "Reject ../secret.txt before filesystem access.",
                "compatibility_risks": [],
                "verification_recipe": "Run the regression and existing tests.",
            }
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
    root = tmp_path / "repository"
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
    return open(request.args.get('name')).read()
""",
        encoding="utf-8",
    )
    return root


def _job(tmp_path: Path):
    repository = _repository(tmp_path)
    policy = SourceHuntPolicy(
        approved_roots=(tmp_path,),
        maximum_prompt_bytes=100_000,
        maximum_model_calls=10,
    )
    snapshot = RepositorySnapshotBuilder(policy).build(repository, revision="a" * 40)
    now = datetime.now(UTC)
    approval = RemoteSourceProcessingApproval.create(
        repository_id=snapshot.repository_id,
        revision=snapshot.revision,
        snapshot_sha256=snapshot.snapshot_sha256,
        visibility=RepositoryVisibility.PRIVATE,
        permitted_paths=(".",),
        customer_data_confirmed_absent=True,
        provider_retention_reviewed=True,
        approved_by="operator",
        approved_at=now,
        expires_at=now + timedelta(hours=1),
    )
    return (
        SourceHuntJob.create(
            repository_root=repository,
            snapshot=snapshot,
            approval=approval,
            model=policy.model,
            now=now,
        ),
        policy,
    )


def test_source_hunt_job_queue_claims_and_completes_without_browser_state(tmp_path):
    job, policy = _job(tmp_path)
    job_store = SourceHuntJobStore(tmp_path / "jobs")
    report_store = SourceHuntStore(tmp_path / "reports")
    job_store.enqueue(job)
    projected: list[SourceHuntJobStatus] = []

    completed = process_next_source_hunt_job(
        job_store=job_store,
        report_store=report_store,
        connector=_QueueGroq(),
        policy=policy,
        on_state_change=lambda item: projected.append(item.status),
    )

    assert completed is not None
    assert completed.status == SourceHuntJobStatus.COMPLETED
    assert projected == [SourceHuntJobStatus.RUNNING, SourceHuntJobStatus.COMPLETED]
    assert completed.report_id is not None
    assert report_store.load(completed.report_id).model_calls == 5
    assert job_store.load(job.job_id) == completed
    assert not tuple((tmp_path / "jobs" / "queued").glob("*.json"))
    assert not tuple((tmp_path / "jobs" / "running").glob("*.json"))


def test_source_hunt_job_queue_persists_safe_failure(tmp_path):
    job, policy = _job(tmp_path)
    job_store = SourceHuntJobStore(tmp_path / "jobs")
    job_store.enqueue(job)
    projected: list[SourceHuntJobStatus] = []
    (Path(job.repository_root) / "app.py").write_text(
        "def changed():\n    return True\n",
        encoding="utf-8",
    )

    failed = process_next_source_hunt_job(
        job_store=job_store,
        report_store=SourceHuntStore(tmp_path / "reports"),
        connector=_QueueGroq(),
        policy=policy,
        on_state_change=lambda item: projected.append(item.status),
    )

    assert failed is not None
    assert failed.status == SourceHuntJobStatus.FAILED
    assert projected == [SourceHuntJobStatus.RUNNING, SourceHuntJobStatus.FAILED]
    assert failed.report_id is None
    assert "repository snapshot" in (failed.safe_error or "")
    assert job_store.load(job.job_id) == failed
