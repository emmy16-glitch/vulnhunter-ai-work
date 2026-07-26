from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from django.urls import reverse

from vulnhunter.providers import (
    PrivacyGate,
    ProviderKind,
    ProviderOutputKind,
    ProviderRequest,
    ProviderResponse,
)
from vulnhunter.source_hunt import (
    GroqSourceHunt,
    RemoteSourceProcessingApproval,
    RepositorySnapshotBuilder,
    RepositoryVisibility,
    SourceHuntError,
    SourceHuntPolicy,
    SourceHuntStage,
    SourceHuntStore,
)


class _FakeGroq:
    def __init__(self, *, invent_reference: bool = False) -> None:
        self.invent_reference = invent_reference
        self.calls: list[str] = []

    def invoke(self, invocation, content, *, cancelled=None):
        self.calls.append(invocation.capability.value)
        envelope = json.loads(content[content.index("{") :])
        capability = invocation.capability.value
        if capability == "source_reconnaissance":
            output = {"summary": "One bounded web-to-file path.", "priority_surface_ids": []}
        elif capability == "attack_path_analysis":
            surface = envelope["surface"]
            entry = dict(surface["entry_point"])
            sink = dict(surface["reachable_sinks"][0])
            if self.invent_reference:
                sink["path"] = "invented.py"
            output = {
                "title": "Untrusted path reaches file open",
                "vulnerability_class": "path_traversal",
                "summary": "A route argument reaches a filesystem access operation.",
                "entry_point": entry,
                "sink": sink,
                "path": surface["call_path"],
                "assumptions": ["The route is reachable by a low-privilege user."],
                "evidence_refs": [entry, sink],
                "confidence": 88,
            }
        elif capability == "candidate_falsification":
            output = {
                "disposition": "survived",
                "reason": "No path normalization or authorization control blocks the supplied path.",
                "blocking_controls": [],
                "unsupported_assumptions": [],
                "contradicting_evidence": [],
            }
        elif capability == "capability_assessment":
            output = {
                "meaningful": True,
                "required_attacker_capability": "Access to the download route",
                "resulting_capability": "Read a file selected by attacker-controlled input",
                "impact_boundary": "Files readable by the application account",
                "reason": "The supplied source path crosses the intended file boundary.",
            }
        elif capability == "remediation_planning":
            path = envelope["hypothesis"]["sink"]["path"]
            output = {
                "summary": "Resolve the requested file under a fixed root and reject escapes.",
                "target_files": [path],
                "regression_test": "Assert that ../secret.txt is rejected before open is called.",
                "compatibility_risks": ["Existing absolute-path callers will be rejected."],
                "verification_recipe": "Run the security test and confirm the resolved path stays under the root.",
            }
        else:  # pragma: no cover - defensive only
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

def read_file(name):
    return open(name).read()
""",
        encoding="utf-8",
    )
    return root


def _policy(tmp_path: Path) -> SourceHuntPolicy:
    return SourceHuntPolicy(
        approved_roots=(tmp_path,),
        maximum_prompt_bytes=100_000,
        maximum_model_calls=10,
        maximum_surfaces=10,
    )


def _approval(snapshot):
    now = datetime.now(UTC)
    return RemoteSourceProcessingApproval.create(
        repository_id=snapshot.repository_id,
        revision=snapshot.revision,
        snapshot_sha256=snapshot.snapshot_sha256,
        visibility=RepositoryVisibility.PRIVATE,
        permitted_paths=(".",),
        approved_by="test-admin",
        approved_at=now,
        expires_at=now + timedelta(minutes=30),
    )


def test_groq_source_hunt_runs_hunt_falsification_capability_and_remediation(tmp_path):
    repository = _repository(tmp_path)
    policy = _policy(tmp_path)
    snapshot = RepositorySnapshotBuilder(policy).build(repository, revision="a" * 40)
    connector = _FakeGroq()

    report = GroqSourceHunt(connector=connector, policy=policy).run(
        repository,
        approval=_approval(snapshot),
        revision=snapshot.revision,
    )

    assert report.stage == SourceHuntStage.COMPLETE
    assert report.surfaces_examined == 1
    assert report.model_calls == 5
    assert connector.calls == [
        "source_reconnaissance",
        "attack_path_analysis",
        "candidate_falsification",
        "capability_assessment",
        "remediation_planning",
    ]
    assert len(report.candidates) == 1
    candidate = report.candidates[0]
    assert candidate.falsification.disposition == "survived"
    assert candidate.capability is not None and candidate.capability.meaningful
    assert candidate.remediation is not None
    assert candidate.hypothesis.entry_point.path == "app.py"
    assert candidate.hypothesis.sink.path == "app.py"


def test_source_processing_approval_is_bound_to_exact_snapshot(tmp_path):
    repository = _repository(tmp_path)
    policy = _policy(tmp_path)
    snapshot = RepositorySnapshotBuilder(policy).build(repository, revision="b" * 40)
    approval = _approval(snapshot)
    (repository / "app.py").write_text("def changed():\n    return True\n", encoding="utf-8")

    with pytest.raises(SourceHuntError, match="does not match the repository snapshot"):
        GroqSourceHunt(connector=_FakeGroq(), policy=policy).run(
            repository,
            approval=approval,
            revision=snapshot.revision,
        )


def test_invented_source_reference_is_rejected_without_a_finding(tmp_path):
    repository = _repository(tmp_path)
    policy = _policy(tmp_path)
    snapshot = RepositorySnapshotBuilder(policy).build(repository, revision="c" * 40)

    report = GroqSourceHunt(
        connector=_FakeGroq(invent_reference=True),
        policy=policy,
    ).run(repository, approval=_approval(snapshot), revision=snapshot.revision)

    assert report.stage == SourceHuntStage.ABSTAINED
    assert report.candidates == ()
    assert report.abstained_count == 1


def test_source_hunt_report_store_round_trip(tmp_path):
    repository = _repository(tmp_path)
    policy = _policy(tmp_path)
    snapshot = RepositorySnapshotBuilder(policy).build(repository, revision="d" * 40)
    report = GroqSourceHunt(connector=_FakeGroq(), policy=policy).run(
        repository,
        approval=_approval(snapshot),
        revision=snapshot.revision,
    )
    store = SourceHuntStore(tmp_path / "reports")

    destination = store.save(report)

    assert destination.is_file()
    assert store.load(report.report_id) == report
    assert store.list() == (report,)


def test_privacy_gate_requires_exact_source_approval_and_still_blocks_customer_data():
    gate = PrivacyGate()

    denied = gate.evaluate(
        "```python\n" + "print('source')\n" * 30 + "```",
        contains_private_source=True,
        contains_customer_data=False,
    )
    approved = gate.evaluate(
        "def bounded_source():\n    return True",
        contains_private_source=True,
        contains_customer_data=False,
        remote_source_processing_approved=True,
    )
    customer = gate.evaluate(
        "def bounded_source():\n    return True",
        contains_private_source=True,
        contains_customer_data=True,
        remote_source_processing_approved=True,
    )

    assert not denied.allowed_for_remote
    assert approved.allowed_for_remote
    assert not customer.allowed_for_remote


def test_provider_request_cannot_claim_source_approval_for_non_source_content():
    with pytest.raises(ValueError, match="valid only for a private-source request"):
        ProviderRequest(
            request_id="source-request",
            purpose="Analyse one exact repository snapshot",
            content="No source code here",
            remote_source_processing_approved=True,
        )


def test_source_hunt_url_and_template_contract():
    template = Path("vulnhunter/web/templates/web/source_hunt.html").read_text(encoding="utf-8")

    assert reverse("web-source-hunt") == "/source-hunt/"
    assert 'name="password"' in template
    assert 'name="approve_remote_processing"' in template
    assert "Groq only" in template
    assert "Hunt → Disprove" in template
    assert "<style" not in template
    assert "<script" not in template
