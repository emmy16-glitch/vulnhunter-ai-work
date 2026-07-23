import hashlib
import json

import pytest
from pydantic import ValidationError

from vulnhunter.intelligence import (
    AnalysisStatus,
    FindingAnalysisRequest,
    GroqFindingReasoningLoop,
    IntelligenceStore,
    ReasoningStage,
)
from vulnhunter.providers import ProviderKind, ProviderOutputKind, ProviderResponse

_EVIDENCE = "a" * 64


def _request(**updates):
    values = {
        "analysis_id": "analysis-test-finding",
        "finding_id": "finding-test",
        "run_id": "run-test",
        "campaign_id": "campaign-test",
        "title": "Missing security header",
        "scanner_severity": "low",
        "scanner_confidence": "medium",
        "verification_verdict": "verified",
        "verification_strategy": "evidence_consistency_check",
        "scanner_template_id": "test-template",
        "target_identity": "target-0123456789abcdef",
        "evidence_sha256": (_EVIDENCE,),
        "safe_observations": ("scanner_candidate:test-template:low",),
    }
    values.update(updates)
    return FindingAnalysisRequest.create(**values)


def _payload(*, evidence=_EVIDENCE, conclusion="likely", summary="Bounded analysis"):
    return {
        "summary": summary,
        "conclusion": conclusion,
        "hypotheses": [
            {
                "vulnerability_type": "security misconfiguration",
                "cwe_ids": ["CWE-693"],
                "disposition": conclusion,
                "confidence": 72,
                "evidence_refs": [evidence],
                "contradicting_evidence_refs": [],
                "assumptions": ["Only supplied passive evidence was considered."],
                "explanation": "The supplied observation supports a candidate configuration issue.",
            }
        ],
        "missing_information": ["Application-level compensating controls are unknown."],
        "safe_verification_suggestions": ["Review the response headers without changing state."],
        "remediation_options": ["Configure the missing defensive header at the application edge."],
    }


class FakeConnector:
    def __init__(self, *, invented_evidence=False, fail_deep=False):
        self.invented_evidence = invented_evidence
        self.fail_deep = fail_deep
        self.calls = []

    def invoke(self, invocation, content, *, cancelled=None):
        del content, cancelled
        self.calls.append(invocation)
        if self.fail_deep and invocation.model == "openai/gpt-oss-120b":
            output = "ABSTAIN"
            return ProviderResponse(
                invocation_id=invocation.invocation_id,
                provider=ProviderKind.GROQ_ADVISORY,
                model=invocation.model,
                content=output,
                output_sha256=hashlib.sha256(output.encode()).hexdigest(),
                output_kind=ProviderOutputKind.ABSTAIN,
                trusted=False,
                degraded=True,
                safe_error="deep model unavailable",
            )
        evidence = "b" * 64 if self.invented_evidence else _EVIDENCE
        output = json.dumps(_payload(evidence=evidence))
        return ProviderResponse(
            invocation_id=invocation.invocation_id,
            provider=ProviderKind.GROQ_ADVISORY,
            model=invocation.model,
            content=output,
            output_sha256=hashlib.sha256(output.encode()).hexdigest(),
            output_kind=ProviderOutputKind.CANDIDATE_ANALYSIS,
            trusted=False,
        )


def test_request_digest_is_bound_and_tampering_is_rejected():
    request = _request()
    assert len(request.context_sha256) == 64
    payload = request.model_dump(mode="json")
    payload["title"] = "Changed after binding"
    with pytest.raises(ValidationError, match="context digest"):
        FindingAnalysisRequest.model_validate(payload)


def test_reasoning_loop_runs_exact_analyst_critic_synthesizer_order():
    connector = FakeConnector()
    report = GroqFindingReasoningLoop(connector=connector).run(_request())

    assert report.status == AnalysisStatus.COMPLETED
    assert tuple(stage.stage for stage in report.stages) == (
        ReasoningStage.ANALYST,
        ReasoningStage.CRITIC,
        ReasoningStage.SYNTHESIZER,
    )
    assert [call.model for call in connector.calls] == [
        "openai/gpt-oss-20b",
        "openai/gpt-oss-20b",
        "openai/gpt-oss-120b",
    ]
    assert report.final is not None
    assert report.final.conclusion == "likely"
    assert report.trusted is False
    assert report.advisory_only is True


def test_deep_model_failure_falls_back_once_to_20b():
    connector = FakeConnector(fail_deep=True)
    report = GroqFindingReasoningLoop(connector=connector).run(_request())

    assert report.status == AnalysisStatus.COMPLETED
    assert [call.model for call in connector.calls] == [
        "openai/gpt-oss-20b",
        "openai/gpt-oss-20b",
        "openai/gpt-oss-120b",
        "openai/gpt-oss-20b",
    ]
    assert len(report.stages) == 3
    assert report.stages[-1].model == "openai/gpt-oss-20b"


def test_model_cannot_invent_evidence_references():
    connector = FakeConnector(invented_evidence=True)
    report = GroqFindingReasoningLoop(connector=connector).run(_request())

    assert report.status == AnalysisStatus.ABSTAINED
    assert report.stages == ()
    assert "not supplied" in (report.safe_error or "")
    assert len(connector.calls) == 1


def test_intelligence_store_is_idempotent_and_persists_report(tmp_path):
    request = _request()
    store = IntelligenceStore(tmp_path)

    assert store.enqueue(request) is True
    assert store.enqueue(request) is False
    claimed = store.claim_next(maximum_attempts=2)
    assert claimed == request

    report = GroqFindingReasoningLoop(connector=FakeConnector()).run(claimed)
    store.complete(report)

    loaded = store.get_report_for_finding(request.finding_id)
    assert loaded == report
    assert store.status_for_finding(request.finding_id) == AnalysisStatus.COMPLETED
    assert store.list_reports_for_run(request.run_id) == (report,)
