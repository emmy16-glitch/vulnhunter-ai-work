"""Bounded analyst, critic, and synthesizer reasoning over sanitised findings."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable
from typing import Protocol
from uuid import uuid4

from pydantic import ValidationError

from vulnhunter.intelligence.models import (
    AdvisoryStagePayload,
    AdvisoryStageResult,
    AnalysisStatus,
    FindingAnalysisRequest,
    FindingIntelligenceReport,
    ReasoningStage,
)
from vulnhunter.providers import (
    ProviderCapability,
    ProviderInvocation,
    ProviderKind,
    ProviderOutputKind,
    ProviderResponse,
)
from vulnhunter.security import redact_text
from vulnhunter.security_tools.scanner_protocol import ScannerCandidateObservation


class IntelligenceAnalysisError(RuntimeError):
    pass


class AdvisoryConnector(Protocol):
    def invoke(
        self,
        invocation: ProviderInvocation,
        content: str,
        *,
        cancelled: Callable[[], bool] | None = None,
    ) -> ProviderResponse: ...


def build_analysis_request(
    *,
    finding_id: str,
    run_id: str,
    campaign_id: str,
    candidate: ScannerCandidateObservation,
    verification,
    capsule,
) -> FindingAnalysisRequest:
    evidence = tuple(dict.fromkeys(str(value) for value in capsule.evidence_hashes))
    observations = tuple(
        redact_text(f"{item.observation_type}:{item.value}")[:500]
        for item in capsule.structured_observations
    )
    seed = f"{finding_id}:{capsule.capsule_hash()}"
    analysis_id = f"analysis-{hashlib.sha256(seed.encode()).hexdigest()[:24]}"
    strategy = getattr(verification.strategy, "value", verification.strategy)
    verdict = getattr(verification.verdict, "value", verification.verdict)
    return FindingAnalysisRequest.create(
        analysis_id=analysis_id,
        finding_id=finding_id,
        run_id=run_id,
        campaign_id=campaign_id,
        title=redact_text(candidate.title),
        scanner_severity=redact_text(candidate.severity),
        scanner_confidence=redact_text(candidate.confidence),
        verification_verdict=redact_text(str(verdict)),
        verification_strategy=redact_text(str(strategy)),
        scanner_template_id=redact_text(candidate.template_id or "unknown"),
        target_identity=capsule.target_identity,
        evidence_sha256=evidence,
        safe_observations=observations,
        created_at=capsule.created_at,
    )


class GroqFindingReasoningLoop:
    """Run exactly analyst -> critic -> synthesizer, with one model fallback."""

    def __init__(
        self,
        *,
        connector: AdvisoryConnector,
        primary_model: str = "openai/gpt-oss-20b",
        deep_model: str = "openai/gpt-oss-120b",
        timeout_seconds: int = 90,
        maximum_input_bytes: int = 64_000,
        maximum_output_tokens: int = 2_400,
    ) -> None:
        if not primary_model.strip() or not deep_model.strip():
            raise IntelligenceAnalysisError("both advisory models must be configured")
        if not 5 <= timeout_seconds <= 180:
            raise IntelligenceAnalysisError(
                "intelligence timeout must be between 5 and 180 seconds"
            )
        self.connector = connector
        self.primary_model = primary_model.strip()
        self.deep_model = deep_model.strip()
        self.timeout_seconds = timeout_seconds
        self.maximum_input_bytes = maximum_input_bytes
        self.maximum_output_tokens = maximum_output_tokens

    def run(
        self,
        request: FindingAnalysisRequest,
        *,
        cancelled: Callable[[], bool] | None = None,
    ) -> FindingIntelligenceReport:
        stages: list[AdvisoryStageResult] = []
        try:
            analyst = self._stage(
                request=request,
                stage=ReasoningStage.ANALYST,
                model=self.primary_model,
                task=(
                    "Develop evidence-bound vulnerability hypotheses. Separate observations from "
                    "assumptions, identify missing context, and prefer abstention over unsupported "
                    "claims. Do not claim exploitation or verification."
                ),
                prior={},
                cancelled=cancelled,
            )
            stages.append(analyst)

            critic = self._stage(
                request=request,
                stage=ReasoningStage.CRITIC,
                model=self.primary_model,
                task=(
                    "Challenge the analyst. Look for false positives, missing preconditions, "
                    "contradicting evidence, overconfident CWE mappings, and safer explanations. "
                    "Do not merely repeat the analyst."
                ),
                prior={"analyst": analyst.payload.model_dump(mode="json")},
                cancelled=cancelled,
            )
            stages.append(critic)

            try:
                synthesizer = self._stage(
                    request=request,
                    stage=ReasoningStage.SYNTHESIZER,
                    model=self.deep_model,
                    task=(
                        "Reconcile the analyst and critic into the final advisory conclusion. "
                        "Keep only evidence-supported claims, clearly state uncertainty, suggest "
                        "non-destructive verification, and provide practical remediation options."
                    ),
                    prior={
                        "analyst": analyst.payload.model_dump(mode="json"),
                        "critic": critic.payload.model_dump(mode="json"),
                    },
                    cancelled=cancelled,
                )
            except IntelligenceAnalysisError:
                if self.deep_model == self.primary_model:
                    raise
                synthesizer = self._stage(
                    request=request,
                    stage=ReasoningStage.SYNTHESIZER,
                    model=self.primary_model,
                    task=(
                        "Reconcile the analyst and critic into the final advisory conclusion. "
                        "The larger model was unavailable, so be especially conservative and "
                        "abstain where the supplied evidence is insufficient."
                    ),
                    prior={
                        "analyst": analyst.payload.model_dump(mode="json"),
                        "critic": critic.payload.model_dump(mode="json"),
                    },
                    cancelled=cancelled,
                )
            stages.append(synthesizer)
        except IntelligenceAnalysisError as exc:
            return FindingIntelligenceReport(
                analysis_id=request.analysis_id,
                finding_id=request.finding_id,
                run_id=request.run_id,
                status=AnalysisStatus.ABSTAINED,
                stages=tuple(stages),
                final=None,
                models=tuple(dict.fromkeys(stage.model for stage in stages)),
                safe_error=str(exc)[:1_000],
                created_at=request.created_at,
            )

        return FindingIntelligenceReport(
            analysis_id=request.analysis_id,
            finding_id=request.finding_id,
            run_id=request.run_id,
            status=AnalysisStatus.COMPLETED,
            stages=tuple(stages),
            final=stages[-1].payload,
            models=tuple(dict.fromkeys(stage.model for stage in stages)),
            created_at=request.created_at,
        )

    def _stage(
        self,
        *,
        request: FindingAnalysisRequest,
        stage: ReasoningStage,
        model: str,
        task: str,
        prior: dict[str, object],
        cancelled: Callable[[], bool] | None,
    ) -> AdvisoryStageResult:
        prompt = self._prompt(request=request, stage=stage, task=task, prior=prior)
        raw = prompt.encode("utf-8")
        if len(raw) > self.maximum_input_bytes:
            raise IntelligenceAnalysisError(
                "bounded intelligence context exceeded its byte limit"
            )
        invocation_id = f"{stage.value}-{uuid4().hex[:20]}"
        invocation = ProviderInvocation(
            invocation_id=invocation_id,
            request_id=request.analysis_id,
            provider=ProviderKind.GROQ_ADVISORY,
            model=model,
            capability=ProviderCapability.CLASSIFICATION,
            input_sha256=hashlib.sha256(raw).hexdigest(),
            maximum_input_characters=min(100_000, self.maximum_input_bytes),
            maximum_output_characters=20_000,
            maximum_input_bytes=self.maximum_input_bytes,
            maximum_output_bytes=24_000,
            maximum_input_tokens=min(16_000, max(1, self.maximum_input_bytes // 4)),
            maximum_output_tokens=self.maximum_output_tokens,
            timeout_seconds=self.timeout_seconds,
        )
        response = self.connector.invoke(invocation, prompt, cancelled=cancelled)
        if response.output_kind == ProviderOutputKind.ABSTAIN:
            raise IntelligenceAnalysisError(
                response.safe_error or f"{stage.value} advisory stage abstained"
            )
        try:
            payload = AdvisoryStagePayload.model_validate_json(response.content)
        except ValidationError as exc:
            raise IntelligenceAnalysisError(
                f"{stage.value} returned invalid structured analysis"
            ) from exc
        self._validate_evidence_binding(request, payload)
        return AdvisoryStageResult(
            stage=stage,
            model=response.model,
            reasoning_effort="low",
            payload=payload,
            output_sha256=response.output_sha256,
        )

    @staticmethod
    def _validate_evidence_binding(
        request: FindingAnalysisRequest,
        payload: AdvisoryStagePayload,
    ) -> None:
        allowed = set(request.evidence_sha256)
        referenced = {
            reference
            for hypothesis in payload.hypotheses
            for reference in (
                *hypothesis.evidence_refs,
                *hypothesis.contradicting_evidence_refs,
            )
        }
        if referenced - allowed:
            raise IntelligenceAnalysisError(
                "model referenced evidence that was not supplied to the advisory session"
            )

    @staticmethod
    def _prompt(
        *,
        request: FindingAnalysisRequest,
        stage: ReasoningStage,
        task: str,
        prior: dict[str, object],
    ) -> str:
        envelope = {
            "stage": stage.value,
            "task": task,
            "security_boundary": {
                "advisory_only": True,
                "no_tools": True,
                "no_network_requests": True,
                "no_authorization_decisions": True,
                "no_final_severity_decisions": True,
                "no_publication": True,
                "no_exploitation": True,
            },
            "finding_context": request.model_dump(mode="json"),
            "prior_stage_outputs": prior,
            "required_content_schema": AdvisoryStagePayload.model_json_schema(),
        }
        return (
            "Return exactly one provider response object. Set output_kind to "
            "CANDIDATE_ANALYSIS. Set content to a JSON-encoded string that validates against "
            "required_content_schema. Do not include markdown or hidden reasoning. "
            + json.dumps(envelope, sort_keys=True, separators=(",", ":"))
        )
