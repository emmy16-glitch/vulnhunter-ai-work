"""Bind governed finding remediation plans to the authoritative graph store."""

from __future__ import annotations

from pathlib import Path

from django.conf import settings

from vulnhunter.assessment_graph import RemediationAssessmentGraphService
from vulnhunter.findings import Finding, RemediationState


def _service() -> RemediationAssessmentGraphService:
    return RemediationAssessmentGraphService(Path(settings.VULNHUNTER_TASK_GRAPH_ROOT))


def bind_remediation_assessment_graph(
    finding: Finding,
    *,
    workspace_id: str,
) -> dict[str, object]:
    """Persist the exact plan graph after the CAS finding transition succeeds."""

    remediation = finding.remediation
    if (
        remediation is None
        or remediation.remediation_id is None
        or remediation.plan_sha256 is None
        or remediation.owner_id is None
        or remediation.source_finding_revision is None
        or remediation.source_finding_fingerprint is None
        or remediation.expires_at is None
        or remediation.state is None
    ):
        raise ValueError("the finding has no complete governed remediation plan")
    _service().create(
        remediation_id=remediation.remediation_id,
        workspace_id=workspace_id,
        owner_id=remediation.owner_id,
        campaign_id=finding.campaign_id,
        finding_id=finding.finding_id,
        finding_fingerprint=remediation.source_finding_fingerprint,
        source_finding_revision=remediation.source_finding_revision,
        plan_sha256=remediation.plan_sha256,
        target_references=remediation.target_references,
        expires_at=remediation.expires_at,
        state=remediation.state.value,
        reason=remediation.cancellation_reason,
    )
    graph = _service().status_payload(remediation.remediation_id)
    if graph is None:
        raise RuntimeError("the remediation assessment graph was not persisted")
    return graph


def project_remediation_finding(finding: Finding) -> dict[str, object] | None:
    """Project the current atomic finding state into an existing child graph."""

    remediation = finding.remediation
    if remediation is None or remediation.remediation_id is None or remediation.state is None:
        return None
    service = _service()
    service.project_state(
        remediation.remediation_id,
        state=remediation.state.value,
        reason=remediation.cancellation_reason,
    )
    if remediation.verification_history:
        latest = remediation.verification_history[-1]
        service.project_fix_verification(
            remediation.remediation_id,
            receipt_id=latest.receipt_id,
            verdict=latest.verdict,
        )
    if remediation.retest_history:
        latest_retest = remediation.retest_history[-1]
        service.project_retest_outcome(
            remediation.remediation_id,
            receipt_id=latest_retest.receipt_id,
            outcome=latest_retest.outcome.value,
        )
    if remediation.review_history:
        latest_review = remediation.review_history[-1]
        service.project_review_decision(
            remediation.remediation_id,
            receipt_id=latest_review.receipt_id,
            outcome=latest_review.outcome.value,
        )
    if remediation.report_history:
        latest_report = remediation.report_history[-1]
        service.project_report_generation(
            remediation.remediation_id,
            report_id=latest_report.report_id,
            manifest_id=latest_report.manifest_id,
        )
    return service.status_payload(remediation.remediation_id)


def fail_remediation_graph(remediation_id: str, *, reason: str) -> dict[str, object] | None:
    """Fail a graph closed when workspace projection cannot be completed."""

    _service().project_state(remediation_id, state=RemediationState.FAILED.value, reason=reason)
    return _service().status_payload(remediation_id)


__all__ = [
    "bind_remediation_assessment_graph",
    "fail_remediation_graph",
    "project_remediation_finding",
]
