"""Bind governed retest plans and outcomes to authoritative task graphs."""

from __future__ import annotations

from pathlib import Path

from django.conf import settings

from vulnhunter.assessment_graph import RetestAssessmentGraphService
from vulnhunter.findings import Finding


def _service() -> RetestAssessmentGraphService:
    return RetestAssessmentGraphService(Path(settings.VULNHUNTER_TASK_GRAPH_ROOT))


def _active_plan(finding: Finding):
    completed = {item.retest_id for item in finding.retest_results}
    active = [item for item in finding.retest_plans if item.retest_id not in completed]
    if len(active) != 1:
        raise ValueError("the finding does not have one active governed retest")
    return active[0]


def bind_retest_assessment_graph(
    finding: Finding,
    *,
    workspace_id: str,
) -> dict[str, object]:
    """Persist the child graph after the atomic retest-plan transition succeeds."""

    plan = _active_plan(finding)
    remediation = finding.remediation
    if remediation is None or remediation.remediation_id is None:
        raise ValueError("the retest has no governed remediation binding")
    _service().create(
        retest_id=plan.retest_id,
        workspace_id=workspace_id,
        owner_id=plan.owner_id,
        campaign_id=finding.campaign_id,
        finding_id=finding.finding_id,
        finding_fingerprint=plan.source_finding_fingerprint,
        source_finding_revision=plan.source_finding_revision,
        remediation_id=plan.remediation_id,
        fix_verification_receipt_id=plan.fix_verification_receipt_id,
        fixed_revision=plan.fixed_revision,
        plan_sha256=plan.plan_sha256,
        check_references=plan.check_references,
        expires_at=plan.expires_at,
    )
    graph = _service().status_payload(plan.retest_id)
    if graph is None:
        raise RuntimeError("the governed retest graph was not persisted")
    return graph


def project_retest_finding(finding: Finding) -> dict[str, object] | None:
    """Project the latest governed retest result into its existing child graph."""

    if not finding.retest_plans:
        return None
    plan = finding.retest_plans[-1]
    result = next(
        (item for item in reversed(finding.retest_results) if item.retest_id == plan.retest_id),
        None,
    )
    service = _service()
    if result is not None:
        service.project_outcome(
            plan.retest_id,
            receipt_id=result.receipt_id,
            outcome=result.outcome.value,
        )
    return service.status_payload(plan.retest_id)


__all__ = [
    "bind_retest_assessment_graph",
    "project_retest_finding",
]
