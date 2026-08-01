from pathlib import Path


def replace_once(path: Path, old: str, new: str, *, label: str) -> None:
    text = path.read_text(encoding="utf-8")
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"Expected exactly one {label} block in {path}, found {count}")
    path.write_text(text.replace(old, new), encoding="utf-8")


path = Path("vulnhunter/web/remediation_assessment_graph.py")
replace_once(
    path,
    '''    _service().create(
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
''',
    '''    _service().create(
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
        state=RemediationState.READY_FOR_IMPLEMENTATION.value,
        reason=None,
    )
    project_remediation_finding(finding)
    graph = _service().status_payload(remediation.remediation_id)
''',
    label="initial remediation graph binding",
)
replace_once(
    path,
    '''    service = _service()
    service.project_state(
        remediation.remediation_id,
        state=remediation.state.value,
        reason=remediation.cancellation_reason,
    )
    if remediation.verification_history:
''',
    '''    service = _service()
    if remediation.state in {
        RemediationState.READY_FOR_IMPLEMENTATION,
        RemediationState.CANCELLED,
        RemediationState.FAILED,
    }:
        service.project_state(
            remediation.remediation_id,
            state=remediation.state.value,
            reason=remediation.cancellation_reason,
        )
    if remediation.verification_history:
''',
    label="receipt-first remediation graph replay",
)

test_path = Path("tests/unit/test_final_remediation_report.py")
replace_once(
    test_path,
    '''        finding_status=FindingStatus.AWAITING_REMEDIATION_REVIEW,
''',
    '''        finding_status=FindingStatus.TRIAGED,
''',
    label="valid non-report-ready fixture",
)
