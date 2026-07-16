"""High-level approval workflows."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from vulnhunter.actions.models import ActionManifest
from vulnhunter.approvals.conditions import CanonicalApprovalExecutionPlan
from vulnhunter.approvals.models import ApprovalDecision, ApprovalRequest
from vulnhunter.approvals.store import ApprovalStore


class ApprovalService:
    def __init__(self, store: ApprovalStore) -> None:
        self.store = store
        self.store.initialize()

    def request(
        self,
        *,
        request_id: str,
        run_id: str,
        manifest: ActionManifest,
        summary: str,
        risk_summary: str,
        ttl_seconds: int = 900,
    ) -> ApprovalRequest:
        instant = datetime.now(UTC)
        request = ApprovalRequest(
            request_id=request_id,
            campaign_id=manifest.campaign_id,
            run_id=run_id,
            action_manifest_sha256=manifest.fingerprint(),
            requested_by=manifest.requested_by,
            summary=summary,
            risk_summary=risk_summary,
            requested_at=instant,
            expires_at=instant + timedelta(seconds=ttl_seconds),
        )
        return self.store.create(request)

    def decide(
        self,
        *,
        request_id: str,
        actor_id: str,
        decision: ApprovalDecision,
        reason: str,
        conditions: tuple[str, ...] = (),
    ) -> ApprovalRequest:
        return self.store.decide(
            request_id=request_id,
            actor_id=actor_id,
            decision=decision,
            reason=reason,
            conditions=conditions,
        )

    def consume(
        self,
        *,
        request_id: str,
        manifest: ActionManifest,
        execution_id: str,
        actor_id: str,
        execution_plan: CanonicalApprovalExecutionPlan | None = None,
    ) -> ApprovalRequest:
        return self.store.consume(
            request_id=request_id,
            action_manifest_sha256=manifest.fingerprint(),
            execution_id=execution_id,
            actor_id=actor_id,
            manifest=manifest,
            execution_plan=execution_plan,
        )
