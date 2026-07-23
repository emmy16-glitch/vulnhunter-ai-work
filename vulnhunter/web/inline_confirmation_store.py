"""Passive exact-plan confirmation for the single-account chat workspace.

This is deliberately narrower than the general approval workflow. It permits the
requesting user to confirm only an already-authorized, immutable passive Nuclei
plan. Standard, intrusive and retest profiles remain governed by the normal
independent approval path.
"""

from __future__ import annotations

from datetime import UTC, datetime

from vulnhunter.approvals import ApprovalDecision, ApprovalRequest, ApprovalStatus
from vulnhunter.approvals.store import ApprovalConflictError, ApprovalStore


class InlineConfirmationStore(ApprovalStore):
    """Record one attributable requester confirmation for an exact passive plan."""

    def confirm_exact_passive_plan(
        self,
        *,
        request_id: str,
        actor_id: str,
        action_manifest_sha256: str,
        profile: str,
        reason: str,
        now: datetime | None = None,
    ) -> ApprovalRequest:
        safe_reason = reason.strip()
        if len(safe_reason) < 8:
            raise ApprovalConflictError(
                "Exact-plan confirmation requires a reason of at least eight characters."
            )
        if profile != "passive":
            raise ApprovalConflictError(
                "Inline confirmation is available only for the reviewed passive profile."
            )

        instant = (now or datetime.now(UTC)).astimezone(UTC)
        self.initialize()
        with self._connect(write=True) as connection:
            current = self._load_locked(connection, request_id)
            if current.requested_by != actor_id:
                raise ApprovalConflictError(
                    "Only the assessment requester may confirm this passive plan inline."
                )
            if current.action_manifest_sha256 != action_manifest_sha256:
                raise ApprovalConflictError(
                    "The confirmation is bound to a different command-plan digest."
                )
            if current.status not in {
                ApprovalStatus.PENDING,
                ApprovalStatus.INFORMATION_REQUIRED,
                ApprovalStatus.CONDITIONS_PROPOSED,
            }:
                raise ApprovalConflictError(
                    f"The plan cannot be confirmed from {current.status.value}."
                )
            if instant >= current.expires_at:
                expired = current.model_copy(update={"status": ApprovalStatus.EXPIRED})
                expired = ApprovalRequest.model_validate(expired.model_dump())
                self._save_locked(connection, expired)
                self._append_event(
                    connection,
                    request_id=request_id,
                    event_type="exact_plan_confirmation_expired",
                    actor_id=actor_id,
                    detail={"profile": profile},
                )
                raise ApprovalConflictError("The exact command plan has expired.")

            confirmed = current.model_copy(
                update={
                    "status": ApprovalStatus.APPROVED,
                    "decided_by": actor_id,
                    "decision": ApprovalDecision.APPROVE_ONCE,
                    "decision_reason": safe_reason,
                    "conditions": (
                        "Exact target, port, reviewed templates, rate limit and concurrency only.",
                    ),
                    "decided_at": instant,
                }
            )
            confirmed = ApprovalRequest.model_validate(confirmed.model_dump())
            self._save_locked(connection, confirmed)
            self._append_event(
                connection,
                request_id=request_id,
                event_type="exact_passive_plan_confirmed",
                actor_id=actor_id,
                detail={
                    "profile": profile,
                    "action_manifest_sha256": action_manifest_sha256,
                    "confirmation_kind": "single_account_exact_plan",
                },
            )
        return confirmed
