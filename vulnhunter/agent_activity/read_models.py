"""Framework-neutral read models for an activity timeline endpoint."""

from __future__ import annotations

from vulnhunter.agent_activity.models import (
    ActivityEvent,
    ActivityFeedSnapshot,
)


def event_to_public_dict(event: ActivityEvent) -> dict[str, object]:
    """Convert one already-redacted event into a stable public read model."""
    return {
        "event_id": event.event_id,
        "run_id": event.run_id,
        "sequence": event.sequence,
        "timestamp": event.timestamp.isoformat(),
        "event_type": event.event_type,
        "summary": event.summary,
        "run_state": event.run_state,
        "source": event.source,
        "role_id": event.role_id,
        "skill_id": event.skill_id,
        "tool_id": event.tool_id,
        "authorization_reference": event.authorization_reference,
        "scope_reference": event.scope_reference,
        "policy_outcome": event.policy_outcome,
        "approval_requirement": event.approval_requirement,
        "approval_state": event.approval_state,
        "execution_state": event.execution_state,
        "risk_level": event.risk_level,
        "audit_reference": event.audit_reference,
        "error_code": event.error_code,
        "error_message": event.error_message,
        "metadata": event.metadata,
        "event_sha256": event.event_sha256,
    }


def snapshot_to_public_dict(snapshot: ActivityFeedSnapshot) -> dict[str, object]:
    """Return the endpoint contract consumed by the polling timeline component."""
    return {
        "run_id": snapshot.run_id,
        "events": [event_to_public_dict(event) for event in snapshot.events],
        "after_sequence": snapshot.after_sequence,
        "last_sequence": snapshot.last_sequence,
        "run_state": snapshot.run_state,
        "terminal": snapshot.terminal,
    }
