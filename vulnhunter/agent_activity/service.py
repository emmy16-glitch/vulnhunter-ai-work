"""Application service for safe bounded-agent activity timelines."""

from __future__ import annotations

from datetime import datetime

from vulnhunter.agent_activity.models import (
    TERMINAL_RUN_STATES,
    ActivityEvent,
    ActivityEventDraft,
    ActivityFeedSnapshot,
    ActivityIntegrityResult,
)
from vulnhunter.agent_activity.redaction import (
    redact_metadata,
    sanitize_summary,
)
from vulnhunter.agent_activity.store import AppendOnlyActivityStore


class AgentActivityService:
    """Record and read operational events without exposing hidden reasoning."""

    def __init__(self, store: AppendOnlyActivityStore) -> None:
        self.store = store

    def record(self, draft: ActivityEventDraft) -> ActivityEvent:
        """Redact untrusted metadata and append one real runtime transition."""
        safe_metadata = redact_metadata(draft.metadata)
        if not isinstance(safe_metadata, dict):
            raise TypeError("activity metadata must remain an object")
        safe_draft = draft.model_copy(
            update={
                "summary": sanitize_summary(draft.summary),
                "error_message": (
                    sanitize_summary(draft.error_message) if draft.error_message else None
                ),
                "metadata": safe_metadata,
            }
        )
        return self.store.append(safe_draft)

    def record_transition(
        self,
        *,
        run_id: str,
        timestamp: datetime,
        event_type: str,
        summary: str,
        run_state: str,
        source: str,
        **fields: object,
    ) -> ActivityEvent:
        """Validate a transition through the strict draft model before append."""
        draft = ActivityEventDraft.model_validate(
            {
                "run_id": run_id,
                "timestamp": timestamp,
                "event_type": event_type,
                "summary": summary,
                "run_state": run_state,
                "source": source,
                **fields,
            }
        )
        return self.record(draft)

    def feed(
        self,
        run_id: str,
        *,
        after_sequence: int = 0,
        limit: int = 200,
    ) -> ActivityFeedSnapshot:
        """Return a non-duplicating polling snapshot for one run."""
        events = self.store.read_after(
            run_id,
            after_sequence=after_sequence,
            limit=limit,
        )
        all_events = self.store.read_after(run_id, after_sequence=0, limit=1_000)
        last = all_events[-1] if all_events else None
        return ActivityFeedSnapshot(
            run_id=run_id,
            events=events,
            after_sequence=after_sequence,
            last_sequence=last.sequence if last else 0,
            run_state=last.run_state if last else None,
            terminal=bool(last and last.run_state in TERMINAL_RUN_STATES),
        )

    def request_stop(
        self,
        *,
        run_id: str,
        timestamp: datetime,
        actor_id: str,
        reason: str,
        audit_reference: str | None = None,
    ) -> ActivityEvent:
        """Record a stop request; runtime cancellation remains controller-owned."""
        return self.record_transition(
            run_id=run_id,
            timestamp=timestamp,
            event_type="stop_requested",
            summary="A human operator requested that the bounded run stop.",
            run_state="stopping",
            source="operator",
            audit_reference=audit_reference,
            metadata={"actor_id": actor_id, "reason": reason},
        )

    def verify(self, run_id: str) -> ActivityIntegrityResult:
        """Verify one activity stream's hash chain."""
        return self.store.verify(run_id)
