"""Bind controlled Active Validation records to the authoritative graph store."""

from __future__ import annotations

import logging
import re
from datetime import UTC, datetime, timedelta
from pathlib import Path

from django.conf import settings

from vulnhunter.adversary_lab.models import LabRecord
from vulnhunter.adversary_lab.store import AdversaryLabStore
from vulnhunter.assessment_graph import (
    ActiveValidationAssessmentGraphService,
    AssessmentGraphError,
    AssessmentGraphService,
)

logger = logging.getLogger(__name__)
_IDENTIFIER_SANITIZER = re.compile(r"[^a-z0-9._-]+")


def _service() -> ActiveValidationAssessmentGraphService:
    return ActiveValidationAssessmentGraphService(Path(settings.VULNHUNTER_TASK_GRAPH_ROOT))


def _owner_id(value: str) -> str:
    normalized = _IDENTIFIER_SANITIZER.sub("-", value.casefold()).strip("-._")
    return (normalized or "validation-operator")[:120]


def parent_workspace_id(assessment_id: str) -> str | None:
    """Resolve the parent assessment's immutable chat-workspace binding."""

    payload = AssessmentGraphService(Path(settings.VULNHUNTER_TASK_GRAPH_ROOT)).status_payload(
        assessment_id
    )
    if payload is None:
        return None
    workspace_id = payload.get("workspace_id")
    return str(workspace_id) if workspace_id else None


def bind_active_validation_assessment_graph(
    record: LabRecord,
    *,
    workspace_id: str | None,
    owner_id: str | None = None,
) -> dict[str, object]:
    """Persist one child graph bound to the exact finding and lab plan digest."""

    service = _service()
    service.create(
        run_id=record.plan.lab_id,
        workspace_id=workspace_id,
        owner_id=_owner_id(owner_id or record.plan.requested_by),
        authorization_id=record.plan.authorization_id,
        assessment_id=record.plan.assessment_id,
        finding_reference=record.plan.finding_reference,
        target_reference=record.plan.target_reference,
        scenario_id=record.plan.scenario_id,
        plan_digest=record.plan.plan_digest,
        expires_at=datetime.now(UTC) + timedelta(hours=24),
        state=record.state.value,
        reason=record.cancellation_reason,
    )
    graph = service.status_payload(record.plan.lab_id)
    if graph is None:
        raise RuntimeError("The Active Validation assessment graph was not persisted.")
    return graph


def project_active_validation_record(record: LabRecord) -> dict[str, object] | None:
    """Project observed SQLite worker state into the existing child graph."""

    service = _service()
    service.project_state(
        record.plan.lab_id,
        state=record.state.value,
        reason=record.cancellation_reason,
    )
    return service.status_payload(record.plan.lab_id)


class ProjectingAdversaryLabStore(AdversaryLabStore):
    """Preserve the lab store as authority while keeping its graph projection current."""

    @staticmethod
    def _project_safely(record: LabRecord) -> None:
        try:
            project_active_validation_record(record)
        except (AssessmentGraphError, OSError, RuntimeError, ValueError):
            logger.exception(
                "Active Validation graph projection failed safely for %s",
                record.plan.lab_id,
            )

    def create(self, record: LabRecord) -> LabRecord:
        """Create first; the web transaction binds the graph immediately afterwards."""

        return super().create(record)

    def save(self, record: LabRecord, *, expected_revision: int) -> LabRecord:
        saved = super().save(record, expected_revision=expected_revision)
        self._project_safely(saved)
        return saved

    def claim_next(self, *, now: datetime) -> LabRecord | None:
        claimed = super().claim_next(now=now)
        if claimed is not None:
            self._project_safely(claimed)
        return claimed


__all__ = [
    "ProjectingAdversaryLabStore",
    "bind_active_validation_assessment_graph",
    "parent_workspace_id",
    "project_active_validation_record",
]
