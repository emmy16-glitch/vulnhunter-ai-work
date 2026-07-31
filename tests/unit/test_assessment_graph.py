from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

import pytest

from vulnhunter.assessment_graph import AssessmentGraphError, AssessmentGraphService

NOW = datetime(2026, 7, 31, 16, 0, tzinfo=UTC)


def _service(tmp_path: Path) -> AssessmentGraphService:
    return AssessmentGraphService(tmp_path / "graphs", clock=lambda: NOW)


def test_website_graph_is_bound_to_chat_workspace_and_exact_manifests(tmp_path):
    service = _service(tmp_path)
    workspace_id = str(uuid4())
    bundle = service.create_website_assessment(
        run_id="assessment-graph-one",
        workspace_id=workspace_id,
        owner_id="operator-a",
        authorization_id="authorization-one",
        target="https://private.lab:443/app",
        expires_at=NOW + timedelta(hours=1),
        profile="passive",
        plan_digest="a" * 64,
        readiness_blocked=False,
    )

    payload = service.status_payload("assessment-graph-one")

    assert payload is not None
    assert payload["workspace_id"] == workspace_id
    assert payload["chat_stage"] == "waiting_for_confirmation"
    assert payload["assessment_kind"] == "website"
    assert len(payload["nodes"]) == 8
    assert len(bundle.manifests) == 8
    assert {item["status"] for item in payload["nodes"][:2]} == {"completed"}
    assert payload["nodes"][2]["status"] == "waiting_for_human_approval"


def test_approval_and_cancellation_project_into_persisted_chat_stage(tmp_path):
    service = _service(tmp_path)
    service.create_website_assessment(
        run_id="assessment-graph-two",
        workspace_id=str(uuid4()),
        owner_id="operator-a",
        authorization_id="authorization-one",
        target="https://private.lab:443/app",
        expires_at=NOW + timedelta(hours=1),
        profile="passive",
        plan_digest="b" * 64,
        readiness_blocked=False,
    )

    assert service.project_approval(
        "assessment-graph-two",
        approved=True,
        execution_intended=True,
        reason="Approved exact plan.",
    )
    payload = service.status_payload("assessment-graph-two")
    assert payload is not None
    assert payload["chat_stage"] == "collecting_evidence"

    assert service.project_terminal(
        "assessment-graph-two",
        outcome="cancelled",
        reason="Operator cancelled from chat.",
    )
    payload = service.status_payload("assessment-graph-two")
    assert payload is not None
    assert payload["chat_stage"] == "cancelled"
    statuses = {item["stage"]: item["status"] for item in payload["nodes"]}
    assert statuses["execution"] == "cancelled"
    assert statuses["report"] == "cancelled"


def test_readiness_blocked_graph_is_terminal_and_truthful(tmp_path):
    service = _service(tmp_path)
    service.create_website_assessment(
        run_id="assessment-graph-three",
        workspace_id=None,
        owner_id="operator-a",
        authorization_id="authorization-one",
        target="https://private.lab:443/app",
        expires_at=NOW + timedelta(hours=1),
        profile="passive",
        plan_digest=None,
        readiness_blocked=True,
    )

    payload = service.status_payload("assessment-graph-three")

    assert payload is not None
    assert payload["chat_stage"] == "blocked"
    statuses = {item["stage"]: item["status"] for item in payload["nodes"]}
    assert statuses["authorization"] == "completed"
    assert statuses["plan"] == "blocked"
    assert statuses["execution"] == "cancelled"


def test_bundle_integrity_tampering_fails_closed(tmp_path):
    service = _service(tmp_path)
    bundle = service.create_website_assessment(
        run_id="assessment-graph-four",
        workspace_id=None,
        owner_id="operator-a",
        authorization_id="authorization-one",
        target="https://private.lab:443/app",
        expires_at=NOW + timedelta(hours=1),
        profile="passive",
        plan_digest="c" * 64,
        readiness_blocked=False,
    )
    path = tmp_path / "graphs" / bundle.graph_id / "assessment-bundle.json"
    envelope = json.loads(path.read_text(encoding="utf-8"))
    envelope["bundle"]["owner_id"] = "attacker"
    path.write_text(json.dumps(envelope), encoding="utf-8")

    with pytest.raises(AssessmentGraphError, match="integrity"):
        service.status_payload("assessment-graph-four")
