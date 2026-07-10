from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError

from vulnhunter.agent.models import (
    AgentProposal,
    AgentTask,
    PermissionManifest,
    ProposalKind,
    RuntimeConfig,
    TaskStatus,
    ToolCall,
    ToolRisk,
    ToolSpec,
)


def manifest(**overrides):
    values = {
        "manifest_id": "manifest-one",
        "role_id": "orchestrator",
        "allowed_actions": ("evidence.inspect",),
        "allowed_tools": ("agent.echo",),
    }
    values.update(overrides)
    return PermissionManifest(**values)


def test_manifest_fingerprint_is_deterministic() -> None:
    assert manifest().fingerprint() == manifest().fingerprint()


def test_manifest_rejects_duplicate_actions() -> None:
    with pytest.raises(ValidationError, match="allowed_actions must be unique"):
        manifest(allowed_actions=("evidence.inspect", "evidence.inspect"))


def test_manifest_rejects_network_risk_without_flag() -> None:
    with pytest.raises(ValidationError, match="matching explicit capability flags"):
        manifest(allowed_risks=(ToolRisk.NETWORK,))


def test_manifest_accepts_explicit_network_flag() -> None:
    value = manifest(allowed_risks=(ToolRisk.NETWORK,), allow_network=True)
    assert value.allow_network


def test_tool_call_fingerprint_changes_with_arguments() -> None:
    first = ToolCall(
        tool_id="agent.echo",
        action="evidence.inspect",
        operation="echo",
        arguments={"value": 1},
    )
    second = first.model_copy(update={"arguments": {"value": 2}})
    assert first.fingerprint() != second.fingerprint()


def test_tool_proposal_requires_call() -> None:
    with pytest.raises(ValidationError, match="tool proposals require call"):
        AgentProposal(kind=ProposalKind.TOOL, rationale="Run approved tool")


def test_complete_proposal_requires_summary() -> None:
    with pytest.raises(ValidationError, match="final_summary"):
        AgentProposal(kind=ProposalKind.COMPLETE, rationale="Done")


def test_pause_proposal_requires_reason() -> None:
    with pytest.raises(ValidationError, match="pause_reason"):
        AgentProposal(kind=ProposalKind.PAUSE, rationale="Pause")


def test_agent_task_terminal_states() -> None:
    task = AgentTask(
        task_id="task-one",
        objective="Inspect approved local evidence.",
        permission_manifest=manifest(),
    )
    assert not task.terminal
    assert task.model_copy(update={"status": TaskStatus.COMPLETED}).terminal


def test_evolved_task_increments_revision() -> None:
    task = AgentTask(
        task_id="task-one",
        objective="Inspect approved local evidence.",
        permission_manifest=manifest(),
    )
    evolved = task.evolved(status=TaskStatus.RUNNING)
    assert evolved.revision == 1
    assert evolved.updated_at >= task.updated_at


def test_runtime_config_forbids_enabling_connectors() -> None:
    with pytest.raises(ValidationError):
        RuntimeConfig(connectors_enabled=True)


def test_manifest_can_expire() -> None:
    expired = manifest(expires_at=datetime.now(UTC) - timedelta(seconds=1))
    assert expired.expires_at is not None


def test_tool_spec_fingerprint_is_deterministic() -> None:
    spec = ToolSpec(
        tool_id="agent.echo",
        action="evidence.inspect",
        operation="echo",
        description="Echo approved local evidence.",
    )
    assert spec.fingerprint() == spec.fingerprint()
