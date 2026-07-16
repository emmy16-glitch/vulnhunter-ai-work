from __future__ import annotations

from datetime import UTC, datetime, timedelta

from vulnhunter.agent.models import (
    AgentProposal,
    AgentTask,
    PermissionManifest,
    PolicyStatus,
    ProposalKind,
    RuntimeConfig,
    ToolCall,
    ToolRisk,
    ToolSpec,
)
from vulnhunter.agent.policy import AgentPolicyEngine


def build(
    *,
    action: str = "evidence.inspect",
    tool_id: str = "agent.echo",
    operation: str = "echo",
    risk: ToolRisk = ToolRisk.READ_ONLY,
    manifest_overrides=None,
    approval_reference=None,
):
    values = {
        "manifest_id": "manifest-policy",
        "role_id": "orchestrator",
        "allowed_actions": ("evidence.inspect",),
        "allowed_tools": ("agent.echo",),
        "allowed_risks": (ToolRisk.READ_ONLY,),
    }
    values.update(manifest_overrides or {})
    manifest = PermissionManifest(**values)
    task = AgentTask(
        task_id="task-policy",
        objective="Evaluate a bounded local agent action.",
        permission_manifest=manifest,
    )
    call = ToolCall(
        tool_id=tool_id,
        action=action,
        operation=operation,
        approval_reference=approval_reference,
    )
    proposal = AgentProposal(
        kind=ProposalKind.TOOL,
        rationale="Use an approved tool",
        call=call,
    )
    spec = ToolSpec(
        tool_id="agent.echo",
        action="evidence.inspect",
        operation="echo",
        description="Echo approved local evidence.",
        risk=risk,
    )
    return task, proposal, spec


def decision(**kwargs):
    task, proposal, spec = build(**kwargs)
    return AgentPolicyEngine(RuntimeConfig()).evaluate(task, proposal, spec)


def test_allowed_read_only_action() -> None:
    assert decision().status == PolicyStatus.ALLOWED


def test_unregistered_tool_is_denied() -> None:
    task, proposal, _ = build()
    result = AgentPolicyEngine(RuntimeConfig()).evaluate(task, proposal, None)
    assert result.status == PolicyStatus.DENIED


def test_action_not_in_manifest_is_denied() -> None:
    assert decision(action="scan.run").status == PolicyStatus.DENIED


def test_tool_not_in_manifest_is_denied() -> None:
    assert decision(tool_id="agent.other").status == PolicyStatus.DENIED


def test_operation_mismatch_is_denied() -> None:
    assert decision(operation="other").status == PolicyStatus.DENIED


def test_global_denied_action_is_denied() -> None:
    result = decision(
        action="git.push",
        manifest_overrides={"allowed_actions": ("git.push",)},
    )
    assert result.status == PolicyStatus.DENIED


def test_network_risk_is_denied_without_flag() -> None:
    result = decision(risk=ToolRisk.NETWORK)
    assert result.status == PolicyStatus.DENIED


def test_network_risk_is_allowed_with_explicit_flag() -> None:
    result = decision(
        risk=ToolRisk.NETWORK,
        manifest_overrides={
            "allowed_risks": (ToolRisk.NETWORK,),
            "allow_network": True,
        },
    )
    assert result.status == PolicyStatus.ALLOWED


def test_connector_remains_denied_by_global_config() -> None:
    result = decision(
        risk=ToolRisk.CONNECTOR,
        manifest_overrides={
            "allowed_risks": (ToolRisk.CONNECTOR,),
            "allow_connectors": True,
        },
    )
    assert result.status == PolicyStatus.DENIED


def test_approval_action_pauses_without_reference() -> None:
    result = decision(
        manifest_overrides={
            "approval_required_actions": ("evidence.inspect",),
        }
    )
    assert result.status == PolicyStatus.REQUIRES_APPROVAL


def test_approval_action_rejects_caller_supplied_reference() -> None:
    result = decision(
        approval_reference="approval-123",
        manifest_overrides={
            "approval_required_actions": ("evidence.inspect",),
        },
    )
    assert result.status == PolicyStatus.DENIED
    assert "not produced" in result.reason


def test_expired_manifest_is_denied() -> None:
    result = decision(
        manifest_overrides={
            "expires_at": datetime.now(UTC) - timedelta(seconds=1),
        }
    )
    assert result.status == PolicyStatus.DENIED


def test_exhausted_tool_budget_is_denied() -> None:
    task, proposal, spec = build(manifest_overrides={"max_tool_calls": 1})
    task = task.model_copy(update={"tool_call_count": 1})
    result = AgentPolicyEngine(RuntimeConfig()).evaluate(task, proposal, spec)
    assert result.status == PolicyStatus.DENIED
