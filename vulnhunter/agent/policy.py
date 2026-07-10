"""Fail-closed policy engine for planner proposals."""

from __future__ import annotations

from datetime import UTC, datetime

from vulnhunter.agent.models import (
    AgentProposal,
    AgentTask,
    PolicyDecision,
    PolicyStatus,
    ProposalKind,
    RuntimeConfig,
    ToolRisk,
    ToolSpec,
)


class AgentPolicyEngine:
    """Authorize proposals using repository and task-level declarations."""

    def __init__(self, config: RuntimeConfig) -> None:
        self.config = config

    def evaluate(
        self,
        task: AgentTask,
        proposal: AgentProposal,
        tool_spec: ToolSpec | None,
        *,
        now: datetime | None = None,
    ) -> PolicyDecision:
        manifest = task.permission_manifest
        proposal_hash = proposal.fingerprint()
        manifest_hash = manifest.fingerprint()
        spec_hash = tool_spec.fingerprint() if tool_spec else None

        def decide(status: PolicyStatus, reason: str) -> PolicyDecision:
            return PolicyDecision(
                status=status,
                reason=reason,
                proposal_sha256=proposal_hash,
                manifest_sha256=manifest_hash,
                tool_spec_sha256=spec_hash,
            )

        if proposal.kind != ProposalKind.TOOL:
            return decide(PolicyStatus.ALLOWED, "No tool execution requested.")
        if proposal.call is None:
            return decide(PolicyStatus.DENIED, "Tool proposal is missing its call.")
        if tool_spec is None:
            return decide(PolicyStatus.DENIED, "Requested tool is not registered.")

        current = now or datetime.now(UTC)
        if manifest.expires_at is not None and current >= manifest.expires_at:
            return decide(PolicyStatus.DENIED, "Permission manifest has expired.")
        if task.step_count > manifest.max_steps:
            return decide(PolicyStatus.DENIED, "Task step budget is exhausted.")
        if task.tool_call_count >= manifest.max_tool_calls:
            return decide(PolicyStatus.DENIED, "Task tool-call budget is exhausted.")

        call = proposal.call
        if call.action in self.config.global_denied_actions:
            return decide(PolicyStatus.DENIED, "Action is globally denied by runtime policy.")
        if call.action not in manifest.allowed_actions:
            return decide(PolicyStatus.DENIED, "Action is not allowed by the task manifest.")
        if call.tool_id not in manifest.allowed_tools:
            return decide(PolicyStatus.DENIED, "Tool is not allowed by the task manifest.")
        if call.tool_id != tool_spec.tool_id:
            return decide(PolicyStatus.DENIED, "Tool declaration does not match the call.")
        if call.action != tool_spec.action:
            return decide(PolicyStatus.DENIED, "Action does not match the tool declaration.")
        if call.operation != tool_spec.operation:
            return decide(PolicyStatus.DENIED, "Operation does not match the tool declaration.")
        if tool_spec.risk not in manifest.allowed_risks:
            return decide(PolicyStatus.DENIED, "Tool risk is not allowed by the task manifest.")

        capability_checks = {
            ToolRisk.NETWORK: manifest.allow_network,
            ToolRisk.CONNECTOR: manifest.allow_connectors and self.config.connectors_enabled,
            ToolRisk.SECRETS: manifest.allow_secrets,
            ToolRisk.GIT_WRITE: manifest.allow_git_write,
            ToolRisk.DEPLOYMENT: manifest.allow_deployment,
        }
        if tool_spec.risk in capability_checks and not capability_checks[tool_spec.risk]:
            return decide(
                PolicyStatus.DENIED,
                f"Tool capability {tool_spec.risk.value} is not enabled.",
            )

        if call.action in manifest.approval_required_actions and not call.approval_reference:
            return decide(
                PolicyStatus.REQUIRES_APPROVAL,
                "Action requires a recorded human approval reference.",
            )

        return decide(PolicyStatus.ALLOWED, "Proposal is within declared runtime limits.")
