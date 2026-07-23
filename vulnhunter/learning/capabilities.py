"""Policy broker for AI-proposed high-impact capabilities."""

from __future__ import annotations

from dataclasses import dataclass

from vulnhunter.learning.models import CapabilityAction, CapabilityDecision, CapabilityProposal


class CapabilityPolicyError(RuntimeError):
    pass


@dataclass(frozen=True)
class CapabilityRequirements:
    exact_authorization: bool
    human_approval: bool
    isolated_environment: bool
    deterministic_verification: bool
    required_role: str
    automatically_executable: bool = False


_REQUIREMENTS = {
    CapabilityAction.NETWORK_REQUEST: CapabilityRequirements(
        exact_authorization=True,
        human_approval=True,
        isolated_environment=False,
        deterministic_verification=True,
        required_role="authorization_owner",
    ),
    CapabilityAction.GRANT_AUTHORIZATION: CapabilityRequirements(
        exact_authorization=False,
        human_approval=True,
        isolated_environment=False,
        deterministic_verification=True,
        required_role="authorization_owner",
    ),
    CapabilityAction.CHANGE_SEVERITY: CapabilityRequirements(
        exact_authorization=False,
        human_approval=True,
        isolated_environment=False,
        deterministic_verification=True,
        required_role="security_analyst",
    ),
    CapabilityAction.PUBLISH_RESULT: CapabilityRequirements(
        exact_authorization=False,
        human_approval=True,
        isolated_environment=False,
        deterministic_verification=True,
        required_role="publisher",
    ),
    CapabilityAction.EXPLOIT_ACTION: CapabilityRequirements(
        exact_authorization=True,
        human_approval=True,
        isolated_environment=True,
        deterministic_verification=True,
        required_role="test_environment_owner",
    ),
}


class CapabilityBroker:
    """Allows the model to request power without ever granting power to itself."""

    @staticmethod
    def requirements(proposal: CapabilityProposal) -> CapabilityRequirements:
        return _REQUIREMENTS[proposal.action]

    @staticmethod
    def validate_decision(
        proposal: CapabilityProposal,
        decision: CapabilityDecision,
        *,
        authorization_active: bool,
        isolated_environment: bool,
    ) -> CapabilityRequirements:
        if decision.proposal_id != proposal.proposal_id:
            raise CapabilityPolicyError("capability decision references another proposal")
        requirements = _REQUIREMENTS[proposal.action]
        if not decision.approved:
            raise CapabilityPolicyError("capability proposal was denied")
        if decision.approver_role != requirements.required_role:
            raise CapabilityPolicyError("capability proposal lacks the required human authority")
        if requirements.exact_authorization and not authorization_active:
            raise CapabilityPolicyError("an exact active authorization is required")
        if requirements.isolated_environment and not isolated_environment:
            raise CapabilityPolicyError(
                "this capability is restricted to an approved test environment"
            )
        return requirements
