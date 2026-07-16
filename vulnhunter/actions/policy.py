"""Fail-closed policy engine for action manifests."""

from __future__ import annotations

from collections.abc import Iterable
from datetime import UTC, datetime

from vulnhunter.actions.models import (
    ActionClass,
    ActionDecision,
    ActionDecisionStatus,
    ActionManifest,
)


class ActionPolicy:
    """Deterministic least-privilege checks independent of any AI planner."""

    def __init__(
        self,
        *,
        known_tools: Iterable[str],
        denied_actions: Iterable[str] = (),
        approval_classes: Iterable[ActionClass] = (
            ActionClass.CONSEQUENTIAL,
            ActionClass.SENSITIVE,
        ),
    ) -> None:
        self._known_tools = frozenset(known_tools)
        self._denied_actions = frozenset(denied_actions)
        self._approval_classes = frozenset(approval_classes)

    def evaluate(
        self,
        manifest: ActionManifest,
        *,
        approval_request_id: str | None = None,
        approval_action_sha256: str | None = None,
        approval_is_active: bool = False,
        now: datetime | None = None,
    ) -> ActionDecision:
        instant = now or datetime.now(UTC)
        digest = manifest.fingerprint()

        if instant >= manifest.expires_at:
            return ActionDecision(
                status=ActionDecisionStatus.DENY,
                reason="The action manifest has expired.",
                manifest_sha256=digest,
            )
        if manifest.action in self._denied_actions:
            return ActionDecision(
                status=ActionDecisionStatus.DENY,
                reason="The action is denied by repository policy.",
                manifest_sha256=digest,
            )
        if manifest.tool_id not in self._known_tools:
            return ActionDecision(
                status=ActionDecisionStatus.DENY,
                reason="The requested tool is not registered.",
                manifest_sha256=digest,
            )
        needs_approval = (
            manifest.approval_required or manifest.action_class in self._approval_classes
        )
        if needs_approval:
            if not approval_is_active:
                return ActionDecision(
                    status=ActionDecisionStatus.REQUIRE_APPROVAL,
                    reason="An active human approval is required.",
                    manifest_sha256=digest,
                    approval_request_id=approval_request_id,
                )
            if approval_action_sha256 != digest:
                return ActionDecision(
                    status=ActionDecisionStatus.DENY,
                    reason="The approval is not bound to this exact action.",
                    manifest_sha256=digest,
                    approval_request_id=approval_request_id,
                )
        return ActionDecision(
            status=ActionDecisionStatus.ALLOW,
            reason="The action passed deterministic policy checks.",
            manifest_sha256=digest,
            approval_request_id=approval_request_id,
        )
