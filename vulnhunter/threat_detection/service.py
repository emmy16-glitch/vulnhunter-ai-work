"""Deterministic sequence-based agentic-threat detection."""

from __future__ import annotations

from collections import Counter
from urllib.parse import urlsplit

from vulnhunter.threat_detection.models import (
    AgentActionEvent,
    ContainmentDecision,
    ThreatAssessment,
    ThreatPolicy,
    ThreatRisk,
    ThreatSignal,
    ThreatSignalKind,
)

_RISK_ORDER = {
    ThreatRisk.NONE: 0,
    ThreatRisk.LOW: 1,
    ThreatRisk.MEDIUM: 2,
    ThreatRisk.HIGH: 3,
    ThreatRisk.CRITICAL: 4,
}


class ThreatDetector:
    """Classify suspicious action sequences without granting or executing authority."""

    def __init__(self, policy: ThreatPolicy | None = None) -> None:
        self.policy = policy or ThreatPolicy()

    def assess(self, events: tuple[AgentActionEvent, ...]) -> ThreatAssessment:
        if not events:
            raise ValueError("at least one action event is required")
        execution_ids = {event.execution_id for event in events}
        if len(execution_ids) != 1:
            raise ValueError("all events must belong to one execution")
        ordered = tuple(sorted(events, key=lambda item: (item.created_at, item.event_id)))
        signals: list[ThreatSignal] = []

        secret_events = tuple(event for event in ordered if self._is_secret_access(event))
        if len(secret_events) >= self.policy.secret_access_threshold:
            signals.append(
                self._signal(
                    ThreatSignalKind.REPEATED_SECRET_ACCESS,
                    ThreatRisk.CRITICAL,
                    "Repeated attempts to access secret material exceeded the policy threshold.",
                    secret_events,
                )
            )

        outbound = tuple(event for event in ordered if self._is_unapproved_outbound(event))
        if outbound:
            signals.append(
                self._signal(
                    ThreatSignalKind.UNEXPECTED_OUTBOUND_CONNECTION,
                    ThreatRisk.HIGH,
                    "An outbound destination was outside the configured allowlist.",
                    outbound,
                )
            )

        rule_specs = (
            (
                ThreatSignalKind.PRIVILEGE_ESCALATION_ATTEMPT,
                ThreatRisk.CRITICAL,
                ("privilege.escalate", "sudo", "setuid", "grant_admin", "broker.bypass"),
                "A privilege-escalation or privileged-broker bypass action was proposed.",
            ),
            (
                ThreatSignalKind.SCOPE_EXPANSION_ATTEMPT,
                ThreatRisk.CRITICAL,
                ("scope.expand", "authorization.override", "target.add_unapproved"),
                "An action attempted to expand scope or override authorization.",
            ),
            (
                ThreatSignalKind.PERSISTENCE_ATTEMPT,
                ThreatRisk.HIGH,
                ("persistence.", "cron.install", "service.install", "startup.modify"),
                "An action attempted to create persistence.",
            ),
            (
                ThreatSignalKind.LOGGING_DISABLE_ATTEMPT,
                ThreatRisk.CRITICAL,
                ("audit.disable", "logging.disable", "logs.delete", "history.clear"),
                "An action attempted to disable or remove audit evidence.",
            ),
            (
                ThreatSignalKind.UNAPPROVED_TOOL_DOWNLOAD,
                ThreatRisk.HIGH,
                ("tool.download", "package.install", "binary.fetch"),
                "An action attempted to download or install an unapproved tool.",
            ),
        )
        for kind, risk, markers, reason in rule_specs:
            matched = tuple(
                event
                for event in ordered
                if any(marker in event.action.lower() for marker in markers)
            )
            if matched:
                signals.append(self._signal(kind, risk, reason, matched))

        if len(ordered) > self.policy.maximum_action_chain:
            signals.append(
                self._signal(
                    ThreatSignalKind.EXCESSIVE_ACTION_CHAIN,
                    ThreatRisk.MEDIUM,
                    "The action sequence exceeded the task policy's maximum chain length.",
                    ordered[self.policy.maximum_action_chain :],
                )
            )

        denied_counts = Counter(
            (event.actor_id, event.action, event.target)
            for event in ordered
            if event.outcome.lower() in {"denied", "blocked"}
        )
        repeated_keys = {
            key
            for key, count in denied_counts.items()
            if count >= self.policy.denial_retry_threshold
        }
        repeated = tuple(
            event
            for event in ordered
            if (event.actor_id, event.action, event.target) in repeated_keys
        )
        if repeated:
            signals.append(
                self._signal(
                    ThreatSignalKind.REPEATED_AFTER_DENIAL,
                    ThreatRisk.HIGH,
                    "The same action was repeatedly attempted after policy denial.",
                    repeated,
                )
            )

        untrusted = tuple(
            event
            for event in ordered
            if event.source_trust.lower() in {"untrusted", "external", "unknown"}
            and bool(event.metadata.get("instruction_followed", False))
        )
        if untrusted:
            signals.append(
                self._signal(
                    ThreatSignalKind.UNTRUSTED_INSTRUCTION_FOLLOWING,
                    ThreatRisk.CRITICAL,
                    "An action was derived from an instruction embedded in untrusted content.",
                    untrusted,
                )
            )

        highest = max(
            (signal.risk for signal in signals), key=_RISK_ORDER.get, default=ThreatRisk.NONE
        )
        if highest == ThreatRisk.CRITICAL and self.policy.kill_on_critical:
            decision = ContainmentDecision.KILL
        elif highest in {ThreatRisk.CRITICAL, ThreatRisk.HIGH} and self.policy.pause_on_high:
            decision = ContainmentDecision.PAUSE
        elif highest == ThreatRisk.MEDIUM:
            decision = ContainmentDecision.RESTRICT
        else:
            decision = ContainmentDecision.CONTINUE
        return ThreatAssessment(
            execution_id=ordered[0].execution_id,
            signals=tuple(signals),
            highest_risk=highest,
            decision=decision,
            notify_human=decision in {ContainmentDecision.PAUSE, ContainmentDecision.KILL},
        )

    def _is_secret_access(self, event: AgentActionEvent) -> bool:
        action = event.action.lower()
        return any(
            marker in action for marker in ("secret", "credential", "token.read", "key.read")
        )

    def _is_unapproved_outbound(self, event: AgentActionEvent) -> bool:
        if not event.action.lower().startswith(("network.", "http.", "connector.")):
            return False
        target = event.target or ""
        host = (urlsplit(target).hostname or target.split(":", 1)[0]).lower().rstrip(".")
        if not host:
            return True
        return not any(
            host == allowed or host.endswith(f".{allowed}")
            for allowed in self.policy.outbound_allowlist
        )

    @staticmethod
    def _signal(
        kind: ThreatSignalKind,
        risk: ThreatRisk,
        reason: str,
        events: tuple[AgentActionEvent, ...],
    ) -> ThreatSignal:
        return ThreatSignal(
            kind=kind,
            risk=risk,
            reason=reason,
            event_ids=tuple(event.event_id for event in events),
        )
