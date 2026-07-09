"""Scheduling decisions and runtime permission enforcement."""

from __future__ import annotations

import fnmatch
from datetime import UTC, datetime
from pathlib import Path

from vulnhunter.exceptions import UnattendedPolicyError
from vulnhunter.unattended.models import (
    ActionKind,
    ExecutionMode,
    NetworkAccess,
    PermissionDecision,
    PermissionManifest,
    ScheduleRecommendation,
    TaskProfile,
    ToolCapability,
)

_REMOTE_SENSITIVE_PATTERNS = (
    ".env*",
    "**/.env*",
    "**/*credential*",
    "**/*secret*",
    "**/*customer*",
    "**/*private-target*",
    "**/*target-inventory*",
    "knowledge/raw/**",
    "artifacts/**",
)


def recommend_execution_mode(profile: TaskProfile) -> ScheduleRecommendation:
    """Apply the documented scheduling decision matrix."""
    rationale: list[str] = []
    controls: list[str] = ["explicit permission manifest", "runtime audit events"]

    if profile.remote_execution_required:
        if profile.contains_sensitive_security_data:
            return ScheduleRecommendation(
                mode=None,
                permitted=False,
                rationale=("Sensitive security data must stay out of remote routines by default.",),
                required_controls=(
                    "Use an interactive or local scheduled loop instead.",
                    "A remote exception requires explicit approval and all technical protections.",
                ),
            )
        rationale.append("The task explicitly requires remote execution.")
        controls.extend(
            (
                "minimal repository access",
                "at most one connector",
                "no push, delete, or deploy permission",
            )
        )
        return ScheduleRecommendation(
            mode=ExecutionMode.REMOTE_ROUTINE,
            permitted=True,
            rationale=tuple(rationale),
            required_controls=tuple(controls),
        )

    if profile.deterministic_checks_only:
        rationale.append("The task consists only of deterministic checks.")
        controls.extend(("fixed verifier registry", "no arbitrary shell commands"))
        return ScheduleRecommendation(
            mode=ExecutionMode.CI_WORKFLOW,
            permitted=True,
            rationale=tuple(rationale),
            required_controls=tuple(controls),
        )

    if profile.requires_supervision:
        rationale.append("The task requires ongoing human supervision.")
        return ScheduleRecommendation(
            mode=ExecutionMode.INTERACTIVE_GOAL,
            permitted=True,
            rationale=tuple(rationale),
            required_controls=tuple(controls),
        )

    if profile.temporary_repetition:
        rationale.append("The repetition is temporary and session-bounded.")
        controls.append("short expiry")
        return ScheduleRecommendation(
            mode=ExecutionMode.SESSION,
            permitted=True,
            rationale=tuple(rationale),
            required_controls=tuple(controls),
        )

    if profile.private_repository_work:
        rationale.append("The work is recurring and limited to a private local repository.")
        controls.extend(("local scheduler", "private repository only"))
        return ScheduleRecommendation(
            mode=ExecutionMode.LOCAL_SCHEDULED,
            permitted=True,
            rationale=tuple(rationale),
            required_controls=tuple(controls),
        )

    rationale.append("No unattended mode is justified by the supplied profile.")
    return ScheduleRecommendation(
        mode=ExecutionMode.INTERACTIVE_GOAL,
        permitted=True,
        rationale=tuple(rationale),
        required_controls=tuple(controls),
    )


class PermissionEnforcer:
    """Enforce manifest permissions at runtime rather than through prompts."""

    def __init__(self, manifest: PermissionManifest) -> None:
        self.manifest = manifest
        self.repository_root = manifest.repository_root.expanduser().resolve()

    def check_tool(self, tool: ToolCapability) -> PermissionDecision:
        return self._decision(
            ActionKind.TOOL,
            tool.value,
            tool in self.manifest.available_tools,
            "Tool is explicitly granted."
            if tool in self.manifest.available_tools
            else "Tool is not granted.",
        )

    def check_command(self, command_id: str) -> PermissionDecision:
        allowed = command_id in {item.value for item in self.manifest.approved_commands}
        return self._decision(
            ActionKind.COMMAND,
            command_id,
            allowed,
            "Command is in the fixed approved registry." if allowed else "Command is not approved.",
        )

    def check_path(
        self, path: Path, *, write: bool = False, delete: bool = False
    ) -> PermissionDecision:
        action = (
            ActionKind.DELETE_PATH
            if delete
            else ActionKind.WRITE_PATH
            if write
            else ActionKind.READ_PATH
        )
        relative = self._relative_path(path)
        patterns = (
            self.manifest.approved_write_paths
            if write or delete
            else self.manifest.approved_read_paths
        )
        capability = (
            ToolCapability.REPOSITORY_WRITE if write or delete else ToolCapability.REPOSITORY_READ
        )
        allowed = capability in self.manifest.available_tools and any(
            fnmatch.fnmatch(relative, pattern) for pattern in patterns
        )
        rationale = (
            "Path and capability are explicitly granted."
            if allowed
            else "Path or capability is not granted."
        )
        if delete and not self.manifest.allow_delete:
            allowed = False
            rationale = "Deletion is not permitted by this manifest."
        if allowed and self.manifest.execution_mode == ExecutionMode.REMOTE_ROUTINE:
            if any(fnmatch.fnmatch(relative, pattern) for pattern in _REMOTE_SENSITIVE_PATTERNS):
                approval = self.manifest.remote_sensitive_approval
                if approval is None or approval.expires_at <= datetime.now(UTC):
                    allowed = False
                    rationale = "Remote access to sensitive paths lacks active protected approval."
        return self._decision(action, relative, allowed, rationale)

    def check_network(self, access: NetworkAccess, host: str = "") -> PermissionDecision:
        levels = {
            NetworkAccess.NONE: 0,
            NetworkAccess.LOOPBACK: 1,
            NetworkAccess.PRIVATE_LAB: 2,
            NetworkAccess.ALLOWLISTED_PUBLIC: 3,
        }
        allowed = (
            ToolCapability.NETWORK_CLIENT in self.manifest.available_tools
            and levels[access] <= levels[self.manifest.network_access]
        )
        normalized_host = host.strip().lower()
        if access == NetworkAccess.ALLOWLISTED_PUBLIC:
            allowed = allowed and normalized_host in self.manifest.approved_network_hosts
        if access == NetworkAccess.PRIVATE_LAB:
            allowed = allowed and bool(self.manifest.target_authorization_ids)
        return self._decision(
            ActionKind.NETWORK,
            f"{access.value}:{normalized_host}",
            allowed,
            "Network class and destination are approved."
            if allowed
            else "Network access is not approved.",
        )

    def check_connector(self, connector: str, *, write: bool = False) -> PermissionDecision:
        normalized = connector.strip().lower()
        capability = ToolCapability.CONNECTOR_WRITE if write else ToolCapability.CONNECTOR_READ
        allowed = (
            capability in self.manifest.available_tools
            and normalized in self.manifest.approved_connectors
        )
        return self._decision(
            ActionKind.CONNECTOR,
            normalized,
            allowed,
            "Connector is explicitly approved." if allowed else "Connector is not approved.",
        )

    def check_secret(self, secret_name: str) -> PermissionDecision:
        normalized = secret_name.strip().lower()
        allowed = (
            ToolCapability.SECRET_READ in self.manifest.available_tools
            and normalized in self.manifest.approved_secret_names
        )
        return self._decision(
            ActionKind.SECRET,
            normalized,
            allowed,
            "Named secret access is approved." if allowed else "Secret access is not approved.",
        )

    def check_git_push(self) -> PermissionDecision:
        return self._decision(
            ActionKind.GIT_PUSH,
            "git_push",
            self.manifest.allow_git_push,
            "Git push is explicitly approved."
            if self.manifest.allow_git_push
            else "Git push is prohibited.",
        )

    def check_deploy(self) -> PermissionDecision:
        return self._decision(
            ActionKind.DEPLOY,
            "deploy",
            self.manifest.allow_deploy,
            "Deployment is explicitly approved."
            if self.manifest.allow_deploy
            else "Deployment is prohibited.",
        )

    def require(self, decision: PermissionDecision) -> PermissionDecision:
        """Raise when a runtime action is denied."""
        if not decision.allowed:
            raise UnattendedPolicyError(decision.rationale)
        return decision

    def _relative_path(self, path: Path) -> str:
        candidate = path if path.is_absolute() else self.repository_root / path
        resolved = candidate.expanduser().resolve(strict=False)
        try:
            relative = resolved.relative_to(self.repository_root).as_posix()
        except ValueError as exc:
            raise UnattendedPolicyError("Path escapes the approved repository root.") from exc
        return relative or "."

    @staticmethod
    def _decision(
        action: ActionKind, value: str, allowed: bool, rationale: str
    ) -> PermissionDecision:
        return PermissionDecision(
            action=action,
            value=value,
            allowed=allowed,
            rationale=rationale,
            checked_at=datetime.now(UTC),
        )
