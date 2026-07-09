"""Runtime policy and scheduling-matrix tests."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from vulnhunter.exceptions import UnattendedPolicyError
from vulnhunter.unattended.models import (
    CommandId,
    ExecutionMode,
    NetworkAccess,
    PermissionManifest,
    TaskProfile,
    ToolCapability,
)
from vulnhunter.unattended.policy import PermissionEnforcer, recommend_execution_mode


def manifest(repository: Path) -> PermissionManifest:
    now = datetime.now(UTC)
    return PermissionManifest(
        manifest_id="manifest-policy",
        loop_id="loop-policy",
        repository_root=repository.resolve(),
        execution_mode=ExecutionMode.LOCAL_SCHEDULED,
        available_tools=(
            ToolCapability.REPOSITORY_READ,
            ToolCapability.REPOSITORY_WRITE,
            ToolCapability.COMMAND_RUNNER,
            ToolCapability.CONNECTOR_READ,
            ToolCapability.SECRET_READ,
            ToolCapability.NETWORK_CLIENT,
        ),
        approved_read_paths=("vulnhunter/**",),
        approved_write_paths=("docs/**",),
        approved_commands=(CommandId.GIT_STATUS,),
        network_access=NetworkAccess.ALLOWLISTED_PUBLIC,
        approved_network_hosts=("github.com",),
        approved_connectors=("github",),
        approved_secret_names=("github-token",),
        created_by="creator.one",
        created_at=now,
        expires_at=now + timedelta(hours=4),
    )


def test_scheduling_matrix_prefers_ci_for_deterministic_checks() -> None:
    result = recommend_execution_mode(TaskProfile(deterministic_checks_only=True))

    assert result.mode == ExecutionMode.CI_WORKFLOW
    assert result.permitted is True


def test_scheduling_matrix_blocks_sensitive_remote_routine() -> None:
    result = recommend_execution_mode(
        TaskProfile(remote_execution_required=True, contains_sensitive_security_data=True)
    )

    assert result.mode is None
    assert result.permitted is False


def test_scheduling_matrix_uses_session_for_temporary_repetition() -> None:
    result = recommend_execution_mode(TaskProfile(temporary_repetition=True))

    assert result.mode == ExecutionMode.SESSION


def test_path_and_destructive_permissions_are_runtime_enforced(tmp_path: Path) -> None:
    enforcer = PermissionEnforcer(manifest(tmp_path))

    assert enforcer.check_path(Path("docs/guide.md"), write=True).allowed is True
    assert enforcer.check_path(Path("vulnhunter/cli.py"), write=True).allowed is False
    assert enforcer.check_path(Path("docs/guide.md"), write=True, delete=True).allowed is False


def test_path_escape_is_rejected(tmp_path: Path) -> None:
    enforcer = PermissionEnforcer(manifest(tmp_path))

    with pytest.raises(UnattendedPolicyError, match="escapes"):
        enforcer.check_path(tmp_path.parent / "outside.txt")


def test_command_connector_secret_and_network_allowlists(tmp_path: Path) -> None:
    enforcer = PermissionEnforcer(manifest(tmp_path))

    assert enforcer.check_command(CommandId.GIT_STATUS.value).allowed is True
    assert enforcer.check_command(CommandId.PYTEST.value).allowed is False
    assert enforcer.check_connector("github").allowed is True
    assert enforcer.check_connector("gmail").allowed is False
    assert enforcer.check_secret("github-token").allowed is True
    assert enforcer.check_secret("other-token").allowed is False
    assert enforcer.check_network(NetworkAccess.ALLOWLISTED_PUBLIC, "github.com").allowed
    assert not enforcer.check_network(NetworkAccess.ALLOWLISTED_PUBLIC, "example.com").allowed
