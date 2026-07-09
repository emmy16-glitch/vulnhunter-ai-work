"""Contract tests for unattended permission manifests."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from pydantic import ValidationError

from vulnhunter.unattended.models import (
    CommandId,
    ExecutionMode,
    NetworkAccess,
    PermissionManifest,
    SensitiveRemoteApproval,
    ToolCapability,
)


def manifest_data(repository: Path) -> dict[str, object]:
    now = datetime.now(UTC)
    return {
        "manifest_id": "manifest-test",
        "loop_id": "loop-test",
        "repository_root": repository.resolve(),
        "execution_mode": ExecutionMode.LOCAL_SCHEDULED,
        "available_tools": (
            ToolCapability.REPOSITORY_READ,
            ToolCapability.COMMAND_RUNNER,
        ),
        "approved_read_paths": ("vulnhunter/**",),
        "approved_commands": (CommandId.GIT_STATUS,),
        "required_completion_commands": (CommandId.GIT_STATUS,),
        "created_by": "creator.one",
        "created_at": now,
        "expires_at": now + timedelta(hours=4),
    }


def test_commands_require_command_runner(tmp_path: Path) -> None:
    data = manifest_data(tmp_path)
    data["available_tools"] = (ToolCapability.REPOSITORY_READ,)

    with pytest.raises(ValidationError, match="command_runner"):
        PermissionManifest(**data)


def test_private_lab_network_requires_authorization_ids(tmp_path: Path) -> None:
    data = manifest_data(tmp_path)
    data["available_tools"] = (
        ToolCapability.REPOSITORY_READ,
        ToolCapability.COMMAND_RUNNER,
        ToolCapability.NETWORK_CLIENT,
    )
    data["network_access"] = NetworkAccess.PRIVATE_LAB

    with pytest.raises(ValidationError, match="authorization IDs"):
        PermissionManifest(**data)


def test_remote_routine_rejects_destructive_permissions(tmp_path: Path) -> None:
    data = manifest_data(tmp_path)
    data["execution_mode"] = ExecutionMode.REMOTE_ROUTINE
    data["allow_git_push"] = True

    with pytest.raises(ValidationError, match="cannot push, delete, or deploy"):
        PermissionManifest(**data)


def test_remote_secret_requires_all_technical_protections(tmp_path: Path) -> None:
    data = manifest_data(tmp_path)
    data["execution_mode"] = ExecutionMode.REMOTE_ROUTINE
    data["available_tools"] = (
        ToolCapability.REPOSITORY_READ,
        ToolCapability.COMMAND_RUNNER,
        ToolCapability.SECRET_READ,
    )
    data["approved_secret_names"] = ("github-token",)
    now = datetime.now(UTC)
    data["remote_sensitive_approval"] = {
        "approved_by": "security.owner",
        "approved_at": now,
        "expires_at": now + timedelta(hours=1),
        "rationale": "Required for a narrowly scoped protected remote validation task.",
        "data_classes": ("credential",),
        "encrypted_at_rest": True,
        "encrypted_in_transit": True,
        "isolated_runtime": False,
        "data_minimization": True,
    }

    with pytest.raises(ValidationError, match="Every technical protection"):
        PermissionManifest(**data)


def test_sensitive_approval_is_valid_when_every_control_is_enabled() -> None:
    now = datetime.now(UTC)
    approval = SensitiveRemoteApproval(
        approved_by="security.owner",
        approved_at=now,
        expires_at=now + timedelta(hours=1),
        rationale="A specific protected exception with documented data minimization.",
        data_classes=("private-target-data",),
        encrypted_at_rest=True,
        encrypted_in_transit=True,
        isolated_runtime=True,
        data_minimization=True,
    )

    assert approval.approved_by == "security.owner"
