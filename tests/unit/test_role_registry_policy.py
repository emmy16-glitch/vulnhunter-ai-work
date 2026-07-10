from __future__ import annotations

import json
import shutil
from pathlib import Path

from vulnhunter.roles.models import DecisionStatus
from vulnhunter.roles.registry import RoleRegistry

REGISTRY_ROOT = Path("config/roles")


def active_registry(tmp_path: Path) -> RoleRegistry:
    root = tmp_path / "roles"
    shutil.copytree(REGISTRY_ROOT, root)
    role_path = root / "roles" / "backend-specialist.json"
    role = json.loads(role_path.read_text(encoding="utf-8"))
    role["status"] = "active"
    role_path.write_text(json.dumps(role, indent=2) + "\n", encoding="utf-8")
    return RoleRegistry.from_path(root)


def test_unknown_role_is_denied() -> None:
    registry = RoleRegistry.from_path(REGISTRY_ROOT)

    decision = registry.evaluate_action("missing-role", "test.execute")

    assert decision.status == DecisionStatus.DENIED
    assert "Unknown role" in decision.reason


def test_planned_role_is_denied_even_for_declared_action() -> None:
    registry = RoleRegistry.from_path(REGISTRY_ROOT)

    decision = registry.evaluate_action("report-writer", "report.draft")

    assert decision.status == DecisionStatus.DENIED
    assert "only active roles" in decision.reason


def test_active_role_requires_human_approval_for_sensitive_write(
    tmp_path: Path,
) -> None:
    registry = active_registry(tmp_path)

    decision = registry.evaluate_action(
        "backend-specialist",
        "code.modify.backend",
        tool_id="repository.write",
        operation="write-approved-paths",
    )

    assert decision.status == DecisionStatus.REQUIRES_APPROVAL


def test_active_role_allows_declared_action_after_approval(tmp_path: Path) -> None:
    registry = active_registry(tmp_path)

    decision = registry.evaluate_action(
        "backend-specialist",
        "code.modify.backend",
        tool_id="repository.write",
        operation="write-approved-paths",
        approval_reference="APPROVAL-19-5A-001",
    )

    assert decision.status == DecisionStatus.ALLOWED
    assert "runtime enforcement" in decision.reason


def test_ungranted_tool_is_denied(tmp_path: Path) -> None:
    registry = active_registry(tmp_path)

    decision = registry.evaluate_action(
        "backend-specialist",
        "test.add",
        tool_id="deployment.tool",
        operation="deploy",
    )

    assert decision.status == DecisionStatus.DENIED
    assert "not granted" in decision.reason


def test_ungranted_tool_operation_is_denied(tmp_path: Path) -> None:
    registry = active_registry(tmp_path)

    decision = registry.evaluate_action(
        "backend-specialist",
        "test.add",
        tool_id="test.runner",
        operation="delete-results",
    )

    assert decision.status == DecisionStatus.DENIED
    assert "operation" in decision.reason


def test_connector_request_is_denied_without_explicit_grant(tmp_path: Path) -> None:
    registry = active_registry(tmp_path)

    decision = registry.evaluate_action(
        "backend-specialist",
        "test.add",
        connector_id="github",
    )

    assert decision.status == DecisionStatus.DENIED
    assert "disabled" in decision.reason


def test_registry_wide_denied_action_remains_denied(tmp_path: Path) -> None:
    registry = active_registry(tmp_path)

    decision = registry.evaluate_action("backend-specialist", "git.push")

    assert decision.status == DecisionStatus.DENIED
