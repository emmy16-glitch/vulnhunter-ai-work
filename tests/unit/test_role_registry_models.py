from __future__ import annotations

from datetime import date

import pytest
from pydantic import ValidationError

from vulnhunter.roles.models import (
    ConnectorGrant,
    ExternalDependency,
    RoleDefinition,
)


def base_role(**overrides):
    values = {
        "role_id": "test-specialist",
        "display_name": "Test Specialist",
        "owner": "Test Owner",
        "version": "1.0.0",
        "purpose": "Exercise registry model invariants in a deterministic unit test.",
        "risk_level": "high",
        "status": "planned",
        "allowed_inputs": ("approved input",),
        "allowed_actions": ("test.execute",),
        "denied_actions": ("git.push",),
        "skill_ids": ("test-verification",),
        "output_schema": {"type": "object"},
        "verification_requirements": ("Verify the declared boundary.",),
        "required_tests": ("Run a schema test.",),
        "last_reviewed_on": date(2026, 7, 10),
        "rollback_procedure": ("Revert the registry change.",),
    }
    values.update(overrides)
    return RoleDefinition(**values)


def test_role_is_untrusted_by_construction() -> None:
    role = base_role()

    assert role.trust_assumption == "untrusted"
    assert role.connector_policy.default == "disabled"
    assert role.connector_policy.grants == ()


def test_role_rejects_overlapping_allowed_and_denied_actions() -> None:
    with pytest.raises(ValidationError, match="role actions overlap"):
        base_role(denied_actions=("test.execute",))


def test_role_approval_points_must_reference_allowed_actions() -> None:
    with pytest.raises(ValidationError, match="approval points"):
        base_role(human_approval_points=("deployment.execute",))


def test_role_output_schema_must_describe_an_object() -> None:
    with pytest.raises(ValidationError, match="JSON object"):
        base_role(output_schema={"type": "array"})


def test_external_dependency_requires_immutable_pin() -> None:
    with pytest.raises(ValidationError, match="immutable pin"):
        ExternalDependency(
            dependency_id="third-party-plugin",
            source="https://example.invalid/plugin",
            pinned_reference="latest",
            integrity_sha256="a" * 64,
            risk_level="high",
            reviewed_by="Security Reviewer",
            reviewed_on=date(2026, 7, 10),
            allowed_capabilities=("read",),
            verification_tests=("Run plugin tests.",),
            rollback_procedure=("Remove the plugin.",),
        )


def test_connector_grant_requires_review_logging_approval_and_revocation() -> None:
    grant = ConnectorGrant(
        connector_id="example.connector",
        purpose="Read one explicitly approved external evidence source.",
        least_privilege_scope=("evidence.read",),
        prompt_injection_reviewed=True,
        audit_logging=True,
        approved_by="Emmanuel Okunlola",
        revocation_procedure=("Revoke the connector token.",),
        expires_on=date(2026, 8, 10),
    )

    assert grant.prompt_injection_reviewed is True
    assert grant.audit_logging is True
