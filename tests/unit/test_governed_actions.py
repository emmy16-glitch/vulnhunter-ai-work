from datetime import UTC, datetime, timedelta

import pytest

from vulnhunter.actions import (
    ActionClass,
    ActionDecisionStatus,
    ActionManifest,
    ActionPolicy,
    ExecutionLimits,
)


def _manifest(**updates):
    now = datetime.now(UTC)
    values = {
        "manifest_id": "manifest-01",
        "campaign_id": "campaign-01",
        "requested_by": "operator-01",
        "role_id": "scanner-evidence-specialist",
        "skill_id": "governed-security-tool-operation",
        "action": "security_tool.nmap.run",
        "action_class": ActionClass.CONSEQUENTIAL,
        "tool_id": "nmap",
        "operation": "discovery",
        "target_references": ("target-01",),
        "authorization_references": ("authorization-01",),
        "limits": ExecutionLimits(maximum_targets=1),
        "approval_required": True,
        "created_at": now,
        "expires_at": now + timedelta(minutes=10),
        "purpose": "Map approved laboratory network services.",
    }
    values.update(updates)
    return ActionManifest(**values)


def test_action_manifest_is_hash_stable_and_policy_requires_exact_approval():
    manifest = _manifest()
    assert manifest.fingerprint() == manifest.fingerprint()

    policy = ActionPolicy(known_tools=("nmap",))
    pending = policy.evaluate(manifest)
    assert pending.status == ActionDecisionStatus.REQUIRE_APPROVAL

    wrong = policy.evaluate(
        manifest,
        approval_is_active=True,
        approval_action_sha256="0" * 64,
    )
    assert wrong.status == ActionDecisionStatus.DENY

    allowed = policy.evaluate(
        manifest,
        approval_is_active=True,
        approval_action_sha256=manifest.fingerprint(),
    )
    assert allowed.status == ActionDecisionStatus.ALLOW


def test_consequential_manifest_cannot_omit_approval_requirement():
    with pytest.raises(ValueError, match="require approval"):
        _manifest(approval_required=False)
