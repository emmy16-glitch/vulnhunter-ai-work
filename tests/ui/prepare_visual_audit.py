#!/usr/bin/env python3
"""Seed a deterministic, local-only UI audit workspace with no external actions."""

# Django must be configured before importing project models in this standalone seed.
# ruff: noqa: E402

from __future__ import annotations

import json
import os
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests" / "unit"))
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "vulnhunter.web.settings")

import django

django.setup()

from django.conf import settings
from django.contrib.auth import get_user_model
from governance_test_support import (
    REVIEWER_ONE_SECRET,
    REVIEWER_TWO_SECRET,
    make_governance_store,
)
from test_governance_workflow import assign_default, prepare_world
from test_web_app import _controller

from vulnhunter.agent.models import PermissionManifest, ToolRisk
from vulnhunter.approvals import ApprovalRequest, ApprovalStore
from vulnhunter.evidence import EvidenceStore, FindingStatus
from vulnhunter.governance.service import submit_governed_review
from vulnhunter.web.models import WebUserMapping


def mapped_user(
    username: str,
    identity: str,
    roles: list[str],
    password: str,
) -> None:
    model = get_user_model()
    user, _ = model.objects.get_or_create(username=username)
    user.set_password(password)
    user.is_active = True
    user.is_staff = True
    user.save()
    WebUserMapping.objects.update_or_create(
        user=user,
        defaults={
            "governance_identity_id": identity,
            "product_roles": roles,
        },
    )


def _review(
    store,
    world: dict[str, object],
    *,
    actor_id: str,
    actor_secret: str,
    outcome: str,
    note: str,
) -> None:
    submit_governed_review(
        store,
        world["repository"],
        actor_id=actor_id,
        actor_secret=actor_secret,
        campaign_id=world["campaign"].campaign_id,
        scan_database=world["scan_database"],
        observation_id=world["observation_id"],
        outcome=outcome,
        note=note,
    )


def main() -> int:
    runtime_root = Path(settings.VULNHUNTER_GOVERNANCE_DATABASE).resolve().parent
    runtime_root.mkdir(parents=True, exist_ok=True)
    store = make_governance_store(runtime_root)
    world = prepare_world(store, runtime_root)
    assignment = assign_default(store, world)

    all_roles = [
        "system-administrator",
        "campaign-operator",
        "campaign-approver",
        "reviewer",
        "adjudicator",
        "security-auditor",
        "model-analyst",
    ]
    password = "Vh-Visual-Audit-2026!"
    mapped_user("visual-admin", "admin-a", all_roles, password)
    mapped_user("visual-reviewer", "reviewer-a", ["reviewer"], password)
    mapped_user("visual-adjudicator", "lead-c", ["adjudicator"], password)

    controller = _controller(runtime_root)
    task = controller.create_task(
        task_id="ui-reference-run",
        objective=(
            "Inspect a bounded local application and preserve evidence for human review."
        ),
        permission_manifest=PermissionManifest(
            manifest_id="ui-reference-manifest",
            role_id="orchestrator",
            skill_id="bounded-task-routing",
            allowed_actions=("evidence.inspect",),
            allowed_tools=("agent.echo",),
            allowed_risks=(ToolRisk.READ_ONLY,),
        ),
    )
    controller.run(task.task_id)

    evidence_root = Path(settings.VULNHUNTER_SECURITY_EVIDENCE_ROOT)
    evidence_root.mkdir(parents=True, exist_ok=True)
    artifact = evidence_root / "ui-reference-proof.txt"
    artifact.write_text(
        "Sanitized deterministic proof for local visual validation.\n",
        encoding="utf-8",
    )
    finding = EvidenceStore(evidence_root).append(
        evidence_id="ui-critical-finding",
        campaign_id=world["campaign"].campaign_id,
        run_id=task.task_id,
        action_manifest_sha256="a" * 64,
        tool_id="nuclei",
        target_reference="http://127.0.0.1:8000/app/",
        finding_status=FindingStatus.VALIDATED,
        title="Critical authorization boundary regression",
        severity="critical",
        confidence="high",
        recorded_by="admin-a",
        artifact_path=artifact,
        metadata={
            "attack_path": [
                {"label": "Authorized target", "state": "observed"},
                {"label": "Candidate evidence", "state": "validated"},
                {"label": "Human review", "state": "required"},
            ]
        },
    )

    _review(
        store,
        world,
        actor_id="reviewer-a",
        actor_secret=REVIEWER_ONE_SECRET,
        outcome="confirmed",
        note="The persisted local evidence supports confirmation.",
    )
    _review(
        store,
        world,
        actor_id="reviewer-b",
        actor_secret=REVIEWER_TWO_SECRET,
        outcome="false_positive",
        note="The second reviewer found the candidate inconclusive.",
    )

    now = datetime.now(UTC)
    ApprovalStore(Path(settings.VULNHUNTER_APPROVAL_DATABASE)).create(
        ApprovalRequest(
            request_id="ui-approval-request",
            campaign_id=world["campaign"].campaign_id,
            run_id=task.task_id,
            action_manifest_sha256="b" * 64,
            requested_by="reviewer-a",
            summary="Approve one bounded local validation action.",
            risk_summary="The action is restricted to synthetic local evidence.",
            requested_at=now,
            expires_at=now + timedelta(hours=2),
        )
    )

    review_reference = assignment.record_sha256[:24]
    campaign_id = world["campaign"].campaign_id
    manifest = {
        "simulation_only": True,
        "external_actions_performed": False,
        "personas": {
            "admin": {"username": "visual-admin", "password": password},
            "reviewer": {
                "username": "visual-reviewer",
                "password": password,
            },
            "adjudicator": {
                "username": "visual-adjudicator",
                "password": password,
            },
        },
        "pages": [
            {
                "name": "dashboard",
                "path": "/",
                "persona": "admin",
                "responsive": True,
            },
            {"name": "new-scan", "path": "/scans/new/", "persona": "admin"},
            {"name": "scan-runs", "path": "/scans/", "persona": "admin"},
            {
                "name": "run-detail",
                "path": f"/scans/{task.task_id}/",
                "persona": "admin",
                "responsive": True,
            },
            {"name": "findings", "path": "/findings/", "persona": "admin"},
            {
                "name": "finding-detail",
                "path": f"/findings/{finding.evidence_id}/",
                "persona": "admin",
                "responsive": True,
            },
            {"name": "approvals", "path": "/approvals/", "persona": "admin"},
            {
                "name": "approval-detail",
                "path": "/approvals/ui-approval-request/",
                "persona": "admin",
            },
            {
                "name": "review",
                "path": f"/reviews/{review_reference}/",
                "persona": "reviewer",
            },
            {
                "name": "adjudication",
                "path": f"/adjudications/{review_reference}/",
                "persona": "adjudicator",
            },
            {"name": "campaigns", "path": "/campaigns/", "persona": "admin"},
            {
                "name": "campaign-detail",
                "path": f"/campaigns/{campaign_id}/",
                "persona": "admin",
            },
            {"name": "releases", "path": "/releases/", "persona": "admin"},
            {"name": "datasets", "path": "/datasets/", "persona": "admin"},
            {"name": "models", "path": "/models/", "persona": "admin"},
            {"name": "reports", "path": "/reports/", "persona": "admin"},
            {
                "name": "mobile",
                "path": "/mobile-analysis/",
                "persona": "admin",
            },
            {"name": "audit", "path": "/audit/", "persona": "admin"},
            {
                "name": "settings",
                "path": "/settings/",
                "persona": "admin",
                "responsive": True,
            },
        ],
    }
    output = Path(
        os.environ.get(
            "VULNHUNTER_UI_MANIFEST",
            runtime_root / "ui-manifest.json",
        )
    )
    output.write_text(
        json.dumps(manifest, indent=2) + "\n",
        encoding="utf-8",
    )
    print(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
