from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from vulnhunter.assessment_graph import RemediationAssessmentGraphService
from vulnhunter.findings import (
    EvidenceReference,
    Finding,
    FindingService,
    FindingSeverity,
    FindingStatus,
    FindingStore,
    RemediationState,
    VerificationState,
)
from vulnhunter.source_hunt import RepositorySnapshot, SourceReference, VerifierReceipt
from vulnhunter.source_hunt.models import RepositoryFile
from vulnhunter.web.remediation_assessment_graph import bind_remediation_assessment_graph
from vulnhunter.web.remediation_conversation_state import remember_remediation_workspace


def _configure(settings, tmp_path: Path) -> None:
    settings.PASSWORD_HASHERS = ["django.contrib.auth.hashers.MD5PasswordHasher"]
    settings.ALLOWED_HOSTS = ["testserver", "localhost", "127.0.0.1"]
    settings.VULNHUNTER_FINDING_DATABASE = tmp_path / "findings.sqlite3"
    settings.VULNHUNTER_TASK_GRAPH_ROOT = tmp_path / "graphs"


def _actor() -> SimpleNamespace:
    return SimpleNamespace(governance_identity=SimpleNamespace(reviewer_id="remediation-owner"))


def _finding(now: datetime) -> Finding:
    return Finding(
        finding_id="finding-01",
        campaign_id="campaign-01",
        fingerprint=Finding.create_fingerprint(
            campaign_id="campaign-01",
            title="IDOR",
            affected_asset="repo-01",
            affected_component="app/users.py",
        ),
        title="IDOR",
        description="User lookup may expose another user's record without ownership checks.",
        severity=FindingSeverity.HIGH,
        confidence=90,
        verification=VerificationState.VERIFIED,
        affected_asset="repo-01",
        affected_component="app/users.py",
        evidence=(
            EvidenceReference(
                evidence_id="source-evidence-01",
                sha256="a" * 64,
                provenance="independently reviewed source evidence",
                content_type="application/json",
            ),
        ),
        created_at=now - timedelta(hours=1),
        updated_at=now - timedelta(hours=1),
    )


def _snapshot(*, revision: str, source_sha256: str, now: datetime) -> RepositorySnapshot:
    return RepositorySnapshot(
        repository_id="repo-01",
        repository_root="/approved/repo-01",
        revision=revision,
        snapshot_sha256=hashlib.sha256(f"snapshot:{revision}".encode()).hexdigest(),
        files=(
            RepositoryFile(
                path="app/users.py",
                sha256=source_sha256,
                size_bytes=120,
                language="python",
                line_count=20,
            ),
        ),
        total_bytes=120,
        created_at=now,
    )


def _receipt(name: str) -> VerifierReceipt:
    return VerifierReceipt(
        verifier_id=name,
        passed=True,
        exit_code=0,
        output_sha256=hashlib.sha256(name.encode()).hexdigest(),
        duration_seconds=0.2,
        safe_summary="Deterministic verifier completed with bounded redacted output.",
    )


@pytest.mark.django_db
def test_chat_opens_protected_handoff_without_consuming_authority(
    client,
    tmp_path,
    settings,
):
    from django.contrib.auth import get_user_model

    from vulnhunter.web.models import ConversationThread

    _configure(settings, tmp_path)
    now = datetime.now(UTC)
    User = get_user_model()
    operator = User.objects.create_user(
        username="remediation-operator",
        password="password-1234",
        is_staff=True,
    )
    thread = ConversationThread.objects.create(owner=operator, title="Verify remediation")
    store = FindingStore(settings.VULNHUNTER_FINDING_DATABASE)
    store.create(_finding(now))
    planned = FindingService(store).start_remediation(
        "finding-01",
        owner_id="remediation-owner",
        summary="Enforce object ownership before returning the selected user record.",
        target_references=("app/users.py",),
        regression_test="A cross-user request must be rejected by the RED security test.",
        verification_recipe="Run the independent read-only security and regression receipts.",
        references=("source-evidence-01",),
        expires_at=now + timedelta(days=7),
        expected_revision=0,
        now=now,
    )
    graph = bind_remediation_assessment_graph(planned, workspace_id=str(thread.thread_id))
    remember_remediation_workspace(
        owner=operator,
        workspace_id=str(thread.thread_id),
        finding=planned,
        graph=graph,
    )
    client.force_login(operator)

    with patch(
        "vulnhunter.web.remediation_views.authorized_actor",
        return_value=_actor(),
    ):
        response = client.post(
            "/workspace/remediation/",
            {
                "thread_id": str(thread.thread_id),
                "message": "Record implementation and verify the remediation fix",
                "password": "must-not-be-consumed-from-chat",
            },
            HTTP_X_VULNHUNTER_THREAD=str(thread.thread_id),
            HTTP_ACCEPT="application/json",
        )

    assert response.status_code == 200
    payload = response.json()
    assert payload["redirect_url"] == (
        f"/findings/finding-01/remediation/verify/?thread={thread.thread_id}"
    )
    assert store.get("finding-01") == planned


@pytest.mark.django_db
def test_protected_handoff_records_fixed_revision_verdict_graph_and_thread(
    client,
    tmp_path,
    settings,
):
    from django.contrib.auth import get_user_model

    from vulnhunter.web.models import ConversationThread

    _configure(settings, tmp_path)
    now = datetime.now(UTC)
    User = get_user_model()
    operator = User.objects.create_user(
        username="remediation-operator",
        password="password-1234",
        is_staff=True,
    )
    thread = ConversationThread.objects.create(owner=operator, title="Verify remediation")
    store = FindingStore(settings.VULNHUNTER_FINDING_DATABASE)
    store.create(_finding(now))
    planned = FindingService(store).start_remediation(
        "finding-01",
        owner_id="remediation-owner",
        summary="Enforce object ownership before returning the selected user record.",
        target_references=("app/users.py",),
        regression_test="A cross-user request must be rejected by the RED security test.",
        verification_recipe="Run the independent read-only security and regression receipts.",
        references=("source-evidence-01",),
        expires_at=now + timedelta(days=7),
        expected_revision=0,
        now=now,
    )
    graph = bind_remediation_assessment_graph(planned, workspace_id=str(thread.thread_id))
    remember_remediation_workspace(
        owner=operator,
        workspace_id=str(thread.thread_id),
        finding=planned,
        graph=graph,
    )
    original = _snapshot(revision="1" * 40, source_sha256="b" * 64, now=now)
    fixed = _snapshot(revision="2" * 40, source_sha256="c" * 64, now=now)
    file = fixed.files[0]
    client.force_login(operator)

    with patch(
        "vulnhunter.web.remediation_views._remediator",
        return_value=_actor(),
    ):
        response = client.post(
            f"/findings/finding-01/remediation/verify/?thread={thread.thread_id}",
            {
                "thread_id": str(thread.thread_id),
                "expected_revision": str(planned.revision),
                "builder_id": "developer-01",
                "allowed_paths": "app/users.py",
                "changed_files": "app/users.py",
                "original_snapshot_json": original.model_dump_json(),
                "fixed_snapshot_json": fixed.model_dump_json(),
                "security_test_json": _receipt("security-red").model_dump_json(),
                "regression_tests_json": json.dumps([_receipt("pytest").model_dump(mode="json")]),
                "fixed_evidence_refs_json": json.dumps(
                    [
                        SourceReference(
                            path=file.path,
                            source_sha256=file.sha256,
                            line_start=1,
                            line_end=12,
                            symbol="get_user",
                        ).model_dump(mode="json")
                    ]
                ),
                "original_attack_blocked": "on",
                "password": "password-1234",
            },
        )

    assert response.status_code == 302
    assert response.url == f"/findings/finding-01/remediation/?thread={thread.thread_id}"
    updated = store.get("finding-01")
    assert updated.status == FindingStatus.READY_FOR_RETEST
    assert updated.remediation is not None
    assert updated.remediation.state == RemediationState.READY_FOR_RETEST
    latest = updated.remediation.verification_history[-1]
    assert latest.verdict == "fixed"
    assert latest.original_revision == original.revision
    assert latest.fixed_revision == fixed.revision

    graph_payload = RemediationAssessmentGraphService(
        Path(settings.VULNHUNTER_TASK_GRAPH_ROOT)
    ).status_payload(updated.remediation.remediation_id)
    assert graph_payload is not None
    assert graph_payload["chat_stage"] == "fix_verified_awaiting_retest"

    thread.refresh_from_db()
    plan = thread.data["vulnhunter_conversation_remediation"]
    assert plan["plan"]["state"] == "ready_for_retest"
    assert plan["plan"]["latest_verification"]["receipt_id"] == latest.receipt_id
    assert plan["assessment_graph"]["chat_stage"] == "fix_verified_awaiting_retest"
