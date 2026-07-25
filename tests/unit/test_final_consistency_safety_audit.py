from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from types import SimpleNamespace

import pytest
from django.core.files.uploadedfile import SimpleUploadedFile
from django.core.management.base import CommandError

from vulnhunter.exceptions import GovernanceAuthenticationError
from vulnhunter.governance.service import bootstrap_administrator, create_identity
from vulnhunter.governance.store import GovernanceStore
from vulnhunter.mobile.models import MobileArtifactRecord
from vulnhunter.mobile.static_toolchain import MobileStaticWorkerPolicy
from vulnhunter.web.conversation_uploads import (
    ConversationUploadError,
    append_apk_chunk,
    begin_apk_upload,
)
from vulnhunter.web.management.commands.vh_manage_learning import (
    _authenticated_learning_actor,
    _read_governance_secret,
)
from vulnhunter.web.mobile_execution import _analysis_capacity_reason


class _Session(dict):
    modified = False


class _Request:
    def __init__(self, user_id: int = 1) -> None:
        self.user = SimpleNamespace(pk=user_id)
        self.session = _Session()


def _governance_registry(tmp_path: Path, settings) -> tuple[GovernanceStore, str]:
    database = tmp_path / "governance.db"
    settings.VULNHUNTER_GOVERNANCE_DATABASE = str(database)
    store = GovernanceStore.from_path(database)
    store.initialize()
    secret = "admin-secret-1234"
    bootstrap_administrator(
        store,
        reviewer_id="learning-admin",
        display_name="Learning Admin",
        secret=secret,
    )
    return store, secret


def _artifact(tmp_path: Path) -> MobileArtifactRecord:
    apk = tmp_path / "sample.apk"
    apk.write_bytes(b"PK")
    return MobileArtifactRecord(
        artifact_id="artifact-sample",
        original_filename="sample.apk",
        stored_path=apk,
        sha256="a" * 64,
        size_bytes=2,
        archive_entry_count=1,
        total_uncompressed_bytes=2,
        manifest_entry="AndroidManifest.xml",
        dex_entries=("classes.dex",),
    )


def _policy(tmp_path: Path) -> MobileStaticWorkerPolicy:
    workspace = tmp_path / "analysis"
    return MobileStaticWorkerPolicy(
        enabled=True,
        worker_id="test-mobile-worker",
        workspace_root=workspace,
        aapt2_executable=Path("/bin/true"),
        maximum_generated_bytes=10_000_000,
        maximum_generated_file_bytes=1_000_000,
    )


def test_learning_actor_must_authenticate_against_governance(tmp_path, settings):
    _store, secret = _governance_registry(tmp_path, settings)

    assert (
        _authenticated_learning_actor(
            actor="learning-admin",
            secret=secret,
            action="promote",
        )
        == "learning-admin"
    )
    with pytest.raises(GovernanceAuthenticationError, match="authentication failed"):
        _authenticated_learning_actor(
            actor="learning-admin",
            secret="wrong-secret",
            action="review",
        )


def test_only_campaign_administrator_can_promote_learning(tmp_path, settings):
    store, admin_secret = _governance_registry(tmp_path, settings)
    create_identity(
        store,
        actor_id="learning-admin",
        actor_secret=admin_secret,
        reviewer_id="learning-reviewer",
        display_name="Learning Reviewer",
        secret="reviewer-secret-1234",
        roles=("reviewer",),
    )

    assert (
        _authenticated_learning_actor(
            actor="learning-reviewer",
            secret="reviewer-secret-1234",
            action="review",
        )
        == "learning-reviewer"
    )
    with pytest.raises(CommandError, match="campaign administrator"):
        _authenticated_learning_actor(
            actor="learning-reviewer",
            secret="reviewer-secret-1234",
            action="promote",
        )


def test_governance_secret_file_must_be_owner_only(tmp_path):
    secret_file = tmp_path / "governance.secret"
    secret_file.write_text("private-secret\n", encoding="utf-8")
    secret_file.chmod(0o600)

    assert _read_governance_secret(secret_file) == "private-secret"

    secret_file.chmod(0o644)
    with pytest.raises(CommandError, match="readable only by its owner"):
        _read_governance_secret(secret_file)


def test_active_upload_limit_does_not_delete_an_existing_upload(settings, tmp_path):
    settings.VULNHUNTER_MOBILE_ARTIFACT_ROOT = tmp_path
    settings.VULNHUNTER_MOBILE_MAX_APK_BYTES = 10_000
    settings.VULNHUNTER_MOBILE_MIN_FREE_BYTES = 0
    settings.VULNHUNTER_MOBILE_MAX_STAGED_BYTES = 40_000
    settings.VULNHUNTER_MOBILE_MAX_ACTIVE_UPLOADS = 3
    request = _Request()

    staged = [
        begin_apk_upload(request, filename=f"sample-{index}.apk", expected_bytes=4)
        for index in range(3)
    ]

    with pytest.raises(ConversationUploadError, match="Too many APK uploads"):
        begin_apk_upload(request, filename="sample-4.apk", expected_bytes=4)

    assert all(item.path.exists() for item in staged)


def test_concurrent_duplicate_chunk_cannot_append_twice(settings, tmp_path):
    settings.VULNHUNTER_MOBILE_ARTIFACT_ROOT = tmp_path
    settings.VULNHUNTER_MOBILE_MAX_APK_BYTES = 10_000
    settings.VULNHUNTER_MOBILE_MIN_FREE_BYTES = 0
    request = _Request()
    staged = begin_apk_upload(request, filename="sample.apk", expected_bytes=4)

    def append(payload: bytes):
        try:
            append_apk_chunk(
                request,
                upload_id=staged.upload_id,
                offset=0,
                chunk=SimpleUploadedFile("chunk", payload),
            )
        except ConversationUploadError as exc:
            return str(exc)
        return "ok"

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = tuple(executor.map(append, (b"AA", b"BB")))

    assert results.count("ok") == 1
    assert any("offset is out of sequence" in result for result in results if result != "ok")
    assert staged.path.read_bytes() in {b"AA", b"BB"}


def test_mobile_analysis_capacity_is_checked_before_queueing(monkeypatch, settings, tmp_path):
    policy = _policy(tmp_path)
    artifact = _artifact(tmp_path)
    settings.VULNHUNTER_MOBILE_ANALYSIS_MIN_FREE_BYTES = 1_000

    monkeypatch.setattr(
        "vulnhunter.web.mobile_execution.shutil.disk_usage",
        lambda _path: SimpleNamespace(total=20_000_000, used=15_000_000, free=5_000_000),
    )
    reason = _analysis_capacity_reason(policy, artifact)
    assert reason is not None
    assert "not enough free storage" in reason

    monkeypatch.setattr(
        "vulnhunter.web.mobile_execution.shutil.disk_usage",
        lambda _path: SimpleNamespace(total=30_000_000, used=5_000_000, free=25_000_000),
    )
    assert _analysis_capacity_reason(policy, artifact) is None


def test_product_blueprint_navigation_matches_the_unified_workspace():
    navigation = json.loads(
        Path("config/product_interface/navigation.json").read_text(encoding="utf-8")
    )
    labels = [
        item["label"]
        for section in navigation["sections"]
        for item in section.get("items", [])
    ]

    assert labels.count("Assessment Workspace") == 1
    assert labels.count("Assessment History") == 1
    assert "New Scan" not in labels
    assert "Scan Runs" not in labels
    assert "Dashboard" not in labels
