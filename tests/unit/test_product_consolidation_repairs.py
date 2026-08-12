from __future__ import annotations

import os
import sqlite3
import time
from pathlib import Path
from types import SimpleNamespace

import pytest
from django.contrib.auth import get_user_model
from django.core.files.uploadedfile import SimpleUploadedFile
from django.urls import reverse

from vulnhunter.learning.models import CandidateStatus, MemoryCandidate, MemoryKind
from vulnhunter.learning.store import ControlledMemoryStore, ControlledMemoryStoreError
from vulnhunter.web.conversation_uploads import (
    ConversationUploadError,
    append_apk_chunk,
    begin_apk_upload,
    prune_stale_apk_uploads,
)
from vulnhunter.web.conversational_authorization import (
    ConversationalAuthorizationError,
    prepare_conversational_authorization,
)
from vulnhunter.web.middleware import _restore_latest_non_terminal_run
from vulnhunter.web.models import WebUserMapping
from vulnhunter.web.templatetags.vh_navigation import canonical_navigation


class _Session(dict):
    modified = False


class _Request:
    def __init__(self, user) -> None:
        self.user = user
        self.session = _Session()


def _candidate(**overrides) -> MemoryCandidate:
    values = {
        "kind": MemoryKind.SEMANTIC,
        "content": "Evidence-bound reviewed security guidance candidate.",
        "source_analysis_id": "analysis-test",
        "source_finding_id": "finding-test",
        "source_run_id": "run-test",
        "evidence_sha256": ("a" * 64,),
        "created_by": "ai",
    }
    values.update(overrides)
    return MemoryCandidate.create(**values)


def test_public_targets_cannot_be_authorized_from_chat(monkeypatch):
    target = SimpleNamespace(
        normalized_url="https://example.com/",
        resolved_addresses=("93.184.216.34",),
        port=443,
    )
    monkeypatch.setattr(
        "vulnhunter.web.conversational_authorization.validate_target",
        lambda *_args, **_kwargs: target,
    )

    with pytest.raises(
        ConversationalAuthorizationError,
        match="independent authorization approver",
    ):
        prepare_conversational_authorization(
            target_url=target.normalized_url,
            evidence_reference="ticket-123",
            identity_id="operator-one",
            username="operator",
        )


def test_new_memory_candidate_cannot_be_pre_promoted():
    candidate = _candidate(status=CandidateStatus.PROMOTED)

    assert candidate.status == CandidateStatus.PENDING_REVIEW


def test_store_rejects_direct_non_pending_candidate(tmp_path):
    store = ControlledMemoryStore(tmp_path / "memory")
    candidate = _candidate().model_copy(update={"status": CandidateStatus.PROMOTED})

    with pytest.raises(ControlledMemoryStoreError, match="pending review"):
        store.add_candidate(candidate)


def test_promoted_status_without_promotion_record_is_not_retrievable(tmp_path):
    store = ControlledMemoryStore(tmp_path / "memory")
    candidate = _candidate()
    assert store.add_candidate(candidate)
    injected = candidate.model_copy(update={"status": CandidateStatus.PROMOTED})
    with sqlite3.connect(store.database) as connection:
        connection.execute(
            "UPDATE memory_candidates SET status = ?, candidate_json = ? WHERE candidate_id = ?",
            (CandidateStatus.PROMOTED.value, injected.model_dump_json(), candidate.candidate_id),
        )
        connection.commit()

    assert store.retrieve_promoted() == ()


@pytest.mark.django_db
def test_web_mapping_normalizes_governance_identity():
    user = get_user_model().objects.create_user(
        username="case-user",
        password="long-password-1234",
    )
    mapping = WebUserMapping(
        user=user,
        governance_identity_id=" Phone-Admin ",
        product_roles=["campaign-operator"],
    )

    mapping.full_clean()

    assert mapping.governance_identity_id == "phone-admin"


@pytest.mark.django_db
def test_consolidated_routes_use_one_workspace(client, settings, tmp_path):
    from governance_test_support import ADMIN_SECRET, NOW, make_governance_store

    from vulnhunter.agent.store import AgentStore
    from vulnhunter.governance.service import bootstrap_administrator

    settings.ALLOWED_HOSTS = ["testserver"]
    settings.VULNHUNTER_GOVERNANCE_DATABASE = str(tmp_path / "governance.db")
    settings.VULNHUNTER_AGENT_DATABASE = str(tmp_path / "agent.db")
    settings.VULNHUNTER_APPROVAL_DATABASE = str(tmp_path / "approvals.db")
    settings.VULNHUNTER_AGENT_ACTIVITY_ROOT = str(tmp_path / "activity")
    settings.VULNHUNTER_SECURITY_EVIDENCE_ROOT = str(tmp_path / "evidence")
    governance = make_governance_store(tmp_path)
    bootstrap_administrator(
        governance,
        reviewer_id="route-user",
        display_name="Route User",
        secret=ADMIN_SECRET,
        now=NOW,
    )
    AgentStore(tmp_path / "agent.db")
    user = get_user_model().objects.create_user(
        username="route-user",
        password="long-password-1234",
    )
    WebUserMapping.objects.create(
        user=user,
        governance_identity_id="route-user",
        product_roles=["campaign-operator"],
    )
    client.force_login(user)

    new_scan = client.get(reverse("web-new-scan"))
    mobile = client.get(reverse("web-mobile-analysis"))
    legacy = client.get(reverse("legacy-run-detail", kwargs={"run_id": "run-test"}))

    assert new_scan.status_code == 302
    assert new_scan["Location"] == "/?intent=new-assessment"
    assert mobile.status_code == 200
    assert b"Assessment Workspace" in mobile.content
    assert b"data-conversation-form" in mobile.content
    assert legacy.status_code == 302
    assert legacy["Location"].endswith("/scans/run-test/")


@pytest.mark.django_db
def test_navigation_has_one_workspace_and_no_mobile_apk_page():
    user = get_user_model().objects.create_user(
        username="nav-user",
        password="long-password-1234",
    )
    WebUserMapping.objects.create(
        user=user,
        governance_identity_id="nav-user",
        product_roles=["campaign-operator"],
    )

    labels = [str(item["label"]) for item in canonical_navigation(user)]

    assert labels.count("Assessment Workspace") == 1
    assert "Mobile APK Analysis" not in labels
    assert "New Assessment" not in labels


def test_restore_latest_visible_non_terminal_run(monkeypatch):
    user = SimpleNamespace(is_authenticated=True)
    request = SimpleNamespace(method="GET", path="/", user=user, session=_Session())
    summary = SimpleNamespace(run_id="run-live", updated_at=2)
    run = SimpleNamespace(
        run_id="run-live",
        workflow_state="running",
        current_state="running",
        scope_summary="http://10.0.0.143:8010/",
        risk_classification="passive",
        authorization_id="auth-live",
    )
    service = SimpleNamespace(
        list_agent_runs=lambda: (summary,),
        get_agent_run=lambda _run_id: run,
    )
    monkeypatch.setattr(
        "vulnhunter.web.services.authorized_actor",
        lambda *_args, **_kwargs: object(),
    )
    monkeypatch.setattr("vulnhunter.web.services.product_service", lambda: service)
    monkeypatch.setattr(
        "vulnhunter.web.services.run_visible_to_actor",
        lambda *_args: True,
    )

    _restore_latest_non_terminal_run(request)

    assert request.session["vulnhunter_conversation_state"] == {
        "run_id": "run-live",
        "target": "http://10.0.0.143:8010/",
        "profile": "passive",
        "authorization_id": "auth-live",
    }
    assert request.session.modified is True


def test_durable_empty_workspace_does_not_restore_another_live_run(monkeypatch):
    user = SimpleNamespace(is_authenticated=True)
    request = SimpleNamespace(
        method="GET",
        path="/",
        user=user,
        session=_Session(),
        vulnhunter_thread=SimpleNamespace(thread_id="new-thread"),
    )

    def unexpected_service_lookup():
        raise AssertionError("durable workspace recovery must not inspect global runs")

    monkeypatch.setattr(
        "vulnhunter.web.services.product_service",
        unexpected_service_lookup,
    )

    _restore_latest_non_terminal_run(request)

    assert "vulnhunter_conversation_state" not in request.session
    assert request.session.modified is False


def test_apk_upload_preflight_rejects_insufficient_storage(monkeypatch, settings, tmp_path):
    settings.VULNHUNTER_MOBILE_ARTIFACT_ROOT = tmp_path
    settings.VULNHUNTER_MOBILE_MAX_APK_BYTES = 1_000_000_000
    settings.VULNHUNTER_MOBILE_MIN_FREE_BYTES = 1_000
    request = _Request(SimpleNamespace(pk=1))
    monkeypatch.setattr(
        "vulnhunter.web.conversation_uploads.shutil.disk_usage",
        lambda _path: SimpleNamespace(total=10_000, used=9_500, free=500),
    )

    with pytest.raises(ConversationUploadError, match="not enough free storage"):
        begin_apk_upload(request, filename="sample.apk", expected_bytes=100)


def test_stale_apk_upload_cleanup(settings, tmp_path):
    settings.VULNHUNTER_MOBILE_ARTIFACT_ROOT = tmp_path
    settings.VULNHUNTER_MOBILE_UPLOAD_TTL_SECONDS = 10
    root = tmp_path / ".conversation-uploads"
    root.mkdir(parents=True)
    stale = root / ("upload-" + "a" * 32 + ".part")
    stale.write_bytes(b"stale")
    os.utime(stale, (time.time() - 100, time.time() - 100))

    assert prune_stale_apk_uploads() == 1
    assert not stale.exists()


def test_apk_upload_updates_activity_timestamp(settings, tmp_path):
    settings.VULNHUNTER_MOBILE_ARTIFACT_ROOT = tmp_path
    settings.VULNHUNTER_MOBILE_MAX_APK_BYTES = 10_000
    settings.VULNHUNTER_MOBILE_MIN_FREE_BYTES = 0
    request = _Request(SimpleNamespace(pk=1))
    staged = begin_apk_upload(request, filename="sample.apk", expected_bytes=4)
    before = float(
        request.session["vulnhunter_conversation_apk_uploads"][staged.upload_id]["updated_at"]
    )

    append_apk_chunk(
        request,
        upload_id=staged.upload_id,
        offset=0,
        chunk=SimpleUploadedFile("chunk", b"PK12"),
    )
    after = float(
        request.session["vulnhunter_conversation_apk_uploads"][staged.upload_id]["updated_at"]
    )

    assert after >= before
    assert staged.path.read_bytes() == b"PK12"


def test_shared_shell_does_not_load_conversation_assets_globally():
    root = Path(__file__).resolve().parents[2]
    base = (root / "vulnhunter/web/templates/web/base.html").read_text(encoding="utf-8")
    conversation = (root / "vulnhunter/web/templates/web/conversation.html").read_text(
        encoding="utf-8"
    )

    assert "assessment-modal.js" not in base
    assert "conversation.js" not in base
    assert "{% block extra_styles %}" in base
    assert "{% block extra_scripts %}" in base
    assert "conversation.js" in conversation
    assert conversation.count("conversation-mobile-deferred-tools.js") == 1
    assert conversation.count("conversation-mobile-deferred-tools.css") == 1


def test_final_workspace_contract_is_shared_and_responsive():
    root = Path(__file__).resolve().parents[2]
    tokens = (root / "vulnhunter/web/static/web/tokens.css").read_text(encoding="utf-8")
    app = (root / "vulnhunter/web/static/web/app.css").read_text(encoding="utf-8")
    conversation_css = (root / "vulnhunter/web/static/web/conversation.css").read_text(
        encoding="utf-8"
    )
    template = (root / "vulnhunter/web/templates/web/conversation.html").read_text(encoding="utf-8")
    inspector = (root / "vulnhunter/web/templates/web/_mobile_analysis_inspector.html").read_text(
        encoding="utf-8"
    )

    assert "--vh-layout-sidebar: 280px" in tokens
    assert "--vh-layout-topbar: 60px" in tokens
    assert "@media (max-width: 1023px)" in app
    assert ".vh-sidebar.is-open" in app
    assert "@media (max-width: 767px)" in conversation_css
    assert "data-run-stages" in template
    assert "data-run-tool-chips" in template
    assert "data-conversation-form" in template
    assert "data-analysis-inspector-open" in template
    assert "Assessment details" in inspector
    assert "vh-state-strip" not in template
    assert "vh-mobile-workspace-nav" not in template
