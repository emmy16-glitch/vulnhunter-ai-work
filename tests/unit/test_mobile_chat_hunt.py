from __future__ import annotations

import io
import json
import zipfile
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from django.contrib.auth import get_user_model
from django.core.files.uploadedfile import SimpleUploadedFile

from vulnhunter.hunt import (
    CandidateRecord,
    CandidateState,
    CoverageCell,
    CoverageStatus,
    HuntAltitude,
    raise_scrutiny,
    transition_candidate,
)
from vulnhunter.mobile import MobileArtifactIngestor
from vulnhunter.mobile.models import MobileArtifactRecord
from vulnhunter.mobile.static_service import MobileStaticQueueService, create_mobile_static_job
from vulnhunter.mobile.static_spool import MobileStaticSpool, MobileStaticSpoolError
from vulnhunter.mobile.static_worker import MobileStaticWorkerPolicy
from vulnhunter.web.conversation_attachments import ConversationAttachment
from vulnhunter.web.mobile_conversation import build_mobile_chat_plan

ROOT = Path(__file__).resolve().parents[2]
NOW = datetime(2026, 7, 25, 12, 0, tzinfo=UTC)


def _artifact(tmp_path: Path, *, native: bool) -> MobileArtifactRecord:
    apk = tmp_path / "original.apk"
    apk.write_bytes(b"test-apk")
    return MobileArtifactRecord(
        artifact_id="apk-0123456789abcdef01234567",
        original_filename="banking-app.apk",
        stored_path=apk,
        sha256="a" * 64,
        size_bytes=8,
        archive_entry_count=4,
        total_uncompressed_bytes=8,
        manifest_entry="AndroidManifest.xml",
        dex_entries=("classes.dex",),
        native_libraries=("lib/arm64-v8a/libsecure.so",) if native else (),
        native_abis=("arm64-v8a",) if native else (),
    )


def _attachment(*, native: bool) -> ConversationAttachment:
    return ConversationAttachment(
        attachment_id="attachment-0123456789abcdef0123",
        kind="android_apk",
        artifact_id="apk-0123456789abcdef01234567",
        artifact_sha256="a" * 64,
        original_filename="banking-app.apk",
        size_bytes=8,
        archive_entry_count=4,
        dex_count=1,
        native_library_count=1 if native else 0,
        native_abis=("arm64-v8a",) if native else (),
        created_at="2026-07-25T12:00:00+00:00",
    )


def _apk_bytes() -> bytes:
    payload = io.BytesIO()
    with zipfile.ZipFile(payload, "w") as archive:
        archive.writestr("AndroidManifest.xml", b"manifest")
        archive.writestr("classes.dex", b"dex")
        archive.writestr("lib/arm64-v8a/libsecure.so", b"native")
    return payload.getvalue()


def _apk_upload() -> SimpleUploadedFile:
    return SimpleUploadedFile(
        "banking-app.apk",
        _apk_bytes(),
        content_type="application/vnd.android.package-archive",
    )


def _fake_aapt2(tmp_path: Path) -> Path:
    tool = tmp_path / "aapt2"
    tool.write_text("#!/bin/sh\necho package: name=com.example.safe\n", encoding="utf-8")
    tool.chmod(0o700)
    return tool.resolve()


def test_full_mobile_chat_request_prepares_static_native_hunt_and_defers_runtime(tmp_path):
    plan = build_mobile_chat_plan(
        text="Do a full deep test of this APK",
        requested_by="VulnHunter User",
        attachment=_attachment(native=True),
        artifact=_artifact(tmp_path, native=True),
    )

    tool_ids = {item["tool_id"] for item in plan["tools"]}
    altitudes = [item["altitude"] for item in plan["rounds"]]

    assert plan["requested_profile"] == "full"
    assert plan["profile"] == "static_and_native"
    assert plan["dynamic_deferred"] is True
    assert {"apktool", "jadx", "radare2", "ghidra"} <= tool_ids
    assert "nmap" not in tool_ids
    assert "nuclei" not in tool_ids
    assert "native" in altitudes
    assert "runtime" in altitudes
    assert altitudes[-1] == "variant_sweep"
    assert len(plan["plan_digest"]) == 64


def test_default_apk_request_uses_static_profile_when_no_native_libraries(tmp_path):
    plan = build_mobile_chat_plan(
        text="Test this APK",
        requested_by="analyst",
        attachment=_attachment(native=False),
        artifact=_artifact(tmp_path, native=False),
    )

    tool_ids = {item["tool_id"] for item in plan["tools"]}
    assert plan["requested_profile"] == "static"
    assert plan["profile"] == "static"
    assert plan["dynamic_deferred"] is False
    assert "jadx" in tool_ids
    assert "radare2" not in tool_ids
    assert all(item["altitude"] != "runtime" for item in plan["rounds"])


def test_hunt_scrutiny_is_monotonic_and_receipt_bound():
    cell = CoverageCell(
        cell_id="cell-01",
        altitude=HuntAltitude.CODE,
        object_reference="class-a",
        weakness_class="unsafe-webview",
    )
    raised = raise_scrutiny(
        cell,
        new_level=2,
        evidence_receipt="evidence-sha256",
        status=CoverageStatus.COVERED,
    )

    assert raised.scrutiny_level == 2
    assert raised.attempts == 1
    assert raised.evidence_receipts == ("evidence-sha256",)
    with pytest.raises(ValueError, match="cannot be lowered"):
        raise_scrutiny(raised, new_level=1, evidence_receipt="other-receipt")


def test_candidate_cannot_jump_to_confirmed_or_be_rejected_without_receipt():
    candidate = CandidateRecord(
        candidate_id="candidate-01",
        weakness_id="cwe-926",
        title="Exported component may lack permission protection",
    )

    with pytest.raises(ValueError, match="not allowed"):
        transition_candidate(
            candidate,
            new_state=CandidateState.CONFIRMED,
            disposition_reason="Skipped verification",
            evidence_receipt="receipt",
        )
    with pytest.raises(ValueError, match="requires an evidence or judge receipt"):
        transition_candidate(
            candidate,
            new_state=CandidateState.REJECTED,
            disposition_reason="No longer believed",
        )


def test_signed_mobile_static_queue_runs_fixed_networkless_worker(tmp_path):
    apk = tmp_path / "banking-app.apk"
    apk.write_bytes(_apk_bytes())
    ingestor = MobileArtifactIngestor(tmp_path / "artifacts")
    artifact = ingestor.ingest_file(apk.resolve())
    policy = MobileStaticWorkerPolicy(
        enabled=True,
        worker_id="mobile-static-worker",
        workspace_root=(tmp_path / "workspace").resolve(),
        aapt2_executable=_fake_aapt2(tmp_path),
        timeout_seconds=10,
        maximum_output_bytes=10_000,
    )
    key = b"m" * 48
    spool = MobileStaticSpool(tmp_path / "spool")
    job = create_mobile_static_job(
        run_id="mobile-run-01",
        artifact_id=artifact.artifact_id,
        artifact_sha256=artifact.sha256,
        hunt_plan_sha256="b" * 64,
        requested_by="mobile-analyst",
        signing_key=key,
        now=NOW,
    )
    spool.enqueue(job)
    assert spool.status(job.job_id) == {"job_id": job.job_id, "state": "queued"}

    receipt = MobileStaticQueueService(
        spool=spool,
        signing_key=key,
        policy=policy,
        ingestor=ingestor,
        clock=lambda: NOW,
    ).run_once()

    assert receipt is not None
    assert receipt.state == "completed"
    assert receipt.captures[0].tool == "aapt2"
    assert receipt.captures[0].return_code == 0
    assert receipt.candidate_observations[0]["title"] == "APK contains native libraries"
    status = spool.status(job.job_id)
    assert status is not None
    assert status["state"] == "completed"
    assert status["receipt"]["result_sha256"] == receipt.result_sha256


def test_signed_mobile_static_queue_rejects_tampered_job(tmp_path):
    spool = MobileStaticSpool(tmp_path / "spool")
    key = b"t" * 48
    job = create_mobile_static_job(
        run_id="mobile-tamper-01",
        artifact_id="apk-tamper-01",
        artifact_sha256="a" * 64,
        hunt_plan_sha256="b" * 64,
        requested_by="mobile-analyst",
        signing_key=key,
        now=NOW,
    )
    path = spool.enqueue(job)
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload["requested_by"] = "tampered-user"
    path.write_text(json.dumps(payload), encoding="utf-8")
    claimed = spool.claim_next()
    assert claimed is not None

    with pytest.raises(MobileStaticSpoolError, match="signature"):
        spool.load_claimed(claimed, key=key, now=NOW)


def test_conversation_ui_exposes_plus_button_progress_live_status_and_context():
    template = (ROOT / "vulnhunter/web/templates/web/conversation.html").read_text(encoding="utf-8")
    script = (ROOT / "vulnhunter/web/static/web/conversation-mobile.js").read_text(encoding="utf-8")
    context_script = (ROOT / "vulnhunter/web/static/web/conversation-mobile-context.js").read_text(
        encoding="utf-8"
    )

    assert "data-conversation-attach" in template
    assert "data-conversation-file" in template
    assert "web-conversation-attachment" in template
    assert "web-conversation-mobile-message" in template
    assert "web-conversation-mobile-followup" in template
    assert "conversation-mobile-execution.css" in template
    assert "conversation-mobile-context.js" in template
    assert 'setTimeout(() => item.classList.add("is-visible")' in script
    assert "watchMobileExecution" in script
    assert "data-mobile-execution-results" in script
    assert "data-mobile-activity-stream-url-template" in template
    assert "openMobileActivityStream" in script
    assert "activeMobilePlan" in context_script
    assert "bypassMobileFollowup" in context_script
    assert "form.requestSubmit()" in context_script
    assert "stopImmediatePropagation" in script


@pytest.mark.django_db
def test_chat_uploads_apk_answers_followups_then_hands_off_to_web_scan(client, settings, tmp_path):
    settings.ALLOWED_HOSTS = ["testserver"]
    settings.VULNHUNTER_MOBILE_ARTIFACT_ROOT = str(tmp_path / "mobile-artifacts")
    settings.VULNHUNTER_MOBILE_MAX_APK_BYTES = 10_000_000
    user = get_user_model().objects.create_user(
        username="mobile-chat-user",
        password="long-test-password-1234",
    )
    client.force_login(user)
    actor = SimpleNamespace(
        governance_identity=SimpleNamespace(reviewer_id="mobile-chat-user"),
        product_roles=("campaign-operator",),
    )

    with patch("vulnhunter.web.conversation_mobile_views._actor", return_value=actor):
        upload = client.post(
            "/workspace/attachments/",
            {"attachment": _apk_upload()},
        )
        assert upload.status_code == 200
        attachment = upload.json()["attachment"]
        assert attachment["kind"] == "android_apk"
        assert attachment["dex_count"] == 1
        assert attachment["native_library_count"] == 1

        request = client.post(
            "/workspace/mobile-message/",
            {
                "attachment_id": attachment["attachment_id"],
                "message": "Test this APK thoroughly",
            },
        )
        followup = client.post(
            "/workspace/mobile-followup/",
            {"message": "What tools did you select for this APK?"},
        )
        activity = client.get(
            f"/workspace/mobile-activity/{request.json()['mobile_plan']['run_id']}/stream/"
        )
        handoff = client.post(
            "/workspace/mobile-followup/",
            {"message": "Scan https://example.com using the passive profile"},
        )
        context = client.get("/workspace/mobile-context/")

    assert request.status_code == 200
    payload = request.json()
    assert payload["message"]["kind"] == "mobile_plan"
    assert payload["mobile_plan"]["profile"] == "static_and_native"
    assert payload["mobile_plan"]["dynamic_deferred"] is True
    assert payload["mobile_plan"]["execution"]["state"] == "gated"
    assert payload["mobile_plan"]["artifact"]["artifact_sha256"] == attachment["artifact_sha256"]

    assert followup.status_code == 200
    assert "planner selected" in followup.json()["message"]["content"].casefold()
    assert "jadx" in followup.json()["message"]["content"].casefold()
    assert handoff.status_code == 200
    assert handoff.json() == {"handoff": True}
    assert context.status_code == 200
    assert context.json() == {"mobile_plan": None}
    activity_body = b"".join(activity.streaming_content).decode()
    assert activity.status_code == 200
    assert "event: activity" in activity_body
    assert "plan_proposed" in activity_body
    assert "policy_denied" in activity_body


@pytest.mark.django_db
def test_mobile_activity_stream_returns_persisted_apk_events(client, monkeypatch):
    user = get_user_model().objects.create_user(
        username="mobile-activity-user",
        password="long-test-password-1234",
    )
    client.force_login(user)
    actor = SimpleNamespace(
        governance_identity=SimpleNamespace(reviewer_id="mobile-activity-user"),
        product_roles=("campaign-operator",),
    )
    plan = {
        "run_id": "mobile-activity-01",
        "execution": {"state": "gated", "reason": "Static worker is disabled."},
        "profile": "static",
    }
    payload = {
        "events": [
            {
                "event_id": "evt_0123456789abcdef01234567",
                "sequence": 1,
                "event_type": "policy_denied",
                "summary": "The APK worker remained blocked by deployment policy.",
                "timestamp": "2026-08-19T12:00:00+00:00",
                "metadata": {"reason": "Static worker is disabled."},
            }
        ],
        "last_sequence": 1,
        "terminal": True,
        "run_state": "blocked",
    }
    monkeypatch.setattr(
        "vulnhunter.web.conversation_mobile_views._actor",
        lambda *_args, **_kwargs: actor,
    )
    monkeypatch.setattr(
        "vulnhunter.web.conversation_mobile_views.current_mobile_plan",
        lambda *_args, **_kwargs: plan,
    )
    monkeypatch.setattr(
        "vulnhunter.web.conversation_mobile_views._record_mobile_activity",
        lambda **_kwargs: None,
    )
    monkeypatch.setattr(
        "vulnhunter.web.conversation_mobile_views.activity_payload",
        lambda *_args, **_kwargs: payload,
    )

    response = client.get("/workspace/mobile-activity/mobile-activity-01/stream/?after_sequence=0")
    body = b"".join(response.streaming_content).decode()

    assert response.status_code == 200
    assert response["Content-Type"].startswith("text/event-stream")
    assert "event: activity" in body
    assert "policy_denied" in body
    assert "Static worker is disabled." in body
