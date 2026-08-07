from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
from uuid import uuid4

from vulnhunter.mobile.models import MobileArtifactRecord
from vulnhunter.mobile.static_spool import MobileStaticSpool
from vulnhunter.mobile.static_worker import MobileStaticWorkerPolicy
from vulnhunter.web.conversation_attachments import ConversationAttachment
from vulnhunter.web.mobile_assessment_graph import bind_mobile_assessment_graph
from vulnhunter.web.mobile_conversation import build_mobile_chat_plan
from vulnhunter.web.mobile_execution import enqueue_mobile_static_if_ready, mobile_static_status


class Session(dict):
    modified = False


def _artifact(tmp_path: Path) -> MobileArtifactRecord:
    apk = tmp_path / "stable.apk"
    apk.write_bytes(b"stable-apk")
    return MobileArtifactRecord(
        artifact_id="apk-0123456789abcdef01234567",
        original_filename="stable.apk",
        stored_path=apk,
        sha256="a" * 64,
        size_bytes=10,
        archive_entry_count=2,
        total_uncompressed_bytes=10,
        manifest_entry="AndroidManifest.xml",
        dex_entries=("classes.dex",),
        native_libraries=(),
        native_abis=(),
    )


def _attachment(identifier: str) -> ConversationAttachment:
    return ConversationAttachment(
        attachment_id=identifier,
        kind="android_apk",
        artifact_id="apk-0123456789abcdef01234567",
        artifact_sha256="a" * 64,
        original_filename="stable.apk",
        size_bytes=10,
        archive_entry_count=2,
        dex_count=1,
        native_library_count=0,
        native_abis=(),
        created_at="2026-08-07T10:00:00+00:00",
    )


def _request(workspace_id, *, username: str = "Mobile Operator"):
    return SimpleNamespace(
        session=Session(),
        user=SimpleNamespace(username=username),
        vulnhunter_thread=SimpleNamespace(thread_id=workspace_id),
    )


def test_same_workspace_artifact_and_workflow_reuse_assessment_identity(tmp_path):
    artifact = _artifact(tmp_path)
    workspace = str(uuid4())
    first = build_mobile_chat_plan(
        text="Test this APK",
        requested_by="reviewer-one",
        attachment=_attachment("attachment-11111111111111111111"),
        artifact=artifact,
        workspace_id=workspace,
    )
    second = build_mobile_chat_plan(
        text="Test this APK",
        requested_by="reviewer-one",
        attachment=_attachment("attachment-22222222222222222222"),
        artifact=artifact,
        workspace_id=workspace,
    )

    assert second["run_id"] == first["run_id"]
    assert second["plan_id"] == first["plan_id"]
    assert second["plan_digest"] == first["plan_digest"]
    assert second["artifact"]["attachment_id"] != first["artifact"]["attachment_id"]


def test_workspace_or_intended_workflow_changes_assessment_identity(tmp_path):
    artifact = _artifact(tmp_path)
    attachment = _attachment("attachment-11111111111111111111")
    workspace = str(uuid4())
    first = build_mobile_chat_plan(
        text="Test this APK",
        requested_by="reviewer-one",
        attachment=attachment,
        artifact=artifact,
        workspace_id=workspace,
    )
    other_workspace = build_mobile_chat_plan(
        text="Test this APK",
        requested_by="reviewer-one",
        attachment=attachment,
        artifact=artifact,
        workspace_id=str(uuid4()),
    )
    full = build_mobile_chat_plan(
        text="Do a full deep test of this APK",
        requested_by="reviewer-one",
        attachment=attachment,
        artifact=artifact,
        workspace_id=workspace,
    )

    assert other_workspace["run_id"] != first["run_id"]
    assert full["run_id"] != first["run_id"]


def test_graph_create_or_bind_survives_recreated_attachment(settings, tmp_path):
    settings.VULNHUNTER_TASK_GRAPH_ROOT = tmp_path / "graphs"
    artifact = _artifact(tmp_path)
    workspace = uuid4()
    request = _request(workspace)
    first = build_mobile_chat_plan(
        text="Test this APK",
        requested_by="reviewer-one",
        attachment=_attachment("attachment-11111111111111111111"),
        artifact=artifact,
        workspace_id=str(workspace),
    )
    first["execution"] = {"state": "queued"}
    first_bound = bind_mobile_assessment_graph(request, plan=first)

    second = build_mobile_chat_plan(
        text="Test this APK",
        requested_by="reviewer-one",
        attachment=_attachment("attachment-22222222222222222222"),
        artifact=artifact,
        workspace_id=str(workspace),
    )
    second["execution"] = {"state": "queued"}
    second_bound = bind_mobile_assessment_graph(request, plan=second)

    first_graph = first_bound["assessment_graph"]
    second_graph = second_bound["assessment_graph"]
    assert second_bound["run_id"] == first_bound["run_id"]
    assert second_graph["graph_id"] == first_graph["graph_id"]
    assert second_graph["revision"] == first_graph["revision"]


def test_duplicate_queue_submission_reuses_exact_signed_job(settings, tmp_path):
    artifact = _artifact(tmp_path)
    attachment = _attachment("attachment-11111111111111111111")
    request = SimpleNamespace(session=Session())
    plan = {
        "run_id": "mobile-idempotent-job",
        "plan_digest": "b" * 64,
    }
    policy = MobileStaticWorkerPolicy(
        enabled=True,
        worker_id="mobile-static-worker",
        workspace_root=(tmp_path / "workspace").resolve(),
        aapt2_executable=Path("/bin/true").resolve(),
        timeout_seconds=10,
        maximum_output_bytes=10_000,
    )
    spool_root = tmp_path / "spool"
    settings.VULNHUNTER_MOBILE_STATIC_WORKER_POLICY = tmp_path / "policy.json"
    key = b"k" * 48

    with (
        patch("vulnhunter.web.mobile_execution._env_bool", return_value=True),
        patch(
            "vulnhunter.web.mobile_execution.MobileStaticWorkerPolicy.from_path",
            return_value=policy,
        ),
        patch("vulnhunter.web.mobile_execution._analysis_capacity_reason", return_value=None),
        patch("vulnhunter.web.mobile_execution.load_worker_signing_key", return_value=key),
        patch("vulnhunter.web.mobile_execution._spool_root", return_value=spool_root),
    ):
        first = enqueue_mobile_static_if_ready(
            request,
            plan=plan,
            attachment=attachment,
            artifact=artifact,
            requested_by="reviewer-one",
        )
        second = enqueue_mobile_static_if_ready(
            request,
            plan=plan,
            attachment=attachment,
            artifact=artifact,
            requested_by="reviewer-one",
        )

    assert first["state"] == "queued"
    assert first["reused"] is False
    assert second["state"] == "queued"
    assert second["job_id"] == first["job_id"]
    assert second["reused"] is True
    assert len(tuple(MobileStaticSpool(spool_root).pending.glob("*.json"))) == 1


def test_status_reconstructs_from_persisted_job_after_local_state_is_cleared(settings, tmp_path):
    artifact = _artifact(tmp_path)
    attachment = _attachment("attachment-11111111111111111111")
    first_request = SimpleNamespace(session=Session())
    plan = {"run_id": "mobile-reconnect-job", "plan_digest": "c" * 64}
    policy = MobileStaticWorkerPolicy(
        enabled=True,
        worker_id="mobile-static-worker",
        workspace_root=(tmp_path / "workspace").resolve(),
        aapt2_executable=Path("/bin/true").resolve(),
        timeout_seconds=10,
        maximum_output_bytes=10_000,
    )
    spool_root = tmp_path / "spool"
    settings.VULNHUNTER_MOBILE_STATIC_WORKER_POLICY = tmp_path / "policy.json"
    key = b"r" * 48

    with (
        patch("vulnhunter.web.mobile_execution._env_bool", return_value=True),
        patch(
            "vulnhunter.web.mobile_execution.MobileStaticWorkerPolicy.from_path",
            return_value=policy,
        ),
        patch("vulnhunter.web.mobile_execution._analysis_capacity_reason", return_value=None),
        patch("vulnhunter.web.mobile_execution.load_worker_signing_key", return_value=key),
        patch("vulnhunter.web.mobile_execution._spool_root", return_value=spool_root),
    ):
        queued = enqueue_mobile_static_if_ready(
            first_request,
            plan=plan,
            attachment=attachment,
            artifact=artifact,
            requested_by="reviewer-one",
        )
        cleared_request = SimpleNamespace(session=Session())
        recovered = mobile_static_status(
            cleared_request,
            job_id=str(queued["job_id"]),
            requested_by="reviewer-one",
        )
        foreign = mobile_static_status(
            SimpleNamespace(session=Session()),
            job_id=str(queued["job_id"]),
            requested_by="reviewer-two",
        )

    assert recovered == {"job_id": queued["job_id"], "state": "queued"}
    assert cleared_request.session["vulnhunter_conversation_mobile_jobs"] == {
        queued["job_id"]: "reviewer-one"
    }
    assert foreign is None
