from __future__ import annotations

import io
import zipfile
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from django.contrib.auth import get_user_model
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import Client

from vulnhunter.web.models import ConversationThread


def _apk_bytes() -> bytes:
    payload = io.BytesIO()
    with zipfile.ZipFile(payload, "w") as archive:
        archive.writestr("AndroidManifest.xml", b"manifest")
        archive.writestr("classes.dex", b"dex" * 40)
    return payload.getvalue()


def _actor(reviewer_id: str):
    return SimpleNamespace(
        governance_identity=SimpleNamespace(reviewer_id=reviewer_id),
        product_roles=("campaign-operator",),
    )


def _complete_chunked_upload(client, *, actor, apk: bytes):
    with patch("vulnhunter.web.conversation_mobile_views._actor", return_value=actor):
        started = client.post(
            "/workspace/uploads/start/",
            {"filename": "receipt.apk", "size_bytes": str(len(apk))},
        )
        assert started.status_code == 200
        start_payload = started.json()
        thread_id = str(client.session["vulnhunter_active_conversation_thread"])
        offset = 0
        final_offset = 0
        final_chunk = b""
        final = None
        while offset < len(apk):
            end = min(len(apk), offset + int(start_payload["chunk_bytes"]))
            final_offset = offset
            final_chunk = apk[offset:end]
            final = client.post(
                start_payload["chunk_url"],
                {
                    "offset": str(offset),
                    "thread_id": thread_id,
                    "chunk": SimpleUploadedFile(
                        "chunk.part",
                        final_chunk,
                        content_type="application/octet-stream",
                    ),
                },
                HTTP_X_VULNHUNTER_THREAD=thread_id,
            )
            assert final.status_code == 200
            result = final.json()
            offset = int(result.get("received_bytes") or result["upload"]["received_bytes"])
    assert final is not None
    return start_payload, thread_id, final_offset, final_chunk, final.json()


@pytest.mark.django_db
def test_duplicate_final_chunk_returns_exact_completion_without_duplicate_messages(
    client,
    settings,
    tmp_path,
    monkeypatch,
):
    settings.ALLOWED_HOSTS = ["testserver"]
    settings.VULNHUNTER_MOBILE_ARTIFACT_ROOT = str(tmp_path / "mobile-artifacts")
    settings.VULNHUNTER_MOBILE_MAX_APK_BYTES = 1_000_000
    settings.VULNHUNTER_MOBILE_UPLOAD_CHUNK_BYTES = 64
    monkeypatch.setenv("VULNHUNTER_MOBILE_STATIC_ENQUEUE_ENABLED", "false")
    user = get_user_model().objects.create_user(
        username="receipt-owner",
        password="long-test-password-1234",
    )
    client.force_login(user)
    actor = _actor("receipt-owner")
    apk = _apk_bytes()
    started, thread_id, final_offset, final_chunk, first_payload = _complete_chunked_upload(
        client,
        actor=actor,
        apk=apk,
    )
    thread = ConversationThread.objects.get(thread_id=thread_id, owner=user)
    first_messages = list(thread.data["vulnhunter_conversation_messages"])

    with patch("vulnhunter.web.conversation_mobile_views._actor", return_value=actor):
        repeated = client.post(
            started["chunk_url"],
            {
                "offset": str(final_offset),
                "thread_id": thread_id,
                "chunk": SimpleUploadedFile(
                    "chunk.part",
                    final_chunk,
                    content_type="application/octet-stream",
                ),
            },
            HTTP_X_VULNHUNTER_THREAD=thread_id,
        )

    assert repeated.status_code == 200
    assert repeated.json() == first_payload
    thread.refresh_from_db()
    assert thread.data["vulnhunter_conversation_messages"] == first_messages
    assert repeated.json()["upload"]["complete"] is True


@pytest.mark.django_db
def test_completion_status_survives_cleared_browser_session_and_device_switch(
    client,
    settings,
    tmp_path,
    monkeypatch,
):
    settings.ALLOWED_HOSTS = ["testserver"]
    settings.VULNHUNTER_MOBILE_ARTIFACT_ROOT = str(tmp_path / "mobile-artifacts")
    settings.VULNHUNTER_MOBILE_MAX_APK_BYTES = 1_000_000
    settings.VULNHUNTER_MOBILE_UPLOAD_CHUNK_BYTES = 64
    monkeypatch.setenv("VULNHUNTER_MOBILE_STATIC_ENQUEUE_ENABLED", "false")
    user = get_user_model().objects.create_user(
        username="receipt-device-owner",
        password="long-test-password-1234",
    )
    client.force_login(user)
    actor = _actor("receipt-device-owner")
    started, thread_id, _, _, first_payload = _complete_chunked_upload(
        client,
        actor=actor,
        apk=_apk_bytes(),
    )

    second_device = Client()
    second_device.force_login(user)
    with patch("vulnhunter.web.conversation_mobile_views._actor", return_value=actor):
        recovered = second_device.get(
            started["status_url"],
            HTTP_X_VULNHUNTER_THREAD=thread_id,
        )

    assert recovered.status_code == 200
    assert recovered.json() == first_payload
    assert recovered.json()["mobile_plan"]["run_id"] == first_payload["mobile_plan"]["run_id"]


@pytest.mark.django_db
def test_completion_receipt_isolated_to_owning_workspace(
    client,
    settings,
    tmp_path,
    monkeypatch,
):
    settings.ALLOWED_HOSTS = ["testserver"]
    settings.VULNHUNTER_MOBILE_ARTIFACT_ROOT = str(tmp_path / "mobile-artifacts")
    settings.VULNHUNTER_MOBILE_MAX_APK_BYTES = 1_000_000
    settings.VULNHUNTER_MOBILE_UPLOAD_CHUNK_BYTES = 64
    monkeypatch.setenv("VULNHUNTER_MOBILE_STATIC_ENQUEUE_ENABLED", "false")
    user = get_user_model().objects.create_user(
        username="receipt-workspace-owner",
        password="long-test-password-1234",
    )
    client.force_login(user)
    actor = _actor("receipt-workspace-owner")
    started, _, _, _, _ = _complete_chunked_upload(client, actor=actor, apk=_apk_bytes())
    other_thread = ConversationThread.objects.create(owner=user, title="Other workspace", data={})

    with patch("vulnhunter.web.conversation_mobile_views._actor", return_value=actor):
        response = client.get(
            started["status_url"],
            HTTP_X_VULNHUNTER_THREAD=str(other_thread.thread_id),
        )

    assert response.status_code == 404
    assert "missing or has expired" in response.json()["detail"]
