from __future__ import annotations

import io
import zipfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from django.contrib.auth import get_user_model
from django.core.files.uploadedfile import SimpleUploadedFile

ROOT = Path(__file__).resolve().parents[2]


def _apk_bytes() -> bytes:
    payload = io.BytesIO()
    with zipfile.ZipFile(payload, "w") as archive:
        archive.writestr("AndroidManifest.xml", b"manifest")
        archive.writestr("classes.dex", b"dex" * 40)
        archive.writestr("lib/arm64-v8a/libsecure.so", b"native" * 20)
    return payload.getvalue()


@pytest.mark.django_db
def test_chunked_apk_upload_auto_starts_the_mobile_worker_plan(
    client, settings, tmp_path, monkeypatch
):
    settings.ALLOWED_HOSTS = ["testserver"]
    settings.VULNHUNTER_MOBILE_ARTIFACT_ROOT = str(tmp_path / "mobile-artifacts")
    settings.VULNHUNTER_MOBILE_MAX_APK_BYTES = 1_000_000_000
    settings.VULNHUNTER_MOBILE_UPLOAD_CHUNK_BYTES = 64
    monkeypatch.setenv("VULNHUNTER_MOBILE_STATIC_ENQUEUE_ENABLED", "false")

    user = get_user_model().objects.create_user(
        username="large-apk-user",
        password="long-test-password-1234",
    )
    client.force_login(user)
    actor = SimpleNamespace(
        governance_identity=SimpleNamespace(reviewer_id="large-apk-user"),
        product_roles=("campaign-operator",),
    )
    apk = _apk_bytes()

    with patch("vulnhunter.web.conversation_mobile_views._actor", return_value=actor):
        started = client.post(
            "/workspace/uploads/start/",
            {"filename": "large-banking-app.apk", "size_bytes": str(len(apk))},
        )
        assert started.status_code == 200
        start_payload = started.json()
        assert start_payload["maximum_bytes"] == 1_000_000_000
        assert start_payload["chunk_bytes"] == 64

        offset = 0
        final = None
        while offset < len(apk):
            end = min(len(apk), offset + start_payload["chunk_bytes"])
            final = client.post(
                start_payload["chunk_url"],
                {
                    "offset": str(offset),
                    "chunk": SimpleUploadedFile(
                        "chunk.part",
                        apk[offset:end],
                        content_type="application/octet-stream",
                    ),
                },
            )
            assert final.status_code == 200
            payload = final.json()
            if "received_bytes" in payload:
                offset = int(payload["received_bytes"])
            else:
                offset = int(payload["upload"]["received_bytes"])

        assert final is not None
        result = final.json()
        assert result["auto_started"] is True
        assert result["message"]["kind"] == "mobile_plan"
        assert result["mobile_plan"]["requested_profile"] == "full"
        assert result["mobile_plan"]["profile"] == "static_and_native"
        assert result["mobile_plan"]["execution"]["state"] == "gated"
        assert result["attachment"]["size_bytes"] == len(apk)
        assert "automatic security analysis" in result["user_message"]["content"]

    staged = tmp_path / "mobile-artifacts" / ".conversation-uploads"
    assert not tuple(staged.glob("*.part"))


@pytest.mark.django_db
def test_chunked_upload_rejects_anything_above_one_gigabyte(client, settings, tmp_path):
    settings.ALLOWED_HOSTS = ["testserver"]
    settings.VULNHUNTER_MOBILE_ARTIFACT_ROOT = str(tmp_path / "mobile-artifacts")
    settings.VULNHUNTER_MOBILE_MAX_APK_BYTES = 1_000_000_000
    user = get_user_model().objects.create_user(
        username="oversize-apk-user",
        password="long-test-password-1234",
    )
    client.force_login(user)
    actor = SimpleNamespace(
        governance_identity=SimpleNamespace(reviewer_id="oversize-apk-user"),
        product_roles=("campaign-operator",),
    )

    with patch("vulnhunter.web.conversation_mobile_views._actor", return_value=actor):
        response = client.post(
            "/workspace/uploads/start/",
            {"filename": "too-large.apk", "size_bytes": "1000000001"},
        )

    assert response.status_code == 400
    assert "upload limit" in response.json()["detail"]


def test_workspace_uses_resumable_uploads_and_codespaces_sets_one_gigabyte():
    template = (ROOT / "vulnhunter/web/templates/web/conversation.html").read_text(encoding="utf-8")
    script = (ROOT / "vulnhunter/web/static/web/conversation-mobile.js").read_text(encoding="utf-8")
    post_create = (ROOT / ".devcontainer/post-create.sh").read_text(encoding="utf-8")
    start_script = (ROOT / ".devcontainer/start-vulnhunter.sh").read_text(encoding="utf-8")

    assert "data-upload-start-url" in template
    assert "uploadInChunks" in script
    assert "file.slice(offset, end)" in script
    assert "consumeUploadResponse" in script
    assert "VULNHUNTER_MOBILE_MAX_APK_BYTES=1000000000" in post_create
    assert "VULNHUNTER_MOBILE_UPLOAD_CHUNK_BYTES=8388608" in post_create
    assert "prepare_mobile_static_worker.py" in start_script
    assert "automatic isolated static/native worker ready" in start_script
