from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from django.contrib.auth import get_user_model
from django.test import Client

from vulnhunter.mobile.mobsf import MobSFServiceConfig


def _write_private(path: Path, payload: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(payload, encoding="utf-8")
    path.chmod(0o600)
    return path.resolve()


def _write_key(path: Path, payload: bytes) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(payload)
    path.chmod(0o600)
    return path.resolve()


def _mobile_plan() -> dict[str, object]:
    return {
        "plan_id": "mobile-plan-endpoint-01",
        "plan_digest": "a" * 64,
        "requested_by": "mobile-endpoint-user",
        "artifact": {
            "artifact_id": "apk-" + "b" * 24,
            "artifact_sha256": "b" * 64,
            "original_filename": "safe.apk",
        },
        "deferred_tools": [
            {
                "tool_id": "mobsf",
                "name": "MobSF",
                "state": "approval_required",
                "reason": "Exact approval is required.",
            }
        ],
        "execution": {"state": "gated"},
    }


@pytest.mark.django_db
def test_mobile_extension_approval_and_status_follow_the_durable_workspace(
    client,
    settings,
    tmp_path,
    monkeypatch,
):
    settings.ALLOWED_HOSTS = ["testserver"]
    user = get_user_model().objects.create_user(
        username="mobile-endpoint-user",
        password="long-test-password-1234",
    )
    client.force_login(user)

    mobsf_key = _write_private(tmp_path / "mobsf-api.key", "m" * 64)
    mobsf_policy = MobSFServiceConfig(
        enabled=True,
        base_url="http://127.0.0.1:8008",
        api_key_file=mobsf_key,
        auth_header="X-Mobsf-Api-Key",
    )
    policy_path = _write_private(
        tmp_path / "mobsf.json",
        mobsf_policy.model_dump_json(indent=2) + "\n",
    )
    extension_key = _write_key(tmp_path / "mobile-extension.key", b"e" * 48)
    spool_root = tmp_path / "extension-spool"
    monkeypatch.setenv("VULNHUNTER_MOBSF_POLICY", str(policy_path))
    monkeypatch.setenv(
        "VULNHUNTER_MOBILE_EXTENSION_SIGNING_KEY_FILE",
        str(extension_key),
    )
    monkeypatch.setenv("VULNHUNTER_MOBILE_EXTENSION_SPOOL_ROOT", str(spool_root))

    session = client.session
    session["vulnhunter_conversation_mobile_plan"] = _mobile_plan()
    session.save()
    actor = SimpleNamespace(governance_identity=SimpleNamespace(reviewer_id="mobile-endpoint-user"))

    with patch(
        "vulnhunter.web.conversation_mobile_extension_views._actor",
        return_value=actor,
    ):
        approval = client.post(
            "/workspace/mobile-extensions/approve/",
            {
                "kind": "mobsf",
                "reason": "Approve exact private MobSF analysis for this APK.",
            },
        )
        assert approval.status_code == 200
        approved = approval.json()["mobile_extension"]
        assert approved["state"] == "queued"
        status_url = approved["status_url"]

        owner_status = client.get(status_url)
        assert owner_status.status_code == 200
        assert owner_status.json()["mobile_extension"]["state"] == "queued"

        second_session = Client()
        second_session.force_login(user)
        reopened = second_session.get(status_url)
        assert reopened.status_code == 200
        assert reopened.json()["mobile_extension"]["state"] == "queued"

        intruder = get_user_model().objects.create_user(
            username="mobile-endpoint-intruder",
            password="long-test-password-1234",
        )
        intruder_session = Client()
        intruder_session.force_login(intruder)
        hidden = intruder_session.get(status_url)
        assert hidden.status_code == 404
