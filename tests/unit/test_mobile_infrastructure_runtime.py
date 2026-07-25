from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from vulnhunter.mobile.mobsf import MobSFError, MobSFServiceConfig
from vulnhunter.mobile.runtime import (
    MobileRuntimeError,
    MobileRuntimePolicy,
    SignedMobileRuntimeApproval,
)
from vulnhunter.web.mobile_infrastructure import mobile_infrastructure_status

NOW = datetime(2026, 7, 25, 8, 30, tzinfo=UTC)


def _write_private(path: Path, payload: str) -> Path:
    path.write_text(payload, encoding="utf-8")
    path.chmod(0o600)
    return path.resolve()


def _runtime_policy(tmp_path: Path, *, expires_at: datetime | None = None) -> MobileRuntimePolicy:
    dummy = _write_private(tmp_path / "tool", "placeholder")
    dummy.chmod(0o700)
    adapter = _write_private(tmp_path / "adapter.py", "print('{}')\n")
    return MobileRuntimePolicy(
        enabled=True,
        runtime_id="emulator-lab-01",
        adb_executable=dummy,
        python_executable=dummy,
        frida_executable=dummy,
        frida_inventory_adapter=adapter,
        adb_serial="emulator-5554",
        frida_device_id="emulator-5554",
        expected_fingerprint="vulnhunter/test/emulator:15/AP4A/test-keys",
        expected_api_level=35,
        expected_abi="x86_64",
        expected_frida_version="17.9.11",
        expires_at=expires_at or NOW + timedelta(hours=4),
    )


def test_mobsf_policy_requires_loopback_and_owner_only_key(tmp_path):
    key = _write_private(tmp_path / "mobsf-api.key", "k" * 64)
    config = MobSFServiceConfig(
        enabled=True,
        base_url="http://127.0.0.1:8008",
        api_key_file=key,
        auth_header="X-Mobsf-Api-Key",
    )

    assert config.read_api_key() == "k" * 64
    with pytest.raises(ValueError):
        MobSFServiceConfig(
            enabled=True,
            base_url="https://mobsf.example.test:8008",
            api_key_file=key,
        )

    key.chmod(0o644)
    with pytest.raises(MobSFError, match="owner-only"):
        config.read_api_key()


def test_runtime_approval_is_signature_and_digest_bound(tmp_path):
    policy = _runtime_policy(tmp_path)
    key = b"r" * 48
    approval = SignedMobileRuntimeApproval.create(
        approval_id="approval-runtime-01",
        plan_sha256="a" * 64,
        artifact_sha256="b" * 64,
        package_name="com.example.safe",
        runtime_id=policy.runtime_id,
        adb_serial=policy.adb_serial,
        frida_device_id=policy.frida_device_id,
        approved_by="security-reviewer",
        approved_at=NOW,
        expires_at=NOW + timedelta(minutes=30),
        key=key,
    )

    approval.verify(
        key=key,
        policy=policy,
        artifact_sha256="b" * 64,
        plan_sha256="a" * 64,
        package_name="com.example.safe",
        now=NOW + timedelta(minutes=1),
    )

    with pytest.raises(MobileRuntimeError, match="exact execution"):
        approval.verify(
            key=key,
            policy=policy,
            artifact_sha256="c" * 64,
            plan_sha256="a" * 64,
            package_name="com.example.safe",
            now=NOW + timedelta(minutes=1),
        )

    tampered = approval.model_copy(update={"signature": "0" * 64})
    with pytest.raises(MobileRuntimeError, match="signature"):
        tampered.verify(
            key=key,
            policy=policy,
            artifact_sha256="b" * 64,
            plan_sha256="a" * 64,
            package_name="com.example.safe",
            now=NOW + timedelta(minutes=1),
        )


def test_mobile_infrastructure_projection_is_fail_closed_and_non_secret(tmp_path, monkeypatch):
    mobsf_key = _write_private(tmp_path / "mobsf.key", "m" * 64)
    mobsf_policy_path = tmp_path / "mobsf.json"
    mobsf_policy = MobSFServiceConfig(
        enabled=True,
        base_url="http://127.0.0.1:8008",
        api_key_file=mobsf_key,
        auth_header="X-Mobsf-Api-Key",
    )
    _write_private(
        mobsf_policy_path,
        mobsf_policy.model_dump_json(indent=2) + "\n",
    )

    runtime_policy_path = tmp_path / "runtime.json"
    runtime_policy = _runtime_policy(tmp_path / "runtime")
    _write_private(
        runtime_policy_path,
        runtime_policy.model_dump_json(indent=2) + "\n",
    )

    monkeypatch.setenv("VULNHUNTER_MOBSF_POLICY", str(mobsf_policy_path.resolve()))
    monkeypatch.setenv(
        "VULNHUNTER_MOBILE_RUNTIME_POLICY",
        str(runtime_policy_path.resolve()),
    )
    status = mobile_infrastructure_status(now=NOW)

    assert status["mobsf"]["state"] == "approval_required"
    assert status["adb"]["state"] == "approval_required"
    assert status["frida"]["state"] == "approval_required"
    assert status["adb"]["runtime_id"] == runtime_policy.runtime_id
    assert status["frida"]["expected_frida_version"] == "17.9.11"
    assert "api_key" not in json.dumps(status).casefold()


def test_expired_runtime_projection_is_gated(tmp_path, monkeypatch):
    runtime_policy_path = tmp_path / "runtime-expired.json"
    runtime_policy = _runtime_policy(
        tmp_path / "expired-runtime",
        expires_at=NOW - timedelta(seconds=1),
    )
    _write_private(
        runtime_policy_path,
        runtime_policy.model_dump_json(indent=2) + "\n",
    )
    monkeypatch.setenv(
        "VULNHUNTER_MOBILE_RUNTIME_POLICY",
        str(runtime_policy_path.resolve()),
    )

    status = mobile_infrastructure_status(now=NOW)

    assert status["adb"]["state"] == "gated"
    assert status["frida"]["state"] == "gated"
    assert "expired" in str(status["adb"]["reason"]).casefold()
