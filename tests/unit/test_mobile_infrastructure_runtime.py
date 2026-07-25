from __future__ import annotations

import io
import json
import zipfile
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest

from vulnhunter.mobile import MobileArtifactIngestor
from vulnhunter.mobile.extension_service import MobileExtensionQueueService
from vulnhunter.mobile.extension_spool import (
    MobileExtensionSpool,
    MobileExtensionSpoolError,
    SignedMobileExtensionJob,
)
from vulnhunter.mobile.mobsf import (
    MobSFError,
    MobSFEvidenceReceipt,
    MobSFServiceConfig,
)
from vulnhunter.mobile.runtime import (
    MobileRuntimeError,
    MobileRuntimePolicy,
    SignedMobileRuntimeApproval,
)
from vulnhunter.web.mobile_extension_execution import enqueue_mobile_extension
from vulnhunter.web.mobile_infrastructure import mobile_infrastructure_status

NOW = datetime(2026, 7, 25, 8, 30, tzinfo=UTC)


class _Session(dict):
    modified = False


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


def _runtime_policy(
    tmp_path: Path,
    *,
    expires_at: datetime | None = None,
) -> MobileRuntimePolicy:
    tmp_path.mkdir(parents=True, exist_ok=True)
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


def _apk_bytes() -> bytes:
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w") as archive:
        archive.writestr("AndroidManifest.xml", b"manifest")
        archive.writestr("classes.dex", b"dex\n035\x00")
    return output.getvalue()


def _mobsf_policy(tmp_path: Path) -> tuple[MobSFServiceConfig, Path]:
    key = _write_private(tmp_path / "mobsf-api.key", "m" * 64)
    config = MobSFServiceConfig(
        enabled=True,
        base_url="http://127.0.0.1:8008",
        api_key_file=key,
        auth_header="X-Mobsf-Api-Key",
    )
    policy_path = _write_private(
        tmp_path / "mobsf.json",
        config.model_dump_json(indent=2) + "\n",
    )
    return config, policy_path


def _plan(*, tool_id: str) -> dict[str, object]:
    return {
        "plan_digest": "a" * 64,
        "artifact": {
            "artifact_id": "apk-" + "b" * 24,
            "artifact_sha256": "b" * 64,
        },
        "deferred_tools": [
            {
                "tool_id": tool_id,
                "state": "approval_required",
                "reason": "Exact approval required.",
            }
        ],
    }


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


def test_mobile_infrastructure_projection_is_fail_closed_and_non_secret(
    tmp_path,
    monkeypatch,
):
    _, mobsf_policy_path = _mobsf_policy(tmp_path)

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


def test_extension_approval_rechecks_current_runtime_registration(tmp_path, monkeypatch):
    runtime_policy = _runtime_policy(
        tmp_path / "expired-runtime",
        expires_at=datetime.now(UTC) - timedelta(seconds=1),
    )
    policy_path = _write_private(
        tmp_path / "runtime-expired.json",
        runtime_policy.model_dump_json(indent=2) + "\n",
    )
    monkeypatch.setenv("VULNHUNTER_MOBILE_RUNTIME_POLICY", str(policy_path))
    request = SimpleNamespace(session=_Session())

    result = enqueue_mobile_extension(
        request,
        plan=_plan(tool_id="adb"),
        kind="runtime",
        package_name="com.example.safe",
        reason="Approve the exact disposable runtime execution.",
        requested_by="security-reviewer",
    )

    assert result["state"] == "gated"
    assert "expired" in str(result["reason"]).casefold()
    assert request.session == {}


def test_mobsf_approval_creates_one_signed_session_bound_job(tmp_path, monkeypatch):
    _, policy_path = _mobsf_policy(tmp_path / "mobsf")
    spool_root = tmp_path / "spool"
    signing_key = _write_key(tmp_path / "extension.key", b"e" * 48)
    monkeypatch.setenv("VULNHUNTER_MOBSF_POLICY", str(policy_path))
    monkeypatch.setenv("VULNHUNTER_MOBILE_EXTENSION_SPOOL_ROOT", str(spool_root))
    monkeypatch.setenv(
        "VULNHUNTER_MOBILE_EXTENSION_SIGNING_KEY_FILE",
        str(signing_key),
    )
    request = SimpleNamespace(session=_Session())
    plan = _plan(tool_id="mobsf")

    result = enqueue_mobile_extension(
        request,
        plan=plan,
        kind="mobsf",
        package_name=None,
        reason="Approve exact private MobSF analysis for this APK.",
        requested_by="security-reviewer",
    )

    assert result["state"] == "queued"
    assert result["artifact_sha256"] == "b" * 64
    assert MobileExtensionSpool(spool_root).status(str(result["job_id"]))["state"] == "queued"
    assert request.session["vulnhunter_mobile_extension_jobs"][result["job_id"]] == (
        "security-reviewer"
    )

    plan["extension_jobs"] = [result]
    duplicate = enqueue_mobile_extension(
        request,
        plan=plan,
        kind="mobsf",
        package_name=None,
        reason="Approve exact private MobSF analysis for this APK.",
        requested_by="security-reviewer",
    )
    assert duplicate["state"] == "gated"
    assert "already" in str(duplicate["reason"]).casefold()


def test_extension_spool_rejects_tampering_and_sanitizes_malformed_kind(tmp_path):
    key = b"e" * 48
    spool = MobileExtensionSpool(tmp_path / "spool")
    job = SignedMobileExtensionJob.create(
        job_id="mobile-mobsf-job-01",
        kind="mobsf",
        artifact_id="apk-" + "b" * 24,
        artifact_sha256="b" * 64,
        plan_sha256="a" * 64,
        requested_by="security-reviewer",
        approval_reason="Approve exact private MobSF analysis.",
        package_name=None,
        runtime_approval=None,
        created_at=NOW,
        expires_at=NOW + timedelta(hours=1),
        key=key,
    )
    spool.enqueue(job.model_copy(update={"signature": "0" * 64}))
    claimed = spool.claim_next()
    assert claimed is not None
    with pytest.raises(MobileExtensionSpoolError, match="signature"):
        spool.load_claimed(claimed, key=key, now=NOW + timedelta(minutes=1))

    malformed = json.loads(claimed.read_text(encoding="utf-8"))
    malformed["kind"] = "not-a-real-extension"
    claimed.write_text(json.dumps(malformed), encoding="utf-8")
    spool.reject(claimed, reason="Tampered job rejected safely.", now=NOW)
    status = spool.status(job.job_id)
    assert status is not None
    assert status["state"] == "rejected"
    assert status["kind"] == "mobsf"


def test_mobsf_worker_keeps_full_report_private_and_returns_bounded_receipt(
    tmp_path,
    monkeypatch,
):
    ingestor = MobileArtifactIngestor(tmp_path / "artifacts")
    record = ingestor.ingest_chunks("safe.apk", [_apk_bytes()])
    _, policy_path = _mobsf_policy(tmp_path / "mobsf")
    spool = MobileExtensionSpool(tmp_path / "spool")
    signing_key = b"e" * 48
    current = datetime.now(UTC)
    job = SignedMobileExtensionJob.create(
        job_id="mobile-mobsf-worker-01",
        kind="mobsf",
        artifact_id=record.artifact_id,
        artifact_sha256=record.sha256,
        plan_sha256="a" * 64,
        requested_by="security-reviewer",
        approval_reason="Approve exact private MobSF analysis.",
        package_name=None,
        runtime_approval=None,
        created_at=current,
        expires_at=current + timedelta(hours=1),
        key=signing_key,
    )
    spool.enqueue(job)

    class _FakeMobSFClient:
        def __init__(self, config):
            assert config.enabled is True

        def analyse(self, apk_path, *, artifact_sha256):
            assert apk_path == record.stored_path
            assert artifact_sha256 == record.sha256
            return MobSFEvidenceReceipt(
                scan_hash="scan-safe-001",
                artifact_sha256=record.sha256,
                report_sha256="c" * 64,
                report_bytes=128,
                report_keys=("package_name", "secret_detail"),
                package_name="com.example.safe",
                app_name="Safe App",
                security_score=72,
                report={
                    "package_name": "com.example.safe",
                    "secret_detail": "owner-private-full-report",
                },
            )

    monkeypatch.setattr(
        "vulnhunter.mobile.extension_service.MobSFClient",
        _FakeMobSFClient,
    )
    result_root = tmp_path / "results"
    service = MobileExtensionQueueService(
        spool=spool,
        signing_key=signing_key,
        runtime_approval_key=b"r" * 48,
        ingestor=ingestor,
        result_root=result_root,
        mobsf_policy_path=policy_path,
        runtime_policy_path=tmp_path / "unused-runtime.json",
    )

    receipt = service.run_once()

    assert receipt is not None
    assert receipt.state == "completed"
    assert receipt.evidence["package_name"] == "com.example.safe"
    assert "report" not in receipt.evidence
    private_result = result_root / job.job_id / "mobsf-result.json"
    assert private_result.is_file()
    assert "owner-private-full-report" in private_result.read_text(encoding="utf-8")
    public_status = spool.status(job.job_id)
    assert public_status is not None
    assert "owner-private-full-report" not in json.dumps(public_status)
