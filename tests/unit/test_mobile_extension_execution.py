from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

from vulnhunter.mobile import extension_service
from vulnhunter.mobile.extension_service import MobileExtensionQueueService
from vulnhunter.mobile.extension_spool import (
    MobileExtensionReceipt,
    MobileExtensionSpool,
    SignedMobileExtensionJob,
)
from vulnhunter.mobile.runtime import (
    MobileRuntimeCapture,
    MobileRuntimeExecutor,
    MobileRuntimePolicy,
    SignedMobileRuntimeApproval,
)
from vulnhunter.web import mobile_extension_execution

NOW = datetime(2026, 7, 25, 9, 30, tzinfo=UTC)


class _Session(dict):
    modified = False


def _private_key(path: Path, value: bytes = b"k" * 48) -> Path:
    path.write_bytes(value)
    path.chmod(0o600)
    return path.resolve()


def _capture(action: str, return_code: int = 0) -> MobileRuntimeCapture:
    output = b"ok" if return_code == 0 else b"failed"
    return MobileRuntimeCapture(
        action=action,
        return_code=return_code,
        output_sha256=hashlib.sha256(output).hexdigest(),
        output=output.decode(),
        truncated=False,
        duration_ms=1,
    )


def _runtime_policy(tmp_path: Path) -> MobileRuntimePolicy:
    executable = tmp_path / "tool"
    executable.write_text("placeholder", encoding="utf-8")
    executable.chmod(0o700)
    adapter = tmp_path / "adapter.py"
    adapter.write_text("print('{}')\n", encoding="utf-8")
    adapter.chmod(0o600)
    return MobileRuntimePolicy(
        enabled=True,
        runtime_id="emulator-lab-01",
        adb_executable=executable.resolve(),
        python_executable=executable.resolve(),
        frida_executable=executable.resolve(),
        frida_inventory_adapter=adapter.resolve(),
        adb_serial="emulator-5554",
        frida_device_id="emulator-5554",
        expected_fingerprint="vulnhunter/test/emulator:15/AP4A/test-keys",
        expected_api_level=35,
        expected_abi="x86_64",
        expected_frida_version="17.9.11",
        expires_at=NOW + timedelta(hours=4),
    )


def test_malformed_extension_job_is_rejected_with_safe_identity(tmp_path):
    spool = MobileExtensionSpool(tmp_path / "spool")
    claimed = spool.processing / "malformed.json"
    claimed.write_text(
        json.dumps(
            {
                "job_id": "../escape",
                "kind": "invalid",
                "artifact_id": "",
            }
        ),
        encoding="utf-8",
    )
    claimed.chmod(0o600)

    rejected = spool.reject(
        claimed,
        reason="Malformed job failed closed.",
        now=NOW,
    )

    assert not claimed.exists()
    assert rejected.parent == spool.failed
    assert rejected.name.startswith("rejected-")
    receipt = MobileExtensionReceipt.model_validate_json(rejected.read_text(encoding="utf-8"))
    assert receipt.state == "rejected"
    assert receipt.kind == "mobsf"
    assert receipt.artifact_id == "unknown-artifact"


def test_mobsf_extension_worker_stores_private_result_and_bounded_receipt(
    tmp_path,
    monkeypatch,
):
    artifact_path = tmp_path / "sample.apk"
    artifact_path.write_bytes(b"apk-envelope")
    artifact_sha256 = hashlib.sha256(artifact_path.read_bytes()).hexdigest()
    artifact = SimpleNamespace(
        artifact_id="artifact-test",
        sha256=artifact_sha256,
        stored_path=artifact_path,
    )
    ingestor = SimpleNamespace(list_records=lambda: [artifact])
    signing_key = b"s" * 48
    spool = MobileExtensionSpool(tmp_path / "spool")
    job = SignedMobileExtensionJob.create(
        job_id="mobile-mobsf-test",
        kind="mobsf",
        artifact_id=artifact.artifact_id,
        artifact_sha256=artifact_sha256,
        plan_sha256="a" * 64,
        requested_by="security-reviewer",
        approval_reason="Approve the exact private MobSF run.",
        package_name=None,
        runtime_approval=None,
        created_at=NOW,
        expires_at=NOW + timedelta(hours=1),
        key=signing_key,
    )
    spool.enqueue(job)

    class _Result:
        scan_hash = "scan-hash-test"
        report_sha256 = "b" * 64
        report_bytes = 42
        report_keys = ("manifest", "permissions")
        package_name = "com.example.safe"
        app_name = "Safe App"
        security_score = 71

        @staticmethod
        def model_dump(*, mode: str) -> dict[str, object]:
            assert mode == "json"
            return {
                "scan_hash": "scan-hash-test",
                "artifact_sha256": artifact_sha256,
                "report": {"permissions": []},
            }

    class _Client:
        def __init__(self, config) -> None:
            self.config = config

        def analyse(self, apk_path: Path, *, artifact_sha256: str):
            assert apk_path == artifact_path
            assert artifact_sha256 == artifact.sha256
            return _Result()

    monkeypatch.setattr(
        extension_service.MobSFServiceConfig,
        "from_path",
        classmethod(lambda cls, path: object()),
    )
    monkeypatch.setattr(extension_service, "MobSFClient", _Client)
    service = MobileExtensionQueueService(
        spool=spool,
        signing_key=signing_key,
        runtime_approval_key=b"r" * 48,
        ingestor=ingestor,
        result_root=tmp_path / "results",
        mobsf_policy_path=tmp_path / "mobsf.json",
        runtime_policy_path=tmp_path / "runtime.json",
    )

    receipt = service.run_once()

    assert receipt is not None
    assert receipt.state == "completed"
    assert receipt.evidence["report_sha256"] == "b" * 64
    assert "report" not in receipt.evidence
    assert spool.status(job.job_id)["state"] == "completed"
    result_path = tmp_path / "results" / job.job_id / "mobsf-result.json"
    assert result_path.is_file()
    assert result_path.stat().st_mode & 0o077 == 0


def test_runtime_cleanup_failure_marks_session_failed(tmp_path, monkeypatch):
    apk_path = tmp_path / "sample.apk"
    apk_path.write_bytes(b"approved-apk")
    artifact_sha256 = hashlib.sha256(apk_path.read_bytes()).hexdigest()
    policy = _runtime_policy(tmp_path)
    approval_key = b"r" * 48
    approval = SignedMobileRuntimeApproval.create(
        approval_id="approval-runtime-test",
        plan_sha256="a" * 64,
        artifact_sha256=artifact_sha256,
        package_name="com.example.safe",
        runtime_id=policy.runtime_id,
        adb_serial=policy.adb_serial,
        frida_device_id=policy.frida_device_id,
        approved_by="security-reviewer",
        approved_at=NOW,
        expires_at=NOW + timedelta(minutes=30),
        key=approval_key,
    )
    executor = MobileRuntimeExecutor(policy)

    def fake_adb(action: str, arguments: tuple[str, ...]) -> MobileRuntimeCapture:
        del arguments
        return _capture(f"adb-{action}", 1 if action == "uninstall" else 0)

    monkeypatch.setattr(
        executor,
        "_verify_device_identity",
        lambda: {
            "adb_serial": policy.adb_serial,
            "fingerprint": policy.expected_fingerprint,
            "api_level": policy.expected_api_level,
            "abi": policy.expected_abi,
            "emulator": True,
        },
    )
    monkeypatch.setattr(executor, "_frida_version", lambda: policy.expected_frida_version)
    monkeypatch.setattr(executor, "_run_adb", fake_adb)
    monkeypatch.setattr(
        executor,
        "_run_frida_inventory",
        lambda package_name: _capture("frida-inventory"),
    )
    monkeypatch.setattr("vulnhunter.mobile.runtime.time.sleep", lambda seconds: None)

    result = executor.execute(
        apk_path=apk_path,
        artifact_sha256=artifact_sha256,
        package_name="com.example.safe",
        plan_sha256="a" * 64,
        approval=approval,
        approval_key=approval_key,
        now=NOW + timedelta(minutes=1),
    )

    assert result.state == "failed"
    assert any(item.action == "adb-uninstall" and item.return_code == 1 for item in result.captures)


def test_mobsf_approval_helper_rechecks_readiness_and_enqueues(tmp_path, monkeypatch):
    signing_key = _private_key(tmp_path / "extension.key")
    spool_root = tmp_path / "spool"
    monkeypatch.setenv(
        "VULNHUNTER_MOBILE_EXTENSION_SIGNING_KEY_FILE",
        str(signing_key),
    )
    monkeypatch.setenv("VULNHUNTER_MOBILE_EXTENSION_SPOOL_ROOT", str(spool_root))
    monkeypatch.setattr(
        mobile_extension_execution,
        "mobile_infrastructure_status",
        lambda now: {
            "mobsf": {"state": "approval_required"},
            "adb": {"state": "gated"},
            "frida": {"state": "gated"},
        },
    )
    request = SimpleNamespace(session=_Session())
    plan = {
        "plan_digest": "a" * 64,
        "artifact": {
            "artifact_id": "artifact-test",
            "artifact_sha256": "b" * 64,
        },
        "deferred_tools": [{"tool_id": "mobsf", "state": "approval_required"}],
        "extension_jobs": [],
    }

    execution = mobile_extension_execution.enqueue_mobile_extension(
        request,
        plan=plan,
        kind="mobsf",
        package_name=None,
        reason="Approve the exact private MobSF analysis.",
        requested_by="security-reviewer",
    )

    assert execution["state"] == "queued"
    assert MobileExtensionSpool(spool_root).status(execution["job_id"])["state"] == "queued"
    assert request.session.modified is True
