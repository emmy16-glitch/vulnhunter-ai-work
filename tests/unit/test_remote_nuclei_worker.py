from __future__ import annotations

import hashlib
import json
import os
import stat
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path

import pytest
from pydantic import ValidationError

from vulnhunter.actions.models import sha256_json
from vulnhunter.security_tools.remote_nuclei_worker import (
    RemoteNucleiRequest,
    RemoteNucleiResult,
    RemoteNucleiWorkerError,
    RemoteNucleiWorkerPolicy,
    RestrictedSshNucleiRunner,
)


def _write(path: Path, content: str, mode: int) -> Path:
    path.write_text(content, encoding="utf-8")
    path.chmod(mode)
    return path


def _enabled_policy(tmp_path: Path) -> RemoteNucleiWorkerPolicy:
    ssh = _write(tmp_path / "ssh", "#!/bin/sh\nexit 0\n", 0o700)
    identity = _write(tmp_path / "identity", "private-test-key\n", 0o600)
    known_hosts = _write(tmp_path / "known_hosts", "10.0.2.2 ssh-ed25519 test\n", 0o600)
    return RemoteNucleiWorkerPolicy(
        enabled=True,
        worker_id="remote-worker-01",
        ssh_executable=ssh,
        remote_user="okunlola",
        remote_host="10.0.2.2",
        identity_file=identity,
        known_hosts_file=known_hosts,
        logical_target="http://10.0.2.15:8002",
        transport_target="http://127.0.0.1:18002",
        engine_version="v3.11.0",
        template_manifest_hash="1" * 64,
        template_sha256="2" * 64,
    )


def _request(operation: str, template_sha256: str) -> dict[str, object]:
    payload: dict[str, object] = {
        "schema_version": "1.0",
        "operation": operation,
        "request_id": "readiness-check" if operation == "readiness" else "execution-test-01",
        "worker_id": "remote-worker-01",
        "logical_target": "http://10.0.2.15:8002",
        "transport_target": "http://127.0.0.1:18002",
        "engine_version": "v3.11.0",
        "template_sha256": template_sha256,
        "timeout_seconds": 10,
        "maximum_candidates": 0 if operation == "readiness" else 5,
        "issued_at": datetime.now(UTC).isoformat(),
    }
    payload["request_digest"] = sha256_json(payload)
    return payload


def _assert_result_digest(result: dict[str, object]) -> None:
    supplied = result["result_digest"]
    unsigned = {key: value for key, value in result.items() if key != "result_digest"}
    assert supplied == sha256_json(unsigned)
    assert supplied != "0" * 64


def test_disabled_policy_loads_without_runtime_identity() -> None:
    policy = RemoteNucleiWorkerPolicy.model_validate(
        {
            "worker_id": "remote-worker-01",
            "identity_file": "/tmp/not-created-identity",
            "known_hosts_file": "/tmp/not-created-known-hosts",
        }
    )
    assert policy.enabled is False


def test_enabled_policy_requires_fixed_private_and_loopback_targets(tmp_path: Path) -> None:
    policy = _enabled_policy(tmp_path)
    assert policy.enabled is True
    with pytest.raises(ValidationError):
        RemoteNucleiWorkerPolicy.model_validate(
            policy.model_dump(mode="python")
            | {"transport_target": "http://10.0.2.2:18002"}
        )


def test_policy_file_rejects_writable_or_symlinked_configuration(tmp_path: Path) -> None:
    policy = _enabled_policy(tmp_path)
    policy_path = tmp_path / "policy.json"
    policy_path.write_text(policy.model_dump_json(indent=2), encoding="utf-8")
    policy_path.chmod(0o622)
    with pytest.raises(RemoteNucleiWorkerError):
        RemoteNucleiWorkerPolicy.from_path(policy_path)
    policy_path.chmod(0o600)
    link = tmp_path / "policy-link.json"
    link.symlink_to(policy_path)
    with pytest.raises(RemoteNucleiWorkerError):
        RemoteNucleiWorkerPolicy.from_path(link)


def test_ssh_command_is_fixed_and_disables_forwarding(tmp_path: Path) -> None:
    runner = RestrictedSshNucleiRunner(policy=_enabled_policy(tmp_path))
    command = runner._ssh_command()
    assert command[-1] == "okunlola@10.0.2.2"
    assert "ClearAllForwardings=yes" in command
    assert "StrictHostKeyChecking=yes" in command
    assert "BatchMode=yes" in command
    assert not any(value in command for value in ("sh", "bash", "-L", "-R", "-D"))


def test_request_and_result_digests_detect_tampering() -> None:
    request = RemoteNucleiRequest.create(
        operation="readiness",
        request_id="readiness-check",
        worker_id="remote-worker-01",
        logical_target="http://10.0.2.15:8002",
        transport_target="http://127.0.0.1:18002",
        engine_version="v3.11.0",
        template_sha256="2" * 64,
        timeout_seconds=10,
        maximum_candidates=0,
        issued_at=datetime.now(UTC),
    )
    assert request.request_digest != "0" * 64
    with pytest.raises(ValidationError):
        RemoteNucleiRequest.model_validate(
            request.model_dump(mode="python") | {"engine_version": "v9.9.9"}
        )

    values: dict[str, object] = {
        "operation": "readiness",
        "worker_id": "remote-worker-01",
        "request_digest": request.request_digest,
        "execution_state": "ready",
        "reason": "Restricted worker is ready.",
        "engine_version": "v3.11.0",
        "template_sha256": "2" * 64,
        "candidate_count": 0,
        "candidates": (),
        "http_status": None,
        "completed_at": datetime.now(UTC),
    }
    result = RemoteNucleiResult(
        **values,
        result_digest=sha256_json(
            RemoteNucleiResult.model_construct(
                **values,
                result_digest="0" * 64,
            ).unsigned_payload()
        ),
    )
    assert result.result_digest != "0" * 64
    with pytest.raises(ValidationError):
        RemoteNucleiResult.model_validate(
            result.model_dump(mode="python") | {"reason": "tampered result"}
        )


def test_host_forced_command_returns_genuine_bounded_results_and_blocks_replay(
    tmp_path: Path,
) -> None:
    repository_root = Path(__file__).resolve().parents[2]
    worker_script = repository_root / "scripts" / "remote_nuclei_forced_command.py"
    fake_nuclei = _write(
        tmp_path / "nuclei",
        (
            "#!/bin/sh\n"
            'if [ "$1" = "-version" ]; then\n'
            '  echo "Nuclei Engine Version: v3.11.0"\n'
            "  exit 0\n"
            "fi\n"
            "printf '%s\\n' "
            "'{\"template-id\":\"missing-security-header\","
            "\"info\":{\"name\":\"Missing security header\","
            "\"severity\":\"info\"},"
            "\"matcher-name\":\"header-check\","
            "\"type\":\"http\"}'\n"
        ),
        0o700,
    )
    template = _write(tmp_path / "passive.yaml", "id: missing-security-header\n", 0o600)
    template_sha256 = hashlib.sha256(template.read_bytes()).hexdigest()
    replay_root = tmp_path / "replay"
    replay_root.mkdir(mode=0o700)
    policy = {
        "schema_version": "1.0",
        "enabled": True,
        "worker_id": "remote-worker-01",
        "nuclei_executable": str(fake_nuclei),
        "template_path": str(template),
        "logical_target": "http://10.0.2.15:8002",
        "transport_target": "http://127.0.0.1:18002",
        "engine_version": "v3.11.0",
        "template_sha256": template_sha256,
        "replay_root": str(replay_root),
        "maximum_timeout_seconds": 30,
        "maximum_candidates": 10,
        "maximum_stdout_bytes": 200_000,
        "maximum_stderr_bytes": 100_000,
        "maximum_response_bytes": 131_072,
    }
    policy_path = tmp_path / "host-policy.json"
    policy_path.write_text(json.dumps(policy), encoding="utf-8")
    policy_path.chmod(0o600)

    readiness = _request("readiness", template_sha256)
    readiness_process = subprocess.run(
        [sys.executable, str(worker_script), "--policy", str(policy_path)],
        input=json.dumps(readiness).encode(),
        capture_output=True,
        check=False,
        timeout=20,
    )
    assert readiness_process.returncode == 0, readiness_process.stderr.decode()
    readiness_result = json.loads(readiness_process.stdout)
    assert readiness_result["execution_state"] == "ready"
    _assert_result_digest(readiness_result)

    scan = _request("scan", template_sha256)
    scan_process = subprocess.run(
        [sys.executable, str(worker_script), "--policy", str(policy_path)],
        input=json.dumps(scan).encode(),
        capture_output=True,
        check=False,
        timeout=20,
    )
    assert scan_process.returncode == 0, scan_process.stderr.decode()
    scan_result = json.loads(scan_process.stdout)
    assert scan_result["execution_state"] == "completed"
    assert scan_result["candidate_count"] == 1
    assert scan_result["candidates"][0]["template_id"] == "missing-security-header"
    assert "matched-at" not in scan_process.stdout.decode()
    _assert_result_digest(scan_result)

    replay_process = subprocess.run(
        [sys.executable, str(worker_script), "--policy", str(policy_path)],
        input=json.dumps(scan).encode(),
        capture_output=True,
        check=False,
        timeout=20,
    )
    assert replay_process.returncode != 0
    assert "replay" in replay_process.stderr.decode().lower()


def test_host_policy_permissions_are_owner_controlled(tmp_path: Path) -> None:
    path = _write(tmp_path / "policy.json", "{}", 0o600)
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert not os.path.islink(path)


def test_settings_status_reports_remote_policy_without_opening_ssh(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from vulnhunter.web.templatetags.vh_remote_nuclei import remote_nuclei_status

    monkeypatch.delenv("VULNHUNTER_REMOTE_NUCLEI_WORKER_POLICY", raising=False)
    assert remote_nuclei_status()["state"] == "not configured"

    policy_path = tmp_path / "remote-policy.json"
    policy_path.write_text(
        json.dumps({"schema_version": "1.0", "enabled": True, "worker_id": "worker-01"}),
        encoding="utf-8",
    )
    policy_path.chmod(0o600)
    monkeypatch.setenv("VULNHUNTER_REMOTE_NUCLEI_WORKER_POLICY", str(policy_path))
    status = remote_nuclei_status()
    assert status["enabled"] is True
    assert status["worker_id"] == "worker-01"
