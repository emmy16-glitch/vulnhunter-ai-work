"""Run one genuine bounded static/native APK acceptance flow.

The harness deliberately invokes the same MobileArtifactIngestor, signed spool,
MobileStaticQueueService, and MobileStaticWorker used by the application. It
never executes the APK and never unlocks dynamic analysis.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import secrets
import subprocess
from pathlib import Path
from typing import Any

from vulnhunter.mobile.artifacts import MobileArtifactIngestor
from vulnhunter.mobile.static_progress import MobileStaticProgressStore
from vulnhunter.mobile.static_service import MobileStaticQueueService, create_mobile_static_job
from vulnhunter.mobile.static_spool import MobileStaticJobReceipt, MobileStaticSpool
from vulnhunter.mobile.static_toolchain import MobileStaticWorkerPolicy
from vulnhunter.security_tools.worker_spool import load_worker_signing_key

REPOSITORY = Path(__file__).resolve().parents[1]
CAPABILITY_PATHS = {
    "aapt2": "aapt2_executable",
    "apksigner": "apksigner_executable",
    "apkid": "apkid_executable",
    "apktool": "apktool_executable",
    "jadx": "jadx_executable",
    "androguard": "androguard_adapter",
    "yara": "yara_adapter",
    "radare2": "radare2_executable",
    "ghidra": "ghidra_headless_executable",
}
CAPABILITY_TESTS = {
    "aapt2": "tests/unit/test_mobile_tool_governance.py",
    "apksigner": "tests/unit/test_mobile_tool_governance.py",
    "apkid": "tests/unit/test_mobile_tool_governance.py",
    "apktool": "tests/unit/test_mobile_tool_governance.py",
    "jadx": "tests/unit/test_mobile_tool_governance.py",
    "androguard": "tests/unit/test_mobile_tool_governance.py",
    "yara": "tests/unit/test_mobile_tool_governance.py",
    "radare2": "tests/unit/test_mobile_tool_governance.py",
    "ghidra": "tests/unit/test_mobile_tool_governance.py",
}


def _sha256_json(payload: Any) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _validated_policy(path: Path) -> MobileStaticWorkerPolicy:
    policy = MobileStaticWorkerPolicy.from_path(path.expanduser().resolve(strict=True))
    if not policy.enabled:
        raise RuntimeError("mobile static worker policy is disabled")
    return policy


def _tool_classification(
    *,
    tool: str,
    policy: MobileStaticWorkerPolicy,
    captures: list[dict[str, Any]],
    workspace: Path,
) -> dict[str, Any]:
    configured_path = getattr(policy, CAPABILITY_PATHS[tool])
    tool_captures = [item for item in captures if item.get("tool") == tool]
    if configured_path is None:
        evidence = "NOT AVAILABLE"
    elif not tool_captures:
        evidence = "NOT RUN"
    elif all(item.get("return_code") == 0 for item in tool_captures):
        evidence = "PASS"
    elif any(item.get("return_code") == 0 for item in tool_captures):
        evidence = "PARTIAL"
    elif tool == "jadx" and any(workspace.joinpath("jadx-output").rglob("*")):
        evidence = "PARTIAL"
    else:
        evidence = "FAIL"
    generated_files = (
        sum(
            item.is_file() and not item.is_symlink()
            for item in workspace.joinpath("jadx-output").rglob("*")
        )
        if tool == "jadx" and workspace.joinpath("jadx-output").is_dir()
        else 0
    )
    return {
        "capability": tool,
        "code_present": (REPOSITORY / "vulnhunter/mobile").is_dir(),
        "unit_tested": (REPOSITORY / CAPABILITY_TESTS[tool]).is_file(),
        "real_executable": (str(configured_path) if configured_path is not None else None),
        "real_apk": evidence,
        "capture_count": len(tool_captures),
        "return_codes": [item.get("return_code") for item in tool_captures],
        "generated_files": generated_files,
    }


def _dynamic_classification() -> dict[str, Any]:
    return {
        "capability": "dynamic execution (ADB/Frida/MobSF/emulator)",
        "code_present": True,
        "unit_tested": True,
        "real_executable": None,
        "real_apk": "BLOCKED",
        "reason": (
            "Dynamic analysis remains fail-closed until a disposable isolated runtime, device "
            "identity, private MobSF policy, and exact digest-bound approval are present."
        ),
    }


def _run_pytest_probe() -> dict[str, Any]:
    command = ["pytest", "-q", "tests/unit/test_mobile_worker_runtime_repairs.py"]
    completed = subprocess.run(command, cwd=REPOSITORY, capture_output=True, text=True, check=False)
    return {
        "command": command,
        "return_code": completed.returncode,
        "output": (completed.stdout + completed.stderr).strip()[-2000:],
        "status": "PASS" if completed.returncode == 0 else "FAIL",
    }


def run_acceptance(
    *,
    apk: Path,
    runtime_root: Path,
    policy_path: Path,
    requested_by: str,
    run_id: str | None = None,
    skip_test_probe: bool = False,
) -> dict[str, Any]:
    source = apk.expanduser().resolve(strict=True)
    runtime = runtime_root.expanduser().resolve()
    if runtime == REPOSITORY or REPOSITORY in runtime.parents:
        raise RuntimeError("acceptance runtime must be outside the repository")
    runtime.mkdir(parents=True, mode=0o700, exist_ok=True)
    policy = _validated_policy(policy_path)
    if policy.workspace_root == REPOSITORY or REPOSITORY in policy.workspace_root.parents:
        raise RuntimeError("worker workspace must be outside the repository")

    artifact_root = runtime / "artifacts"
    spool_root = runtime / "spool"
    ingestor = MobileArtifactIngestor(artifact_root)
    record = ingestor.ingest_file(source, original_filename=source.name)
    signing_key_path = runtime / "worker.key"
    signing_key_path.write_bytes(secrets.token_bytes(48))
    signing_key_path.chmod(0o600)
    signing_key = load_worker_signing_key(signing_key_path)
    job_id = run_id or f"acceptance-{record.sha256[:20]}"
    job = create_mobile_static_job(
        run_id=job_id,
        artifact_id=record.artifact_id,
        artifact_sha256=record.sha256,
        hunt_plan_sha256=_sha256_json({"profile": "static-native", "tools": policy.active_tools()}),
        requested_by=requested_by,
        signing_key=signing_key,
    )
    spool = MobileStaticSpool(spool_root)
    spool.enqueue(job)
    service = MobileStaticQueueService(
        spool=spool,
        signing_key=signing_key,
        policy=policy,
        ingestor=ingestor,
    )
    receipt = service.run_once()
    if receipt is None:
        raise RuntimeError("real mobile worker did not claim the acceptance job")
    receipt_root = spool.completed if receipt.state == "completed" else spool.failed
    receipt_path = receipt_root / f"{job_id}.receipt.json"
    persisted = MobileStaticJobReceipt.model_validate_json(receipt_path.read_text(encoding="utf-8"))
    if persisted.model_dump(mode="json") != receipt.model_dump(mode="json"):
        raise RuntimeError("persisted mobile receipt did not match the returned receipt")
    progress = MobileStaticProgressStore(spool_root).read(job_id=job_id, key=signing_key)
    if progress is None:
        raise RuntimeError("signed terminal mobile progress snapshot was not persisted")
    progress.verify(signing_key)
    if progress.state != receipt.state:
        raise RuntimeError("mobile progress terminal state did not match the receipt")

    captures = [item.model_dump(mode="json") for item in receipt.captures]
    analysis_workspace = policy.workspace_root / record.artifact_id / job_id
    classifications = [
        _tool_classification(
            tool=tool,
            policy=policy,
            captures=captures,
            workspace=analysis_workspace,
        )
        for tool in CAPABILITY_PATHS
    ]
    classifications.append(_dynamic_classification())
    result = {
        "acceptance": "real_apk_static_native",
        "job_id": job_id,
        "artifact_id": record.artifact_id,
        "artifact_sha256": record.sha256,
        "artifact_size_bytes": record.size_bytes,
        "dex_count": len(record.dex_entries),
        "native_library_count": len(record.native_libraries),
        "worker_state": receipt.state,
        "receipt_reason": receipt.reason,
        "capture_count": len(receipt.captures),
        "candidate_observation_count": len(receipt.candidate_observations),
        "progress_state": progress.state,
        "progress_event_count": len(progress.events),
        "tool_states": progress.tool_states,
        "capabilities": classifications,
        "dynamic_execution": _dynamic_classification(),
        "evidence": {
            "receipt_path": str(receipt_path),
            "progress_path": str(
                spool.completed / f"{job_id}.progress.json"
                if receipt.state == "completed"
                else spool.failed / f"{job_id}.progress.json"
            ),
            "candidate_observation_ids": [
                str(item.get("observation_id")) for item in receipt.candidate_observations
            ],
        },
    }
    if not skip_test_probe:
        result["unit_test_probe"] = _run_pytest_probe()
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("apk", type=Path)
    parser.add_argument("--runtime-root", type=Path, required=True)
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--requested-by", default="mobile-apk-acceptance")
    parser.add_argument("--run-id")
    parser.add_argument("--skip-test-probe", action="store_true")
    arguments = parser.parse_args()
    print(
        json.dumps(
            run_acceptance(
                apk=arguments.apk,
                runtime_root=arguments.runtime_root,
                policy_path=arguments.policy,
                requested_by=arguments.requested_by,
                run_id=arguments.run_id,
                skip_test_probe=arguments.skip_test_probe,
            ),
            indent=2,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
