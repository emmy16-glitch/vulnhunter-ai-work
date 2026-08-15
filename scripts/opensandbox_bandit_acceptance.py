"""Genuine local OpenSandbox acceptance for the first VulnHunter scanner worker."""

from __future__ import annotations

import argparse
import json
import tempfile
from pathlib import Path

from vulnhunter.security_tools import default_catalog, normalize_execution_findings
from vulnhunter.security_tools.executor import SecurityToolExecutor
from vulnhunter.security_tools.models import SecurityToolRequest, ToolProfile, ToolTargetKind
from vulnhunter.security_tools.opensandbox_activation import OpenSandboxActivationConfig

_FIXTURE = """\
import subprocess

subprocess.run("echo opensandbox-acceptance", shell=True, check=False)
"""


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run VulnHunter -> OpenSandbox -> Bandit -> evidence acceptance."
    )
    parser.add_argument("--image", required=True, help="Digest-pinned Bandit worker image")
    parser.add_argument("--domain", default="localhost:8080", help="OpenSandbox host:port")
    parser.add_argument(
        "--protocol",
        choices=("http", "https"),
        default="http",
        help="OpenSandbox control-plane protocol",
    )
    return parser


def run_acceptance(*, image: str, domain: str, protocol: str) -> dict[str, object]:
    config = OpenSandboxActivationConfig(
        enabled=True,
        domain=domain,
        protocol=protocol,
        bandit_image=image,
        maximum_input_bytes=1_000_000,
    )
    backend = config.build_backend()
    if backend is None:
        raise RuntimeError("OpenSandbox acceptance backend unexpectedly remained disabled")

    with tempfile.TemporaryDirectory(prefix="vulnhunter-opensandbox-") as directory:
        root = Path(directory)
        input_root = root / "inputs"
        evidence_root = root / "evidence"
        input_root.mkdir()
        evidence_root.mkdir()
        target = input_root / "shell_fixture.py"
        target.write_text(_FIXTURE, encoding="utf-8")

        executor = SecurityToolExecutor(
            catalog=default_catalog(),
            execution_enabled=True,
            approved_output_root=evidence_root,
            approved_input_roots=(input_root,),
            execution_backend=backend,
            # This authorizer is intentionally acceptance-only. Production callers
            # must use the real VulnHunter authorization/policy gate.
            execution_authorizer=lambda _plan, _execution_id: True,
        )
        request = SecurityToolRequest(
            request_id="opensandbox-bandit-acceptance",
            action_manifest_sha256="0" * 64,
            tool_id="bandit",
            profile=ToolProfile.SAFE_ASSESSMENT,
            operation="scan",
            target=str(target),
            target_kind=ToolTargetKind.LOCAL_PATH,
            timeout_seconds=30,
            maximum_output_bytes=250_000,
            output_directory=evidence_root,
        )

        plan = executor.plan(request)
        result = executor.execute(
            plan,
            approval_consumed=False,
            execution_id="opensandbox-bandit-acceptance-run",
        )
        if not result.success:
            raise RuntimeError(
                f"Bandit acceptance execution failed with return code {result.return_code}"
            )
        if len(result.output_files) != 1:
            raise RuntimeError("Bandit acceptance did not produce exactly one evidence artifact")

        evidence_path = Path(result.output_files[0])
        payload = json.loads(evidence_path.read_text(encoding="utf-8"))
        records = payload.get("results") if isinstance(payload, dict) else None
        if not isinstance(records, list) or not records:
            raise RuntimeError("Bandit acceptance produced no structured findings")

        findings = normalize_execution_findings(
            result,
            target_reference="opensandbox-bandit-acceptance",
        )
        if not findings:
            raise RuntimeError("VulnHunter normalization produced no Bandit findings")
        if any(finding.tool_id != "bandit" for finding in findings):
            raise RuntimeError("Bandit acceptance normalized an unexpected tool identity")
        if not any(finding.evidence.get("test_id") for finding in findings):
            raise RuntimeError(
                "Bandit acceptance findings are missing their deterministic test IDs"
            )

        return {
            "status": "accepted",
            "tool_id": result.tool_id,
            "worker_image": image,
            "command_plan_sha256": result.command_plan_sha256,
            "evidence_sha256": result.evidence_sha256,
            "finding_count": len(findings),
            "timed_out": result.timed_out,
        }


def main() -> None:
    args = _parser().parse_args()
    receipt = run_acceptance(
        image=args.image,
        domain=args.domain,
        protocol=args.protocol,
    )
    print(json.dumps(receipt, sort_keys=True))


if __name__ == "__main__":
    main()
