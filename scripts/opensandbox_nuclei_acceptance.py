"""Genuine local OpenSandbox acceptance for VulnHunter's exact-target Nuclei worker."""

from __future__ import annotations

import argparse
import json
import tempfile
from pathlib import Path
from urllib.parse import urlsplit

from vulnhunter.security_tools import default_catalog, normalize_execution_findings
from vulnhunter.security_tools.executor import SecurityToolExecutor
from vulnhunter.security_tools.models import SecurityToolRequest, ToolProfile, ToolTargetKind
from vulnhunter.security_tools.opensandbox_activation import OpenSandboxActivationConfig


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run VulnHunter -> OpenSandbox -> exact-target Nuclei -> evidence acceptance."
    )
    parser.add_argument("--image", required=True, help="Digest-pinned Nuclei worker image")
    parser.add_argument("--target-url", required=True, help="Authorized HTTP target URL")
    parser.add_argument("--release-registry", type=Path, required=True)
    parser.add_argument("--release-signature", type=Path, required=True)
    parser.add_argument("--release-public-key", type=Path, required=True)
    parser.add_argument("--domain", default="localhost:8080", help="OpenSandbox host:port")
    parser.add_argument(
        "--protocol",
        choices=("http", "https"),
        default="http",
        help="OpenSandbox control-plane protocol",
    )
    return parser


def run_acceptance(
    *,
    image: str,
    target_url: str,
    release_registry: Path,
    release_signature: Path,
    release_public_key: Path,
    domain: str,
    protocol: str,
) -> dict[str, object]:
    parsed = urlsplit(target_url)
    if parsed.scheme not in {"http", "https"} or parsed.hostname is None:
        raise RuntimeError("acceptance target must be one HTTP or HTTPS URL")

    config = OpenSandboxActivationConfig(
        enabled=True,
        domain=domain,
        protocol=protocol,
        nuclei_image=image,
        maximum_input_bytes=1_000_000,
        release_registry_file=release_registry,
        release_signature_file=release_signature,
        release_public_key_file=release_public_key,
    )
    backend = config.build_backend()
    if backend is None:
        raise RuntimeError("OpenSandbox Nuclei acceptance backend unexpectedly remained disabled")

    with tempfile.TemporaryDirectory(prefix="vulnhunter-opensandbox-nuclei-") as directory:
        evidence_root = Path(directory) / "evidence"
        evidence_root.mkdir()

        def authorizer(plan, _execution_id: str) -> bool:
            binding = plan.network_binding
            return bool(
                plan.tool_id == "nuclei"
                and plan.runtime_image == image
                and plan.runtime_release_id is not None
                and binding is not None
                and binding.hostname == parsed.hostname.casefold()
                and binding.port == (parsed.port or (443 if parsed.scheme == "https" else 80))
            )

        executor = SecurityToolExecutor(
            catalog=default_catalog(),
            execution_enabled=True,
            approved_output_root=evidence_root,
            execution_backend=backend,
            execution_authorizer=authorizer,
        )
        request = SecurityToolRequest(
            request_id="opensandbox-nuclei-acceptance",
            action_manifest_sha256="0" * 64,
            tool_id="nuclei",
            profile=ToolProfile.SAFE_ASSESSMENT,
            operation="scan",
            target=target_url,
            target_kind=ToolTargetKind.NETWORK,
            timeout_seconds=45,
            maximum_output_bytes=500_000,
            output_directory=evidence_root,
            parameters={
                "scan_profile": "passive",
                "rate_limit": 1,
                "bulk_size": 1,
                "concurrency": 1,
                "probe_concurrency": 1,
                "request_timeout": 5,
                "retries": 0,
            },
        )

        plan = executor.plan(request)
        if plan.network_binding is None:
            raise RuntimeError("Nuclei acceptance plan did not bind a network destination")
        if plan.runtime_image != image:
            raise RuntimeError("Nuclei acceptance plan did not bind its worker digest")
        if plan.template_manifest_sha256 is None:
            raise RuntimeError("Nuclei acceptance plan did not bind reviewed template identity")
        if plan.runtime_release_id is None or plan.runtime_sbom_sha256 is None:
            raise RuntimeError("Nuclei acceptance plan did not bind signed release identity")
        if plan.runtime_provenance_sha256 is None or plan.runtime_release_key_id is None:
            raise RuntimeError("Nuclei acceptance plan did not bind supply-chain evidence")
        if "-disable-redirects" not in plan.argv or "-no-httpx" not in plan.argv:
            raise RuntimeError(
                "Nuclei acceptance plan did not retain exact-target scanner controls"
            )

        result = executor.execute(
            plan,
            approval_consumed=True,
            execution_id="opensandbox-nuclei-acceptance-run",
        )
        if not result.success:
            raise RuntimeError(
                f"Nuclei acceptance execution failed with return code {result.return_code}: "
                f"{result.stderr_preview[:1000]}"
            )
        if len(result.output_files) != 1:
            raise RuntimeError("Nuclei acceptance did not produce exactly one evidence artifact")

        evidence_path = Path(result.output_files[0])
        if not evidence_path.read_text(encoding="utf-8").strip():
            raise RuntimeError("Nuclei acceptance produced an empty JSONL evidence artifact")
        findings = normalize_execution_findings(
            result,
            target_reference=target_url,
        )
        if not findings:
            raise RuntimeError("VulnHunter normalization produced no Nuclei candidate finding")
        if any(finding.tool_id != "nuclei" for finding in findings):
            raise RuntimeError("Nuclei acceptance normalized an unexpected tool identity")

        return {
            "status": "accepted",
            "tool_id": result.tool_id,
            "worker_image": image,
            "release_id": plan.runtime_release_id,
            "sbom_sha256": plan.runtime_sbom_sha256,
            "provenance_sha256": plan.runtime_provenance_sha256,
            "release_registry_sha256": plan.runtime_release_registry_sha256,
            "release_key_id": plan.runtime_release_key_id,
            "template_manifest_sha256": plan.template_manifest_sha256,
            "bound_ip": plan.network_binding.ip_address,
            "bound_port": plan.network_binding.port,
            "command_plan_sha256": result.command_plan_sha256,
            "evidence_sha256": result.evidence_sha256,
            "finding_count": len(findings),
            "timed_out": result.timed_out,
        }


def main() -> None:
    args = _parser().parse_args()
    receipt = run_acceptance(
        image=args.image,
        target_url=args.target_url,
        release_registry=args.release_registry,
        release_signature=args.release_signature,
        release_public_key=args.release_public_key,
        domain=args.domain,
        protocol=args.protocol,
    )
    print(json.dumps(receipt, sort_keys=True))


if __name__ == "__main__":
    main()