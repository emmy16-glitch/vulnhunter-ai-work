#!/usr/bin/env python3
"""Run one genuine pinned-Nuclei private-lab acceptance flow."""

from __future__ import annotations

import argparse
import json
import os
import secrets
import shutil
from datetime import UTC, datetime, timedelta
from pathlib import Path


def _validated_readiness(path: Path) -> dict[str, object]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError("the verified readiness report is unavailable") from exc
    if not isinstance(payload, dict):
        raise RuntimeError("the verified readiness report is invalid")
    required = {
        "ready": True,
        "installed": True,
        "expected_engine": "v3.8.0",
        "expected_templates": "v10.4.5",
        "engine_pin_matches": True,
        "templates_pin_matches": True,
        "execution_enabled": True,
        "scan_performed": False,
        "update_performed": False,
    }
    mismatches = [key for key, expected in required.items() if payload.get(key) != expected]
    if mismatches:
        raise RuntimeError(
            "the readiness report did not verify all private-lab gates: " + ", ".join(mismatches)
        )
    return payload


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runtime-root", type=Path, required=True)
    parser.add_argument("--executable", type=Path, required=True)
    parser.add_argument("--readiness-report", type=Path, required=True)
    parser.add_argument("--target-url", required=True)
    parser.add_argument(
        "--template-root",
        type=Path,
        default=Path("config/security_tools/pilot_templates"),
    )
    arguments = parser.parse_args()

    repository = Path(__file__).resolve().parents[1]
    runtime = arguments.runtime_root.expanduser().resolve()
    if runtime == repository or repository in runtime.parents:
        raise SystemExit("acceptance runtime must be outside the repository")
    readiness = _validated_readiness(arguments.readiness_report.expanduser().resolve())
    shutil.rmtree(runtime, ignore_errors=True)
    runtime.mkdir(parents=True, mode=0o700)
    executable = arguments.executable.expanduser().resolve(strict=True)
    source_templates = arguments.template_root.expanduser().resolve(strict=True)
    runtime_templates = runtime / "templates"
    shutil.copytree(source_templates, runtime_templates)
    for path in runtime_templates.rglob("*"):
        path.chmod(0o555 if path.is_dir() else 0o444)

    paths = {
        "web": runtime / "web.sqlite3",
        "authorization": runtime / "authorization.db",
        "governance": runtime / "governance.db",
        "agent": runtime / "agent.db",
        "approval": runtime / "approvals.db",
        "activity": runtime / "activity",
        "evidence": runtime / "evidence",
        "spool": runtime / "spool",
        "execution": runtime / "execution",
        "verification": runtime / "verification",
        "readiness": runtime / "readiness.json",
        "key": runtime / "worker.key",
        "policy": runtime / "worker.json",
    }
    paths["readiness"].write_text(
        json.dumps(readiness, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    paths["key"].write_bytes(secrets.token_bytes(48))
    paths["key"].chmod(0o600)
    paths["policy"].write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "enabled": True,
                "worker_id": "ci-phone-lab-worker",
                "nuclei_executable": str(executable),
                "template_root": str(runtime_templates),
                "maximum_rate_limit": 1,
                "maximum_concurrency": 1,
                "maximum_observations": 25,
                "poll_interval_seconds": 0.05,
                "private_targets_only": True,
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    paths["policy"].chmod(0o600)

    os.environ.update(
        {
            "DJANGO_SETTINGS_MODULE": "vulnhunter.web.settings",
            "VULNHUNTER_WEB_DEBUG": "true",
            "VULNHUNTER_WEB_DATABASE": str(paths["web"]),
            "VULNHUNTER_AUTHORIZATION_DATABASE": str(paths["authorization"]),
            "VULNHUNTER_GOVERNANCE_DATABASE": str(paths["governance"]),
            "VULNHUNTER_AGENT_DATABASE": str(paths["agent"]),
            "VULNHUNTER_APPROVAL_DATABASE": str(paths["approval"]),
            "VULNHUNTER_AGENT_ACTIVITY_ROOT": str(paths["activity"]),
            "VULNHUNTER_SECURITY_EVIDENCE_ROOT": str(paths["evidence"]),
            "VULNHUNTER_NUCLEI_TEMPLATE_ROOT": str(runtime_templates),
            "VULNHUNTER_NUCLEI_TEMPLATE_MANIFEST": str(
                repository / "config/security_tools/nuclei_template_manifest.json"
            ),
            "VULNHUNTER_NUCLEI_READINESS_REPORT": str(paths["readiness"]),
            "VULNHUNTER_NUCLEI_WORKER_POLICY": str(paths["policy"]),
            "VULNHUNTER_NUCLEI_WORKER_SIGNING_KEY_FILE": str(paths["key"]),
            "VULNHUNTER_NUCLEI_WORKER_SPOOL_ROOT": str(paths["spool"]),
            "VULNHUNTER_NUCLEI_EXECUTION_ROOT": str(paths["execution"]),
            "VULNHUNTER_VERIFICATION_ROOT": str(paths["verification"]),
            "VULNHUNTER_NUCLEI_PILOT_ENQUEUE_ENABLED": "true",
        }
    )

    import django

    django.setup()

    from vulnhunter.agent.store import AgentStore
    from vulnhunter.agent_activity.service import AgentActivityService
    from vulnhunter.agent_activity.store import AppendOnlyActivityStore
    from vulnhunter.approvals import ApprovalDecision, ApprovalStore
    from vulnhunter.authorization.models import AuthorizationLimits
    from vulnhunter.authorization.service import issue_authorization
    from vulnhunter.authorization.store import AuthorizationStore
    from vulnhunter.evidence.store import EvidenceStore
    from vulnhunter.oracle.store import OracleStore
    from vulnhunter.scope import validate_target
    from vulnhunter.security_tools.nuclei_activation import NucleiTemplateManifest
    from vulnhunter.security_tools.nuclei_execution import NucleiExecutionStore
    from vulnhunter.security_tools.nuclei_pilot_service import NucleiPilotWorkerService
    from vulnhunter.security_tools.nuclei_worker_pilot import NucleiPilotPolicy
    from vulnhunter.security_tools.scanner_protocol import ScannerCompatibilityManifest
    from vulnhunter.security_tools.worker_spool import SignedWorkerSpool
    from vulnhunter.web.assessment_workflow import (
        AssessmentWorkflowService,
        bind_nuclei_authorization,
    )

    now = datetime.now(UTC)
    authorization_store = AuthorizationStore.from_path(paths["authorization"])
    authorization_store.initialize()
    target = validate_target(arguments.target_url)
    record = issue_authorization(
        authorization_store,
        target,
        owner="phone-operator",
        approved_by="phone-approver",
        purpose="Automated genuine private-lab acceptance test.",
        expires_at=now + timedelta(hours=1),
        limits=AuthorizationLimits(
            maximum_pages=2,
            maximum_depth=0,
            maximum_requests=10,
            minimum_request_delay_seconds=1,
        ),
        now=now - timedelta(seconds=1),
    )
    bind_nuclei_authorization(
        authorization_store,
        authorization_id=record.authorization_id,
        approved_profiles=("passive",),
        private_network_approved=True,
        recorded_by="phone-approver",
        approval_basis="CI acceptance of one exact self-owned RFC1918 target.",
        now=now,
    )
    agent_store = AgentStore(paths["agent"])
    approval_store = ApprovalStore(paths["approval"])
    activity = AgentActivityService(AppendOnlyActivityStore(paths["activity"]))
    workflow = AssessmentWorkflowService(
        authorization_store=authorization_store,
        agent_store=agent_store,
        approval_store=approval_store,
        activity_service=activity,
        profile_config=repository / "config/security_tools/nuclei_profiles.json",
        template_manifest=repository / "config/security_tools/nuclei_template_manifest.json",
        template_root=runtime_templates,
        evidence_root=paths["evidence"],
        readiness_report=paths["readiness"],
    )
    created = workflow.create_assessment(
        authorization_id=record.authorization_id,
        target=record.target_url,
        protocol=record.scheme,
        port=record.port,
        profile="passive",
        identity_id="phone-operator",
        username="phone-operator",
    )
    if created.approval_request is None:
        raise RuntimeError("acceptance assessment did not create an approval request")
    approved = approval_store.decide(
        request_id=created.approval_request.request_id,
        actor_id="phone-approver",
        decision=ApprovalDecision.APPROVE_ONCE,
        reason="Exact target, passive template, limits and plan digest verified.",
    )
    queued = workflow.record_approval_decision(request=approved, actor_id="phone-approver")
    if queued is None or queued.memory["assessment_workflow"]["workflow_state"] != "queued":
        raise RuntimeError("approved assessment did not enter the signed worker queue")

    compatibility = ScannerCompatibilityManifest.load(
        repository / "config/security_tools/scanner_compatibility.json"
    )
    compatibility.verify_repository_manifests(repository)
    template_manifest = NucleiTemplateManifest.model_validate_json(
        (repository / "config/security_tools/nuclei_template_manifest.json").read_text(
            encoding="utf-8"
        )
    )
    worker = NucleiPilotWorkerService(
        spool=SignedWorkerSpool(paths["spool"]),
        signing_key=paths["key"].read_bytes(),
        policy=NucleiPilotPolicy.from_path(paths["policy"]),
        compatibility_manifest=compatibility,
        template_manifest=template_manifest,
        execution_store=NucleiExecutionStore(paths["execution"]),
        evidence_store=EvidenceStore(paths["evidence"]),
        verification_store=OracleStore(paths["verification"]),
        agent_store=agent_store,
        activity_service=activity,
    )
    receipt = worker.run_once()
    if receipt is None or receipt.state != "completed":
        raise RuntimeError(f"real Nuclei worker did not complete: {receipt}")
    final_task = agent_store.get_task(created.task.task_id)
    records = EvidenceStore(paths["evidence"]).list()
    final_workflow = final_task.memory["assessment_workflow"]
    if final_workflow["workflow_state"] != "completed":
        raise RuntimeError("terminal assessment state was not persisted")
    if final_workflow["execution_enabled"] is not True:
        raise RuntimeError("terminal run lost its verified worker capability state")
    if final_workflow["execution_authorized"] is not True:
        raise RuntimeError("terminal run lost its approval state")
    if final_workflow["execution_queued"] is not False:
        raise RuntimeError("terminal run was incorrectly left marked as queued")
    if not records:
        raise RuntimeError("real Nuclei output did not create candidate evidence")
    print(
        json.dumps(
            {
                "run_id": created.task.task_id,
                "authorization_id": record.authorization_id,
                "target": record.target_url,
                "worker_state": receipt.state,
                "evidence_records": len(records),
                "finding_titles": [item.title for item in records],
                "execution_enabled": final_workflow["execution_enabled"],
                "execution_authorized": final_workflow["execution_authorized"],
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
