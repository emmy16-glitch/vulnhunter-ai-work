from __future__ import annotations

import os
from datetime import UTC, datetime
from pathlib import Path

from django.conf import settings
from django.core.management.base import BaseCommand, CommandError

from vulnhunter.agent.store import AgentStore
from vulnhunter.agent_activity.service import AgentActivityService
from vulnhunter.agent_activity.store import AppendOnlyActivityStore
from vulnhunter.evidence.store import EvidenceStore
from vulnhunter.oracle.store import OracleStore
from vulnhunter.security_tools.nuclei_activation import NucleiTemplateManifest
from vulnhunter.security_tools.nuclei_execution import NucleiExecutionStore
from vulnhunter.security_tools.remote_nuclei_worker import (
    RemoteNucleiPilotWorkerService,
    RemoteNucleiWorkerError,
    RemoteNucleiWorkerPolicy,
    RestrictedSshNucleiRunner,
)
from vulnhunter.security_tools.scanner_protocol import ScannerCompatibilityManifest
from vulnhunter.security_tools.worker_spool import (
    SignedWorkerSpool,
    WorkerSpoolError,
    load_worker_signing_key,
)


class Command(BaseCommand):
    help = "Process one signed passive Nuclei job through the restricted remote worker."

    def add_arguments(self, parser) -> None:
        parser.add_argument(
            "--policy",
            default=os.environ.get("VULNHUNTER_REMOTE_NUCLEI_WORKER_POLICY", ""),
            help="Owner-controlled guest-side remote-worker policy JSON.",
        )
        parser.add_argument(
            "--skip-readiness",
            action="store_true",
            help="Skip the separate readiness request; intended only for supervised tests.",
        )

    def handle(self, *args, **options) -> None:
        base = Path(settings.BASE_DIR)
        policy_value = str(options["policy"] or "").strip()
        if not policy_value:
            raise CommandError(
                "--policy or VULNHUNTER_REMOTE_NUCLEI_WORKER_POLICY is required"
            )
        policy_path = Path(policy_value)
        key_path = Path(settings.VULNHUNTER_NUCLEI_WORKER_SIGNING_KEY_FILE)
        spool_root = Path(settings.VULNHUNTER_NUCLEI_WORKER_SPOOL_ROOT)
        execution_root = Path(settings.VULNHUNTER_NUCLEI_EXECUTION_ROOT)
        verification_root = Path(settings.VULNHUNTER_VERIFICATION_ROOT)
        compatibility_path = Path(settings.VULNHUNTER_SCANNER_COMPATIBILITY_MANIFEST)
        try:
            policy = RemoteNucleiWorkerPolicy.from_path(policy_path)
            runner = RestrictedSshNucleiRunner(policy=policy)
            if not options["skip_readiness"]:
                runner.verify_readiness()
            signing_key = load_worker_signing_key(key_path)
            compatibility = ScannerCompatibilityManifest.load(compatibility_path)
            compatibility.verify_repository_manifests(base)
            template_manifest = NucleiTemplateManifest.model_validate_json(
                Path(settings.VULNHUNTER_NUCLEI_TEMPLATE_MANIFEST).read_text(
                    encoding="utf-8"
                )
            )
            now = datetime.now(UTC)
            spool = SignedWorkerSpool(spool_root)
            execution_store = NucleiExecutionStore(execution_root)
            spool.recover_processing(now=now)
            execution_store.recover_unfinished(actor_id=policy.worker_id, now=now)
            service = RemoteNucleiPilotWorkerService(
                remote_runner=runner,
                spool=spool,
                signing_key=signing_key,
                compatibility_manifest=compatibility,
                template_manifest=template_manifest,
                execution_store=execution_store,
                evidence_store=EvidenceStore(
                    Path(settings.VULNHUNTER_SECURITY_EVIDENCE_ROOT)
                ),
                verification_store=OracleStore(verification_root),
                agent_store=AgentStore(Path(settings.VULNHUNTER_AGENT_DATABASE)),
                activity_service=AgentActivityService(
                    AppendOnlyActivityStore(
                        Path(settings.VULNHUNTER_AGENT_ACTIVITY_ROOT)
                    )
                ),
            )
            receipt = service.run_once()
        except (
            OSError,
            ValueError,
            WorkerSpoolError,
            RemoteNucleiWorkerError,
        ) as exc:
            raise CommandError(str(exc)) from exc
        if receipt is None:
            self.stdout.write("No signed Nuclei pilot job is pending.")
            return
        self.stdout.write(
            self.style.SUCCESS(
                f"Remote worker job {receipt.job_id} finished with state {receipt.state}."
            )
        )
