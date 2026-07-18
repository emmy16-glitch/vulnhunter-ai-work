from __future__ import annotations

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
from vulnhunter.security_tools.nuclei_pilot_service import (
    NucleiPilotServiceError,
    NucleiPilotWorkerService,
)
from vulnhunter.security_tools.nuclei_worker_pilot import NucleiPilotPolicy
from vulnhunter.security_tools.scanner_protocol import ScannerCompatibilityManifest
from vulnhunter.security_tools.worker_spool import (
    SignedWorkerSpool,
    WorkerSpoolError,
    load_worker_signing_key,
)


class Command(BaseCommand):
    help = "Process one signed passive Nuclei pilot job in the isolated worker boundary."

    def add_arguments(self, parser) -> None:
        parser.add_argument("--once", action="store_true", default=True)

    def handle(self, *args, **options) -> None:
        base = Path(settings.BASE_DIR)
        policy_path = Path(
            getattr(
                settings,
                "VULNHUNTER_NUCLEI_WORKER_POLICY",
                base / "config/security_tools/nuclei_worker_pilot.json",
            )
        )
        key_path = Path(
            getattr(
                settings,
                "VULNHUNTER_NUCLEI_WORKER_SIGNING_KEY_FILE",
                Path.home() / ".vulnhunter-nuclei-worker-key",
            )
        )
        spool_root = Path(
            getattr(
                settings,
                "VULNHUNTER_NUCLEI_WORKER_SPOOL_ROOT",
                base / ".local/nuclei-worker-spool",
            )
        )
        execution_root = Path(
            getattr(
                settings,
                "VULNHUNTER_NUCLEI_EXECUTION_ROOT",
                base / ".local/nuclei-executions",
            )
        )
        verification_root = Path(
            getattr(
                settings,
                "VULNHUNTER_VERIFICATION_ROOT",
                base / ".local/verification",
            )
        )
        compatibility_path = base / "config/security_tools/scanner_compatibility.json"
        try:
            policy = NucleiPilotPolicy.from_path(policy_path)
            signing_key = load_worker_signing_key(key_path)
            compatibility = ScannerCompatibilityManifest.load(compatibility_path)
            compatibility.verify_repository_manifests(base)
            template_manifest = NucleiTemplateManifest.model_validate_json(
                Path(settings.VULNHUNTER_NUCLEI_TEMPLATE_MANIFEST).read_text(encoding="utf-8")
            )
            service = NucleiPilotWorkerService(
                spool=SignedWorkerSpool(spool_root),
                signing_key=signing_key,
                policy=policy,
                compatibility_manifest=compatibility,
                template_manifest=template_manifest,
                execution_store=NucleiExecutionStore(execution_root),
                evidence_store=EvidenceStore(Path(settings.VULNHUNTER_SECURITY_EVIDENCE_ROOT)),
                verification_store=OracleStore(verification_root),
                agent_store=AgentStore(Path(settings.VULNHUNTER_AGENT_DATABASE)),
                activity_service=AgentActivityService(
                    AppendOnlyActivityStore(Path(settings.VULNHUNTER_AGENT_ACTIVITY_ROOT))
                ),
            )
            receipt = service.run_once()
        except (
            OSError,
            ValueError,
            WorkerSpoolError,
            NucleiPilotServiceError,
        ) as exc:
            raise CommandError(str(exc)) from exc
        if receipt is None:
            self.stdout.write("No signed Nuclei pilot job is pending.")
            return
        self.stdout.write(
            self.style.SUCCESS(
                f"Worker job {receipt.job_id} finished with state {receipt.state}."
            )
        )
