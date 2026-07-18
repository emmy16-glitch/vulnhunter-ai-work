from __future__ import annotations

from pathlib import Path

from django.conf import settings
from django.core.management.base import BaseCommand, CommandError

from vulnhunter.mobile import MobileArtifactIngestor
from vulnhunter.mobile.static_worker import (
    MobileStaticWorker,
    MobileStaticWorkerError,
    MobileStaticWorkerPolicy,
)


class Command(BaseCommand):
    help = "Run read-only static analysis for one already-ingested APK artifact."

    def add_arguments(self, parser) -> None:
        parser.add_argument("artifact_id")
        parser.add_argument("--policy", type=Path)

    def handle(self, *args, **options) -> None:
        artifact_id = str(options["artifact_id"]).strip()
        ingestor = MobileArtifactIngestor(Path(settings.VULNHUNTER_MOBILE_ARTIFACT_ROOT))
        records = {record.artifact_id: record for record in ingestor.list_records()}
        try:
            record = records[artifact_id]
        except KeyError as exc:
            raise CommandError("The requested APK artifact does not exist.") from exc
        policy_path = options["policy"] or Path(
            getattr(
                settings,
                "VULNHUNTER_MOBILE_STATIC_WORKER_POLICY",
                Path(settings.BASE_DIR)
                / "config/security_tools/mobile_static_worker.json",
            )
        )
        try:
            policy = MobileStaticWorkerPolicy.from_path(policy_path)
            result = MobileStaticWorker(policy).analyze(record)
        except (OSError, ValueError, MobileStaticWorkerError) as exc:
            raise CommandError(str(exc)) from exc
        if result.state != "completed":
            raise CommandError(result.reason)
        self.stdout.write(
            self.style.SUCCESS(
                f"Static analysis completed for {result.artifact_id}: "
                f"{len(result.candidate_observations)} candidate observation(s)."
            )
        )
