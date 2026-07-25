from __future__ import annotations

import os
import time
from datetime import UTC, datetime
from pathlib import Path

from django.conf import settings
from django.core.management.base import BaseCommand, CommandError

from vulnhunter.mobile import MobileArtifactIngestor
from vulnhunter.mobile.static_service import (
    MobileStaticQueueService,
    MobileStaticQueueServiceError,
)
from vulnhunter.mobile.static_spool import MobileStaticSpool, MobileStaticSpoolError
from vulnhunter.mobile.static_worker import (
    MobileStaticWorker,
    MobileStaticWorkerError,
    MobileStaticWorkerPolicy,
)
from vulnhunter.security_tools.worker_spool import WorkerSpoolError, load_worker_signing_key


class Command(BaseCommand):
    help = "Run direct or queued read-only analysis for already-ingested APK artifacts."

    def add_arguments(self, parser) -> None:
        parser.add_argument("artifact_id", nargs="?")
        mode = parser.add_mutually_exclusive_group()
        mode.add_argument("--once", action="store_true", help="Process at most one queued job.")
        mode.add_argument("--watch", action="store_true", help="Keep polling for queued jobs.")
        parser.add_argument("--poll-seconds", type=float, default=1.0)
        parser.add_argument("--policy", type=Path)

    def handle(self, *args, **options) -> None:
        policy_path = options["policy"] or Path(settings.VULNHUNTER_MOBILE_STATIC_WORKER_POLICY)
        try:
            policy = MobileStaticWorkerPolicy.from_path(policy_path)
        except (OSError, ValueError, MobileStaticWorkerError) as exc:
            raise CommandError(str(exc)) from exc

        artifact_id = str(options.get("artifact_id") or "").strip()
        if artifact_id:
            if options["watch"] or options["once"]:
                raise CommandError("artifact_id cannot be combined with --watch or --once")
            self._run_direct(artifact_id=artifact_id, policy=policy)
            return

        poll_seconds = float(options["poll_seconds"])
        if not 0.1 <= poll_seconds <= 60:
            raise CommandError("poll-seconds must be between 0.1 and 60")
        self._run_queue(
            policy=policy,
            watch=bool(options["watch"]),
            poll_seconds=poll_seconds,
        )

    def _ingestor(self) -> MobileArtifactIngestor:
        return MobileArtifactIngestor(
            Path(settings.VULNHUNTER_MOBILE_ARTIFACT_ROOT),
            maximum_apk_bytes=settings.VULNHUNTER_MOBILE_MAX_APK_BYTES,
        )

    def _run_direct(self, *, artifact_id: str, policy: MobileStaticWorkerPolicy) -> None:
        records = {record.artifact_id: record for record in self._ingestor().list_records()}
        try:
            record = records[artifact_id]
        except KeyError as exc:
            raise CommandError("The requested APK artifact does not exist.") from exc
        result = MobileStaticWorker(policy).analyze(record)
        if result.state != "completed":
            raise CommandError(result.reason)
        self.stdout.write(
            self.style.SUCCESS(
                f"Static analysis completed for {result.artifact_id}: "
                f"{len(result.candidate_observations)} candidate observation(s)."
            )
        )

    def _run_queue(
        self,
        *,
        policy: MobileStaticWorkerPolicy,
        watch: bool,
        poll_seconds: float,
    ) -> None:
        spool_root = Path(
            os.environ.get(
                "VULNHUNTER_MOBILE_STATIC_SPOOL_ROOT",
                str(Path(settings.BASE_DIR) / ".local" / "mobile-static-spool"),
            )
        )
        key_path = Path(
            os.environ.get(
                "VULNHUNTER_MOBILE_STATIC_SIGNING_KEY_FILE",
                str(Path.home() / ".vulnhunter-mobile-worker-key"),
            )
        )
        try:
            spool = MobileStaticSpool(spool_root)
            spool.recover_processing(now=datetime.now(UTC))
            service = MobileStaticQueueService(
                spool=spool,
                signing_key=load_worker_signing_key(key_path),
                policy=policy,
                ingestor=self._ingestor(),
            )
            while True:
                receipt = service.run_once()
                if receipt is not None:
                    self.stdout.write(
                        self.style.SUCCESS(
                            f"Mobile job {receipt.job_id} finished with state {receipt.state}."
                        )
                    )
                elif not watch:
                    self.stdout.write("No mobile static job is pending.")
                    return
                if not watch:
                    return
                time.sleep(poll_seconds)
        except KeyboardInterrupt:
            self.stdout.write(self.style.WARNING("Mobile static worker watch stopped."))
        except (
            OSError,
            ValueError,
            MobileStaticQueueServiceError,
            MobileStaticSpoolError,
            WorkerSpoolError,
        ) as exc:
            raise CommandError(str(exc)) from exc
