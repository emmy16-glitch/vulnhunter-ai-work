from __future__ import annotations

import os
import time
from datetime import UTC, datetime
from pathlib import Path

from django.conf import settings
from django.core.management.base import BaseCommand, CommandError

from vulnhunter.mobile import MobileArtifactIngestor
from vulnhunter.mobile.extension_service import (
    MobileExtensionQueueService,
    MobileExtensionServiceError,
)
from vulnhunter.mobile.extension_spool import (
    MobileExtensionSpool,
    MobileExtensionSpoolError,
)
from vulnhunter.security_tools.worker_spool import (
    WorkerSpoolError,
    load_worker_signing_key,
)


class Command(BaseCommand):
    help = "Run separately approved MobSF and disposable Android runtime jobs."

    def add_arguments(self, parser) -> None:
        mode = parser.add_mutually_exclusive_group()
        mode.add_argument("--once", action="store_true")
        mode.add_argument("--watch", action="store_true")
        parser.add_argument("--poll-seconds", type=float, default=1.0)

    def handle(self, *args, **options) -> None:
        poll_seconds = float(options["poll_seconds"])
        if not 0.1 <= poll_seconds <= 60:
            raise CommandError("poll-seconds must be between 0.1 and 60")
        spool_root = Path(
            os.environ.get(
                "VULNHUNTER_MOBILE_EXTENSION_SPOOL_ROOT",
                str(Path(settings.BASE_DIR) / ".local" / "mobile-extension-spool"),
            )
        )
        result_root = Path(
            os.environ.get(
                "VULNHUNTER_MOBILE_EXTENSION_RESULT_ROOT",
                str(Path(settings.BASE_DIR) / ".local" / "mobile-extension-results"),
            )
        )
        try:
            spool = MobileExtensionSpool(spool_root)
            spool.recover_processing(now=datetime.now(UTC))
            service = MobileExtensionQueueService(
                spool=spool,
                signing_key=load_worker_signing_key(
                    self._path(
                        "VULNHUNTER_MOBILE_EXTENSION_SIGNING_KEY_FILE",
                        "mobile-extension-worker.key",
                    )
                ),
                runtime_approval_key=load_worker_signing_key(
                    self._path(
                        "VULNHUNTER_MOBILE_RUNTIME_APPROVAL_KEY_FILE",
                        "mobile-runtime-approval.key",
                    )
                ),
                ingestor=MobileArtifactIngestor(
                    Path(settings.VULNHUNTER_MOBILE_ARTIFACT_ROOT),
                    maximum_apk_bytes=settings.VULNHUNTER_MOBILE_MAX_APK_BYTES,
                ),
                result_root=result_root,
                mobsf_policy_path=self._path("VULNHUNTER_MOBSF_POLICY", "mobsf.json"),
                runtime_policy_path=self._path(
                    "VULNHUNTER_MOBILE_RUNTIME_POLICY",
                    "mobile-runtime.json",
                ),
            )
            while True:
                receipt = service.run_once()
                if receipt is not None:
                    self.stdout.write(
                        self.style.SUCCESS(
                            f"Mobile extension {receipt.job_id} finished with state "
                            f"{receipt.state}."
                        )
                    )
                elif not options["watch"]:
                    self.stdout.write("No mobile extension job is pending.")
                    return
                if not options["watch"]:
                    return
                time.sleep(poll_seconds)
        except KeyboardInterrupt:
            self.stdout.write(self.style.WARNING("Mobile extension worker stopped."))
        except (
            OSError,
            ValueError,
            MobileExtensionServiceError,
            MobileExtensionSpoolError,
            WorkerSpoolError,
        ) as exc:
            raise CommandError(str(exc)) from exc

    @staticmethod
    def _path(name: str, fallback: str) -> Path:
        return Path(
            os.environ.get(
                name,
                str(Path(settings.BASE_DIR) / ".codespaces" / "runtime" / fallback),
            )
        )
