from __future__ import annotations

import json
import os
from pathlib import Path

from django.core.management.base import BaseCommand, CommandError

from vulnhunter.security_tools.remote_nuclei_worker import (
    RemoteNucleiWorkerError,
    RemoteNucleiWorkerPolicy,
    RestrictedSshNucleiRunner,
)


class Command(BaseCommand):
    help = "Verify the restricted remote Nuclei worker without contacting a target."

    def add_arguments(self, parser) -> None:
        parser.add_argument(
            "--policy",
            default=os.environ.get("VULNHUNTER_REMOTE_NUCLEI_WORKER_POLICY", ""),
            help="Owner-controlled guest-side remote-worker policy JSON.",
        )

    def handle(self, *args, **options) -> None:
        policy_value = str(options["policy"] or "").strip()
        if not policy_value:
            raise CommandError("--policy or VULNHUNTER_REMOTE_NUCLEI_WORKER_POLICY is required")
        try:
            policy = RemoteNucleiWorkerPolicy.from_path(Path(policy_value))
            result = RestrictedSshNucleiRunner(policy=policy).verify_readiness()
        except (OSError, ValueError, RemoteNucleiWorkerError) as exc:
            raise CommandError(str(exc)) from exc
        summary = {
            "worker_id": result.worker_id,
            "state": result.execution_state,
            "engine_version": result.engine_version,
            "template_sha256": result.template_sha256,
            "request_digest": result.request_digest,
            "result_digest": result.result_digest,
        }
        self.stdout.write(json.dumps(summary, sort_keys=True, separators=(",", ":")))
