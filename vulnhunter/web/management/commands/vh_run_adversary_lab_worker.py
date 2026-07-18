from __future__ import annotations

import time
from pathlib import Path

from django.conf import settings
from django.core.management.base import BaseCommand, CommandError

from vulnhunter.adversary_lab.runner import LabWorkerPolicy, SyntheticScenarioRunner
from vulnhunter.adversary_lab.service import AdversaryLabService, AdversaryLabServiceError
from vulnhunter.adversary_lab.store import AdversaryLabStore, AdversaryLabStoreError
from vulnhunter.agent_activity.service import AgentActivityService
from vulnhunter.agent_activity.store import AppendOnlyActivityStore


class Command(BaseCommand):
    help = "Process queued controlled validation simulations."

    def add_arguments(self, parser) -> None:
        parser.add_argument("--once", action="store_true")
        parser.add_argument("--poll-seconds", type=float, default=2.0)

    def handle(self, *args, **options) -> None:
        del args
        poll_seconds = float(options["poll_seconds"])
        if not 0.2 <= poll_seconds <= 60:
            raise CommandError("--poll-seconds must be between 0.2 and 60")
        try:
            policy = LabWorkerPolicy(
                enabled=settings.VULNHUNTER_ADVERSARY_LAB_ENABLED,
                workspace_root=Path(settings.VULNHUNTER_ADVERSARY_LAB_WORKSPACE_ROOT).absolute(),
                evidence_root=Path(settings.VULNHUNTER_ADVERSARY_LAB_EVIDENCE_ROOT).absolute(),
                maximum_trials=settings.VULNHUNTER_ADVERSARY_LAB_MAX_TRIALS,
            )
            service = AdversaryLabService(
                store=AdversaryLabStore(Path(settings.VULNHUNTER_ADVERSARY_LAB_DATABASE)),
                activity_service=AgentActivityService(
                    AppendOnlyActivityStore(Path(settings.VULNHUNTER_AGENT_ACTIVITY_ROOT))
                ),
                runner=SyntheticScenarioRunner(policy),
            )
        except (
            OSError,
            ValueError,
            AdversaryLabStoreError,
            AdversaryLabServiceError,
        ) as exc:
            raise CommandError(str(exc)) from exc

        while True:
            try:
                record = service.run_next()
            except (AdversaryLabStoreError, AdversaryLabServiceError) as exc:
                raise CommandError(str(exc)) from exc
            if record is not None:
                self.stdout.write(
                    self.style.SUCCESS(
                        f"Lab run {record.plan.lab_id} finished with state {record.state.value}."
                    )
                )
            elif options["once"]:
                self.stdout.write("No controlled validation run is queued.")
                return
            if options["once"]:
                return
            time.sleep(poll_seconds)
