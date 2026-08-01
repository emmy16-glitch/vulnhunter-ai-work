from __future__ import annotations

import json
from datetime import timedelta

from django.core.management.base import BaseCommand, CommandError

from vulnhunter.web.publication_service import publication_deployment_readiness


class Command(BaseCommand):
    help = "Validate governed publication activation, authorities, destinations and signed state."

    def add_arguments(self, parser) -> None:
        parser.add_argument("--probe-writes", action="store_true")
        parser.add_argument("--minimum-free-mib", type=int, default=64)
        parser.add_argument("--stale-after-minutes", type=int, default=60)
        parser.add_argument("--json", action="store_true", dest="as_json")

    def handle(self, *args, **options) -> None:
        minimum_free_mib = options["minimum_free_mib"]
        stale_after_minutes = options["stale_after_minutes"]
        if minimum_free_mib < 0:
            raise CommandError("minimum free MiB must be non-negative")
        if stale_after_minutes < 1:
            raise CommandError("stale publication threshold must be at least one minute")
        report = publication_deployment_readiness(
            probe_writes=options["probe_writes"],
            minimum_free_bytes=minimum_free_mib * 1024 * 1024,
            stale_after=timedelta(minutes=stale_after_minutes),
        )
        if options["as_json"]:
            self.stdout.write(json.dumps(report.as_dict(), sort_keys=True))
        else:
            self.stdout.write(f"Publication status: {report.status}.")
            for check in report.checks:
                self.stdout.write(f"- {check.name}: {check.state} — {check.detail}")
            for warning in report.warnings:
                self.stdout.write(self.style.WARNING(f"Warning: {warning}"))
            for blocker in report.blockers:
                self.stdout.write(self.style.ERROR(f"Blocker: {blocker}"))
        if not report.enabled:
            raise CommandError("governed publication is not activated")
        if not report.ready:
            raise CommandError("governed publication preflight failed")
        self.stdout.write(self.style.SUCCESS("Governed publication preflight passed."))
