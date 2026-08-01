from __future__ import annotations

import json

from django.core.management.base import BaseCommand, CommandError

from vulnhunter.web.readiness import deployment_readiness


class Command(BaseCommand):
    help = "Check whether VulnHunter's required local production dependencies are ready."

    def handle(self, *args, **options):
        del args, options
        report = deployment_readiness()
        self.stdout.write(json.dumps(report.as_payload(), separators=(",", ":"), sort_keys=True))
        if not report.ready:
            raise CommandError("VulnHunter deployment readiness checks failed.")
