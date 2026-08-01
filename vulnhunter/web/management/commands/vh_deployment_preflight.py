from __future__ import annotations

import json

from django.core.management.base import BaseCommand, CommandError

from vulnhunter.web.deployment_policy import deployment_policy
from vulnhunter.web.readiness import deployment_readiness


class Command(BaseCommand):
    help = "Check local readiness and fail-closed deployment security policy."

    def add_arguments(self, parser):
        parser.add_argument(
            "--public",
            action="store_true",
            help=(
                "Require HTTPS, secure cookies, HSTS, an explicit public host, "
                "trusted HTTPS CSRF origins, and PostgreSQL."
            ),
        )

    def handle(self, *args, **options):
        del args
        readiness = deployment_readiness()
        policy = deployment_policy(public=bool(options["public"]))
        payload = readiness.as_payload()
        payload["policy"] = policy.as_payload()
        payload["status"] = "ready" if readiness.ready and policy.ready else "unready"
        self.stdout.write(json.dumps(payload, separators=(",", ":"), sort_keys=True))
        if not readiness.ready or not policy.ready:
            raise CommandError("VulnHunter deployment readiness checks failed.")
