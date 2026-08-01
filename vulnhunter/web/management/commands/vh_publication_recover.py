from __future__ import annotations

import json
from datetime import timedelta

from django.core.management.base import BaseCommand, CommandError

from vulnhunter.publication import PublicationServiceError, PublicationStoreError
from vulnhunter.web.publication_service import publication_recovery


class Command(BaseCommand):
    help = "Inspect or narrowly repair interrupted governed publication operations."

    def add_arguments(self, parser) -> None:
        parser.add_argument("--apply-safe", action="store_true")
        parser.add_argument("--stale-after-minutes", type=int, default=60)
        parser.add_argument("--json", action="store_true", dest="as_json")

    def handle(self, *args, **options) -> None:
        stale_after_minutes = options["stale_after_minutes"]
        if stale_after_minutes < 1:
            raise CommandError("stale publication threshold must be at least one minute")
        try:
            report = publication_recovery(
                apply_safe=options["apply_safe"],
                stale_after=timedelta(minutes=stale_after_minutes),
            )
        except (PublicationServiceError, PublicationStoreError, OSError, RuntimeError) as exc:
            raise CommandError(str(exc)) from exc
        if options["as_json"]:
            self.stdout.write(json.dumps(report.as_dict(), sort_keys=True))
        else:
            for action in report.actions:
                self.stdout.write(self.style.SUCCESS(f"Action: {action}"))
            if not report.issues:
                self.stdout.write(self.style.SUCCESS("No publication recovery issue remains."))
            for issue in report.issues:
                style = self.style.ERROR if issue.severity == "blocker" else self.style.WARNING
                location = "/".join(
                    item
                    for item in (issue.destination_id, issue.relative_path)
                    if item is not None
                )
                suffix = f" [{location}]" if location else ""
                self.stdout.write(style(f"{issue.code}{suffix}: {issue.detail}"))
        if report.blockers:
            action = "after safe recovery" if options["apply_safe"] else "during inspection"
            raise CommandError(f"publication recovery blockers remain {action}")
