from __future__ import annotations

import json
from pathlib import Path

from django.core.management.base import BaseCommand, CommandError

from vulnhunter.web.backup_recovery import plan_restore


class Command(BaseCommand):
    help = "Verify a backup and print the restore actions without replacing live state."

    def add_arguments(self, parser):
        parser.add_argument("bundle", help="Backup bundle directory to plan for restore.")

    def handle(self, *args, **options):
        del args
        plan = plan_restore(Path(options["bundle"]))
        self.stdout.write(json.dumps(plan.as_payload(), separators=(",", ":"), sort_keys=True))
        if not plan.ready:
            raise CommandError("VulnHunter restore planning is blocked by backup verification.")
