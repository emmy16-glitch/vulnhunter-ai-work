from __future__ import annotations

import json
from pathlib import Path

from django.core.management.base import BaseCommand, CommandError

from vulnhunter.web.backup_recovery import verify_backup_bundle


class Command(BaseCommand):
    help = (
        "Verify hashes, file inventory, paths, and SQLite integrity in a backup bundle."
    )

    def add_arguments(self, parser):
        parser.add_argument("bundle", help="Backup bundle directory to verify.")

    def handle(self, *args, **options):
        del args
        report = verify_backup_bundle(Path(options["bundle"]))
        self.stdout.write(json.dumps(report.as_payload(), separators=(",", ":"), sort_keys=True))
        if not report.valid:
            raise CommandError("VulnHunter backup verification failed.")
