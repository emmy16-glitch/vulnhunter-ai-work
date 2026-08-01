from __future__ import annotations

import json
from pathlib import Path

from django.core.management.base import BaseCommand, CommandError

from vulnhunter.web.backup_recovery import BackupRecoveryError, create_backup_bundle


class Command(BaseCommand):
    help = "Create an atomic, checksummed VulnHunter recovery bundle."

    def add_arguments(self, parser):
        parser.add_argument(
            "destination", help="New directory to create for the backup bundle."
        )
        parser.add_argument(
            "--postgres-dump",
            help="Externally created pg_dump artifact required for PostgreSQL deployments.",
        )

    def handle(self, *args, **options):
        del args
        postgresql_dump = (
            Path(options["postgres_dump"]) if options.get("postgres_dump") else None
        )
        try:
            payload = create_backup_bundle(
                Path(options["destination"]),
                postgresql_dump=postgresql_dump,
            )
        except BackupRecoveryError as exc:
            raise CommandError(str(exc)) from exc
        self.stdout.write(json.dumps(payload, separators=(",", ":"), sort_keys=True))
