from __future__ import annotations

import json
from pathlib import Path

from django.core.management.base import BaseCommand, CommandError

from vulnhunter.web.backup_recovery import BackupRecoveryError
from vulnhunter.web.restore_execution import execute_verified_sqlite_restore


class Command(BaseCommand):
    help = "Execute a digest-bound SQLite restore with rollback protection."

    def add_arguments(self, parser):
        parser.add_argument("bundle", help="Verified backup bundle directory.")
        parser.add_argument(
            "--bundle-digest",
            required=True,
            help="Expected SHA-256 digest of the bundle manifest.",
        )
        parser.add_argument(
            "--maintenance-marker",
            required=True,
            help="Owner-only JSON maintenance marker for this exact bundle.",
        )
        parser.add_argument(
            "--rollback-directory",
            required=True,
            help="New private directory for pre-restore rollback snapshots.",
        )

    def handle(self, *args, **options):
        del args
        try:
            result = execute_verified_sqlite_restore(
                Path(options["bundle"]),
                expected_bundle_digest=options["bundle_digest"],
                maintenance_marker=Path(options["maintenance_marker"]),
                rollback_directory=Path(options["rollback_directory"]),
            )
        except BackupRecoveryError as exc:
            raise CommandError(str(exc)) from exc
        self.stdout.write(json.dumps(result.as_payload(), separators=(",", ":"), sort_keys=True))
