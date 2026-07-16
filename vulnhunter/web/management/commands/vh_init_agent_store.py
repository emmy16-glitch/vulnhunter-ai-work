from __future__ import annotations

from pathlib import Path

from django.conf import settings
from django.core.management.base import BaseCommand, CommandError

from vulnhunter.agent.store import AgentStore, AgentStoreError


class Command(BaseCommand):
    help = "Explicitly initialize or validate the versioned agent runtime store."

    def add_arguments(self, parser) -> None:
        parser.add_argument("--database", type=Path)
        parser.add_argument("--migrate-legacy", action="store_true")
        parser.add_argument("--backup-root", type=Path)

    def handle(self, *args, **options) -> None:
        database = options["database"] or Path(settings.VULNHUNTER_AGENT_DATABASE)
        try:
            store, backup = AgentStore.initialize_database(
                database,
                migrate_legacy=options["migrate_legacy"],
                backup_root=options["backup_root"],
            )
        except AgentStoreError as exc:
            raise CommandError(str(exc)) from exc
        message = f"Agent store schema {store.schema_version()} is ready at {store.database}."
        if backup is not None:
            message += f" Legacy backup: {backup}."
        self.stdout.write(self.style.SUCCESS(message))
