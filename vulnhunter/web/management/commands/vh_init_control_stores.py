from __future__ import annotations

from pathlib import Path

from django.conf import settings
from django.core.management.base import BaseCommand, CommandError

from vulnhunter.authorization.store import AuthorizationStore
from vulnhunter.governance.store import GovernanceStore


class Command(BaseCommand):
    help = "Explicitly initialize or validate the authorization and governance stores."

    def add_arguments(self, parser) -> None:
        parser.add_argument("--authorization-database", type=Path)
        parser.add_argument("--governance-database", type=Path)

    def handle(self, *args, **options) -> None:
        authorization_path = (
            options["authorization_database"] or Path(settings.VULNHUNTER_AUTHORIZATION_DATABASE)
        ).expanduser()
        governance_path = (
            options["governance_database"] or Path(settings.VULNHUNTER_GOVERNANCE_DATABASE)
        ).expanduser()

        for path in (authorization_path, governance_path):
            if path.exists() and path.is_symlink():
                raise CommandError(f"Store path may not be a symbolic link: {path}")
            path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)

        try:
            authorization = AuthorizationStore.from_path(authorization_path)
            authorization.initialize()
            authorization.list(limit=1)
            governance = GovernanceStore.from_path(governance_path)
            governance.initialize()
            governance.list_campaigns()
            governance.verify_integrity()
        except Exception as exc:
            raise CommandError(f"Control stores could not be initialized safely: {exc}") from exc

        self.stdout.write(
            self.style.SUCCESS(
                "Control stores are ready. "
                f"Authorization={authorization_path.resolve()} "
                f"Governance={governance_path.resolve()}"
            )
        )
