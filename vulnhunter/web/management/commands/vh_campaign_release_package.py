from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from django.conf import settings
from django.core.management.base import BaseCommand, CommandError

from vulnhunter.exceptions import GovernanceError
from vulnhunter.governance import (
    CampaignReleasePackageError,
    CampaignReleasePackageStore,
    GovernanceStore,
    create_campaign_release_package,
)
from vulnhunter.observations.storage import ScanRepository


class Command(BaseCommand):
    help = "Create or verify one exact append-only governed campaign release package."

    def add_arguments(self, parser) -> None:
        parser.add_argument("--campaign-id", required=True)
        parser.add_argument("--output-root", type=Path)
        parser.add_argument("--json", action="store_true", dest="as_json")

    @staticmethod
    def _repositories(
        governance_store: GovernanceStore,
        campaign_id: str,
    ) -> dict[str, ScanRepository]:
        repositories: dict[str, ScanRepository] = {}
        for scan in governance_store.list_scans(campaign_id):
            path = Path(scan.scan_database).expanduser()
            if path.is_symlink() or not path.is_file():
                raise CampaignReleasePackageError(
                    f"released scan repository is unavailable: {scan.scan_id}"
                )
            resolved = str(path.resolve(strict=True))
            repositories.setdefault(resolved, ScanRepository.from_path(Path(resolved)))
        return repositories

    def handle(self, *args, **options) -> None:
        governance_database = Path(settings.VULNHUNTER_GOVERNANCE_DATABASE)
        output_root = options["output_root"]
        if output_root is None:
            output_root = governance_database.expanduser().resolve().parent / (
                "campaign-release-packages"
            )
        governance_store = GovernanceStore.from_path(governance_database)
        try:
            repositories = self._repositories(
                governance_store,
                options["campaign_id"],
            )
            package, created = create_campaign_release_package(
                governance_store,
                CampaignReleasePackageStore(output_root),
                repositories,
                campaign_id=options["campaign_id"],
            )
        except (
            CampaignReleasePackageError,
            GovernanceError,
            OSError,
            RuntimeError,
            ValueError,
            sqlite3.Error,
        ) as exc:
            raise CommandError(str(exc)) from exc

        result = {
            "status": "created" if created else "verified",
            "package_id": package.package_id,
            "package_sha256": package.package_sha256,
            "campaign_id": package.campaign_id,
            "release_id": package.release_id,
            "application_count": len(package.applications),
            "application_family_count": len(
                {item.application_family for item in package.applications}
            ),
            "review_count": len(package.reviews),
            "adjudicated_review_count": sum(
                item.resolution_state == "adjudicated" for item in package.reviews
            ),
        }
        if options["as_json"]:
            self.stdout.write(json.dumps(result, sort_keys=True))
            return
        self.stdout.write(
            self.style.SUCCESS(
                f"Campaign release package {result['status']}: {package.package_id}"
            )
        )
        self.stdout.write(f"Package SHA-256: {package.package_sha256}")
        self.stdout.write(
            "Coverage: "
            f"{result['application_count']} applications, "
            f"{result['application_family_count']} families, "
            f"{result['review_count']} final reviews, "
            f"{result['adjudicated_review_count']} adjudicated."
        )
