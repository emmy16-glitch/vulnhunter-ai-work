from __future__ import annotations

import json
from pathlib import Path

from django.core.management.base import BaseCommand, CommandError

from vulnhunter.governance.store import GovernanceStore
from vulnhunter.source_hunt.controlled_corpus import (
    ControlledCorpusDraft,
    ControlledCorpusReviewAttestation,
    ControlledCorpusService,
)


def _atomic_write(path: Path, payload) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_text(
        json.dumps(payload.model_dump(mode="json"), sort_keys=True, indent=2) + "\n",
        encoding="utf-8",
    )
    temporary.replace(path)


class Command(BaseCommand):
    help = (
        "Release an exact controlled Source Hunt corpus only after at least two distinct current "
        "reviewers independently approved the same immutable draft."
    )

    def add_arguments(self, parser) -> None:
        parser.add_argument("--draft-file", required=True)
        parser.add_argument("--review-file", action="append", required=True)
        parser.add_argument("--governance-db", required=True)
        parser.add_argument("--output", required=True)

    def handle(self, *args, **options) -> None:
        try:
            governance = GovernanceStore(Path(options["governance_db"]))
            governance.initialize()
            draft = ControlledCorpusDraft.model_validate_json(
                Path(options["draft_file"]).read_text(encoding="utf-8")
            )
            reviews = tuple(
                ControlledCorpusReviewAttestation.model_validate_json(
                    Path(path).read_text(encoding="utf-8")
                )
                for path in options["review_file"]
            )
            release = ControlledCorpusService(governance).release(
                draft=draft,
                attestations=reviews,
            )
            _atomic_write(Path(options["output"]).expanduser(), release)
        except (OSError, ValueError, RuntimeError) as exc:
            raise CommandError(str(exc)) from exc
        reviewers = ", ".join(release.approved_reviewer_ids)
        self.stdout.write(
            self.style.SUCCESS(f"released {release.release_id} after approvals from {reviewers}")
        )
