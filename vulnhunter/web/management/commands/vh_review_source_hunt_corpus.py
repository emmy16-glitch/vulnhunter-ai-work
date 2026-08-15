from __future__ import annotations

import getpass
import json
from pathlib import Path

from django.core.management.base import BaseCommand, CommandError

from vulnhunter.governance.store import GovernanceStore
from vulnhunter.source_hunt.controlled_corpus import (
    ControlledCorpusDraft,
    ControlledCorpusReviewDecision,
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
        "Record one authenticated independent review of an exact controlled Source Hunt corpus "
        "draft. Reviewer credentials are prompted and never accepted as arguments."
    )

    def add_arguments(self, parser) -> None:
        parser.add_argument("--draft-file", required=True)
        parser.add_argument("--reviewer-id", required=True)
        parser.add_argument("--decision", choices=("approve", "reject"), required=True)
        parser.add_argument("--governance-db", required=True)
        parser.add_argument("--output", required=True)

    def handle(self, *args, **options) -> None:
        try:
            governance = GovernanceStore(Path(options["governance_db"]))
            governance.initialize()
            draft = ControlledCorpusDraft.model_validate_json(
                Path(options["draft_file"]).read_text(encoding="utf-8")
            )
            secret = getpass.getpass("Governance reviewer credential: ")
            attestation = ControlledCorpusService(governance).attest(
                draft=draft,
                reviewer_id=options["reviewer_id"],
                reviewer_secret=secret,
                decision=ControlledCorpusReviewDecision(options["decision"]),
            )
            _atomic_write(Path(options["output"]).expanduser(), attestation)
        except (OSError, ValueError, RuntimeError) as exc:
            raise CommandError(str(exc)) from exc
        self.stdout.write(
            self.style.SUCCESS(
                f"recorded {attestation.decision.value} review {attestation.attestation_id}"
            )
        )
