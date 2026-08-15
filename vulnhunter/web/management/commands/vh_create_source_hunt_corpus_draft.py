from __future__ import annotations

import getpass
import json
import os
from pathlib import Path

from django.conf import settings
from django.core.management.base import BaseCommand, CommandError

from vulnhunter.governance.store import GovernanceStore
from vulnhunter.source_hunt.benchmark_v2 import SourceBenchmarkCorpus
from vulnhunter.source_hunt.controlled_corpus import ControlledCorpusService
from vulnhunter.source_hunt.controlled_fixture import (
    ControlledFixtureCompiler,
    ControlledFixtureDefinition,
)
from vulnhunter.source_hunt.service import RepositorySnapshotBuilder, SourceHuntPolicy


def _approved_roots() -> tuple[Path, ...]:
    raw = os.environ.get("VULNHUNTER_SOURCE_HUNT_ROOTS", str(settings.BASE_DIR))
    roots = tuple(Path(item).expanduser() for item in raw.split(os.pathsep) if item.strip())
    if not roots:
        raise CommandError("VULNHUNTER_SOURCE_HUNT_ROOTS has no approved root")
    return roots


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
        "Create one controlled-lab Source Hunt corpus draft bound to an exact approved local "
        "repository snapshot. Reviewer credentials are prompted and never accepted as arguments."
    )

    def add_arguments(self, parser) -> None:
        parser.add_argument("--repo", required=True)
        parser.add_argument("--revision")
        inputs = parser.add_mutually_exclusive_group(required=True)
        inputs.add_argument("--corpus-file")
        inputs.add_argument("--definition-file")
        parser.add_argument("--creator-id", required=True)
        parser.add_argument("--governance-db", required=True)
        parser.add_argument("--output", required=True)

    def handle(self, *args, **options) -> None:
        try:
            governance = GovernanceStore(Path(options["governance_db"]))
            governance.initialize()
            policy = SourceHuntPolicy(approved_roots=_approved_roots())
            repository = Path(options["repo"])
            if options.get("definition_file"):
                definition = ControlledFixtureDefinition.model_validate_json(
                    Path(options["definition_file"]).read_text(encoding="utf-8")
                )
                compiled = ControlledFixtureCompiler(policy=policy).compile(
                    repository,
                    definition=definition,
                )
                snapshot = compiled.snapshot
                corpus = compiled.corpus
            else:
                revision = (options.get("revision") or "").strip()
                if not revision:
                    raise ValueError("--revision is required when --corpus-file is used")
                corpus = SourceBenchmarkCorpus.model_validate_json(
                    Path(options["corpus_file"]).read_text(encoding="utf-8")
                )
                snapshot = RepositorySnapshotBuilder(policy).build(
                    repository,
                    revision=revision,
                )
            secret = getpass.getpass("Governance reviewer credential: ")
            draft = ControlledCorpusService(governance).create_draft(
                snapshot=snapshot,
                corpus=corpus,
                creator_id=options["creator_id"],
                creator_secret=secret,
            )
            _atomic_write(Path(options["output"]).expanduser(), draft)
        except (OSError, ValueError, RuntimeError) as exc:
            raise CommandError(str(exc)) from exc
        self.stdout.write(self.style.SUCCESS(f"created controlled corpus draft {draft.draft_id}"))
