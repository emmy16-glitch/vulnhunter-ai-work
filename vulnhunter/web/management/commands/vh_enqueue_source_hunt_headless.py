from __future__ import annotations

import os
from pathlib import Path

from django.conf import settings
from django.core.management.base import BaseCommand, CommandError

from vulnhunter.source_hunt.headless_v2 import (
    HeadlessManifestLedger,
    HeadlessPermissionManifest,
    HeadlessSourceHuntService,
)
from vulnhunter.source_hunt.jobs import SourceHuntJobStore
from vulnhunter.source_hunt.models import RemoteSourceProcessingApproval
from vulnhunter.source_hunt.service import SourceHuntPolicy


def _approved_roots() -> tuple[Path, ...]:
    raw = os.environ.get("VULNHUNTER_SOURCE_HUNT_ROOTS", str(settings.BASE_DIR))
    roots = tuple(Path(item).expanduser() for item in raw.split(os.pathsep) if item.strip())
    if not roots:
        raise CommandError("VULNHUNTER_SOURCE_HUNT_ROOTS has no approved root")
    return roots


def _job_store() -> SourceHuntJobStore:
    root = Path(
        os.environ.get(
            "VULNHUNTER_SOURCE_HUNT_JOB_ROOT",
            str(settings.BASE_DIR / ".local" / "source-hunt-jobs"),
        )
    )
    return SourceHuntJobStore(root)


def _ledger() -> HeadlessManifestLedger:
    root = Path(
        os.environ.get(
            "VULNHUNTER_SOURCE_HUNT_HEADLESS_LEDGER_ROOT",
            str(settings.BASE_DIR / ".local" / "source-hunt-headless-ledger"),
        )
    )
    return HeadlessManifestLedger(root)


class Command(BaseCommand):
    help = (
        "Enqueue one exact local Source Hunt job from a pre-approved one-use headless manifest. "
        "This command never clones repositories or creates approval."
    )

    def add_arguments(self, parser) -> None:
        parser.add_argument("--repo", required=True)
        parser.add_argument("--revision", required=True)
        parser.add_argument("--manifest-file", required=True)
        parser.add_argument("--approval-file", required=True)

    def handle(self, *args, **options) -> None:
        repository = Path(options["repo"]).expanduser()
        manifest_path = Path(options["manifest_file"]).expanduser()
        approval_path = Path(options["approval_file"]).expanduser()
        try:
            manifest = HeadlessPermissionManifest.model_validate_json(
                manifest_path.read_text(encoding="utf-8")
            )
            approval = RemoteSourceProcessingApproval.model_validate_json(
                approval_path.read_text(encoding="utf-8")
            )
            policy = SourceHuntPolicy(
                approved_roots=_approved_roots(),
                model=settings.VULNHUNTER_GROQ_MODEL,
                maximum_prompt_bytes=min(settings.VULNHUNTER_GROQ_MAX_INPUT_BYTES, 100_000),
                maximum_output_tokens=min(settings.VULNHUNTER_GROQ_MAX_OUTPUT_TOKENS, 4_000),
                timeout_seconds=min(settings.VULNHUNTER_GROQ_TIMEOUT_SECONDS, 180),
            )
            job = HeadlessSourceHuntService(
                policy=policy,
                job_store=_job_store(),
                manifest_ledger=_ledger(),
            ).enqueue(
                repository,
                revision=options["revision"],
                approval=approval,
                manifest=manifest,
            )
        except (OSError, ValueError, RuntimeError) as exc:
            raise CommandError(str(exc)) from exc
        self.stdout.write(self.style.SUCCESS(f"queued {job.job_id}"))
