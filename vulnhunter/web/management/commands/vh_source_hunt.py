from __future__ import annotations

import os
import stat
from datetime import UTC, datetime, timedelta
from pathlib import Path

from django.conf import settings
from django.core.management.base import BaseCommand, CommandError

from vulnhunter.governance.service import authenticate_identity
from vulnhunter.governance.store import GovernanceStore
from vulnhunter.providers import GroqProvider, GroqProviderError
from vulnhunter.source_hunt import (
    GroqSourceHunt,
    RemoteSourceProcessingApproval,
    RepositorySnapshotBuilder,
    RepositoryVisibility,
    SourceHuntError,
    SourceHuntPolicy,
    SourceHuntStore,
)


def _secret_from_file(path: Path) -> str:
    expanded = path.expanduser()
    if expanded.is_symlink():
        raise CommandError("governance secret file may not be a symbolic link")
    try:
        metadata = expanded.stat()
        value = expanded.read_text(encoding="utf-8").strip()
    except OSError as exc:
        raise CommandError("governance secret file could not be read") from exc
    if stat.S_IMODE(metadata.st_mode) & 0o077:
        raise CommandError("governance secret file must be readable only by its owner")
    if not value:
        raise CommandError("governance secret file is empty")
    return value


def _approved_roots() -> tuple[Path, ...]:
    raw = os.environ.get("VULNHUNTER_SOURCE_HUNT_ROOTS", str(settings.BASE_DIR))
    roots = tuple(Path(item).expanduser() for item in raw.split(os.pathsep) if item.strip())
    if not roots:
        raise CommandError("VULNHUNTER_SOURCE_HUNT_ROOTS does not contain an approved root")
    return roots


class Command(BaseCommand):
    help = "Run one exact, Groq-only attacker-first source-code hunt."

    def add_arguments(self, parser) -> None:
        parser.add_argument("--repo", required=True)
        parser.add_argument("--revision")
        parser.add_argument("--visibility", choices=("public", "private"), required=True)
        parser.add_argument("--permitted-path", action="append", default=[])
        parser.add_argument("--actor", required=True)
        parser.add_argument("--secret-file", type=Path, required=True)
        parser.add_argument("--approve-groq-source-processing", action="store_true")
        parser.add_argument("--model", default=settings.VULNHUNTER_GROQ_MODEL)

    def handle(self, *args, **options) -> None:
        if not settings.VULNHUNTER_GROQ_ENABLED:
            raise CommandError("Groq is disabled by configuration.")
        if not options["approve_groq_source_processing"]:
            raise CommandError(
                "source code is not transmitted until --approve-groq-source-processing is supplied"
            )
        secret = _secret_from_file(options["secret_file"])
        governance = GovernanceStore.from_path(Path(settings.VULNHUNTER_GOVERNANCE_DATABASE))
        governance.initialize()
        identity = authenticate_identity(
            governance,
            str(options["actor"]),
            secret,
            required_role="campaign_admin",
        )
        policy = SourceHuntPolicy(
            approved_roots=_approved_roots(),
            model=str(options["model"]),
            maximum_prompt_bytes=min(settings.VULNHUNTER_GROQ_MAX_INPUT_BYTES, 100_000),
            maximum_output_tokens=min(settings.VULNHUNTER_GROQ_MAX_OUTPUT_TOKENS, 4_000),
            timeout_seconds=min(settings.VULNHUNTER_GROQ_TIMEOUT_SECONDS, 180),
        )
        repository = Path(str(options["repo"]))
        snapshot = RepositorySnapshotBuilder(policy).build(
            repository,
            revision=options.get("revision"),
        )
        now = datetime.now(UTC)
        approval = RemoteSourceProcessingApproval.create(
            repository_id=snapshot.repository_id,
            revision=snapshot.revision,
            snapshot_sha256=snapshot.snapshot_sha256,
            visibility=RepositoryVisibility(str(options["visibility"])),
            permitted_paths=tuple(options["permitted_path"] or (".",)),
            approved_by=identity.reviewer_id,
            approved_at=now,
            expires_at=now + timedelta(minutes=30),
        )
        try:
            provider = GroqProvider.from_key_file(
                Path(settings.VULNHUNTER_GROQ_API_KEY_FILE),
                approved_models=(
                    settings.VULNHUNTER_GROQ_MODEL,
                    settings.VULNHUNTER_GROQ_FALLBACK_MODEL,
                ),
                api_base=settings.VULNHUNTER_GROQ_API_BASE,
            )
            report = GroqSourceHunt(connector=provider, policy=policy).run(
                repository,
                approval=approval,
                revision=snapshot.revision,
            )
        except (GroqProviderError, SourceHuntError, ValueError) as exc:
            raise CommandError(str(exc)) from exc
        store_root = Path(
            os.environ.get(
                "VULNHUNTER_SOURCE_HUNT_REPORT_ROOT",
                str(settings.BASE_DIR / ".local" / "source-hunt-reports"),
            )
        )
        destination = SourceHuntStore(store_root).save(report)
        survived = sum(
            1
            for item in report.candidates
            if item.capability is not None and item.capability.meaningful
        )
        self.stdout.write(
            self.style.SUCCESS(
                f"source hunt {report.report_id}: stage={report.stage.value} "
                f"surfaces={report.surfaces_examined} survived={survived} "
                f"model_calls={report.model_calls} report={destination}"
            )
        )
