from __future__ import annotations

import getpass
import json
import os
import stat
import sys
from pathlib import Path

from django.conf import settings
from django.core.management.base import BaseCommand, CommandError
from pydantic import TypeAdapter

from vulnhunter.exceptions import GovernanceError
from vulnhunter.governance.service import authenticate_identity
from vulnhunter.governance.store import GovernanceStore
from vulnhunter.source_hunt.benchmark_acceptance import (
    BenchmarkAcceptanceVerdict,
    SourceBenchmarkAcceptancePolicy,
)
from vulnhunter.source_hunt.controlled_corpus import (
    ControlledBenchmarkCampaignRunner,
    ControlledCorpusDraft,
    ControlledCorpusDraftBuilder,
    ControlledCorpusRelease,
    ControlledCorpusReleaseService,
    ControlledGroundTruthSpec,
    CorpusReviewAttestation,
    CorpusReviewLedger,
    CorpusReviewVerdict,
    ReviewedSourceBenchmarkSuite,
    ReviewedSourceBenchmarkSuiteBuilder,
)
from vulnhunter.source_hunt.models import SourceHuntReport
from vulnhunter.source_hunt.service import RepositorySnapshotBuilder, SourceHuntPolicy


def _read_secret(secret_file: Path | None) -> str:
    if secret_file is None:
        if not sys.stdin.isatty():
            raise CommandError(
                "--secret-file is required when corpus governance is not running interactively"
            )
        secret = getpass.getpass("Governance secret: ")
    else:
        candidate = secret_file.expanduser()
        try:
            if candidate.is_symlink():
                raise CommandError("--secret-file must not be a symbolic link")
            metadata = candidate.stat()
            if not stat.S_ISREG(metadata.st_mode):
                raise CommandError("--secret-file must reference a regular file")
            if stat.S_IMODE(metadata.st_mode) & 0o077:
                raise CommandError("--secret-file must be readable only by its owner")
            secret = candidate.read_text(encoding="utf-8").rstrip("\r\n")
        except OSError as exc:
            raise CommandError("the governance secret file could not be read safely") from exc
    if not secret:
        raise CommandError("the governance secret is empty")
    return secret


def _governance_store() -> GovernanceStore:
    store = GovernanceStore.from_path(Path(settings.VULNHUNTER_GOVERNANCE_DATABASE))
    store.initialize()
    return store


def _review_ledger() -> CorpusReviewLedger:
    default = Path(settings.BASE_DIR) / ".local" / "source-hunt-corpus-reviews"
    root = Path(os.environ.get("VULNHUNTER_SOURCE_HUNT_CORPUS_LEDGER_ROOT", str(default)))
    return CorpusReviewLedger(root)


def _corpus_roots() -> tuple[Path, ...]:
    default = Path(settings.BASE_DIR) / "tests" / "fixtures" / "source_hunt_controlled"
    raw = os.environ.get("VULNHUNTER_SOURCE_HUNT_CORPUS_ROOTS", str(default))
    roots = tuple(Path(item).expanduser() for item in raw.split(os.pathsep) if item.strip())
    if not roots:
        raise CommandError("VULNHUNTER_SOURCE_HUNT_CORPUS_ROOTS has no approved root")
    return roots


def _atomic_write_json(path: Path, value: object) -> None:
    destination = path.expanduser()
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_name(f".{destination.name}.tmp")
    temporary.write_text(
        json.dumps(value, sort_keys=True, indent=2) + "\n",
        encoding="utf-8",
    )
    temporary.replace(destination)


def _load_reports(
    directory: Path,
    suite_release: ReviewedSourceBenchmarkSuite,
) -> dict[str, SourceHuntReport]:
    reports: dict[str, SourceHuntReport] = {}
    for entry in suite_release.suite.entries:
        path = directory / f"{entry.corpus.corpus_id}.json"
        reports[entry.corpus.corpus_id] = SourceHuntReport.model_validate_json(
            path.read_text(encoding="utf-8")
        )
    return reports


def _require(options: dict[str, object], *names: str) -> None:
    missing = [name for name in names if not options.get(name)]
    if missing:
        rendered = ", ".join(f"--{name.replace('_', '-')}" for name in missing)
        raise CommandError(f"missing required arguments for this action: {rendered}")


class Command(BaseCommand):
    help = (
        "Prepare, independently review, release and evaluate controlled Source Hunt benchmark "
        "corpora. Fixture code is never executed and campaign evaluation performs no scan, "
        "model call or network request."
    )

    def add_arguments(self, parser) -> None:
        action = parser.add_mutually_exclusive_group(required=True)
        action.add_argument("--prepare", action="store_true")
        action.add_argument("--review", metavar="DRAFT_FILE")
        action.add_argument("--release-corpus", metavar="DRAFT_FILE")
        action.add_argument("--release-suite", action="store_true")
        action.add_argument("--run-campaign", metavar="SUITE_RELEASE_FILE")
        parser.add_argument("--actor", required=True)
        parser.add_argument("--secret-file", type=Path)
        parser.add_argument("--output", required=True, type=Path)
        parser.add_argument("--fixture-root", type=Path)
        parser.add_argument("--revision")
        parser.add_argument("--corpus-id")
        parser.add_argument("--spec-file", type=Path)
        parser.add_argument("--reviewer", action="append", default=[])
        parser.add_argument(
            "--decision",
            choices=[item.value for item in CorpusReviewVerdict],
        )
        parser.add_argument("--reason", default="")
        parser.add_argument("--corpus-release-file", action="append", type=Path, default=[])
        parser.add_argument("--suite-id")
        parser.add_argument("--policy-file", type=Path)
        parser.add_argument("--baseline-report-dir", type=Path)
        parser.add_argument("--candidate-report-dir", type=Path)
        parser.add_argument("--baseline-engine-revision")
        parser.add_argument("--candidate-engine-revision")

    def handle(self, *args, **options) -> None:
        try:
            secret = _read_secret(options.get("secret_file"))
            store = _governance_store()
            actor_id = str(options["actor"]).strip()
            if options["prepare"]:
                result = self._prepare(store, actor_id, secret, options)
            elif options["review"]:
                result = self._review(store, actor_id, secret, options)
            elif options["release_corpus"]:
                result = self._release_corpus(store, actor_id, secret, options)
            elif options["release_suite"]:
                result = self._release_suite(store, actor_id, secret, options)
            else:
                result = self._run_campaign(store, actor_id, secret, options)
            _atomic_write_json(options["output"], result.model_dump(mode="json"))
        except (GovernanceError, OSError, ValueError) as exc:
            raise CommandError(str(exc)) from exc

        if options["run_campaign"]:
            acceptance = result.acceptance_bundle.acceptance
            if acceptance.verdict != BenchmarkAcceptanceVerdict.ACCEPTED:
                reasons = "; ".join(acceptance.reasons) or "acceptance policy rejected candidate"
                raise CommandError(f"controlled Source Hunt benchmark rejected: {reasons}")
        self.stdout.write(self.style.SUCCESS(f"wrote {options['output']}"))

    def _prepare(self, store, actor_id, secret, options):
        _require(options, "fixture_root", "revision", "corpus_id", "spec_file")
        actor = authenticate_identity(store, actor_id, secret)
        reviewer_ids = tuple(str(item).strip() for item in options["reviewer"])
        if len(reviewer_ids) != 2:
            raise CommandError("--prepare requires exactly two --reviewer values")
        reviewers = tuple(store.get_identity(item) for item in reviewer_ids)
        specs = TypeAdapter(tuple[ControlledGroundTruthSpec, ...]).validate_json(
            options["spec_file"].read_text(encoding="utf-8")
        )
        policy = SourceHuntPolicy(approved_roots=_corpus_roots())
        snapshot = RepositorySnapshotBuilder(policy).build(
            options["fixture_root"],
            revision=str(options["revision"]),
        )
        return ControlledCorpusDraftBuilder().build(
            corpus_id=str(options["corpus_id"]),
            snapshot=snapshot,
            specs=specs,
            prepared_by=actor,
            assigned_reviewers=reviewers,
        )

    def _review(self, store, actor_id, secret, options):
        _require(options, "review", "decision")
        actor = authenticate_identity(store, actor_id, secret, required_role="reviewer")
        draft = ControlledCorpusDraft.model_validate_json(
            Path(options["review"]).read_text(encoding="utf-8")
        )
        attestation = CorpusReviewAttestation.create(
            draft=draft,
            reviewer=actor,
            verdict=CorpusReviewVerdict(options["decision"]),
            reason=str(options["reason"]).strip(),
        )
        _review_ledger().record(attestation)
        return attestation

    def _release_corpus(self, store, actor_id, secret, options):
        _require(options, "release_corpus")
        actor = authenticate_identity(store, actor_id, secret, required_role="campaign_admin")
        draft = ControlledCorpusDraft.model_validate_json(
            Path(options["release_corpus"]).read_text(encoding="utf-8")
        )
        reviews = _review_ledger().load_assigned(draft)
        identities = {
            binding.reviewer_id: store.get_identity(binding.reviewer_id)
            for binding in draft.assigned_reviewers
        }
        return ControlledCorpusReleaseService().release(
            draft=draft,
            reviews=reviews,
            reviewer_identities=identities,
            released_by=actor,
        )

    def _release_suite(self, store, actor_id, secret, options):
        _require(options, "suite_id")
        actor = authenticate_identity(store, actor_id, secret, required_role="campaign_admin")
        release_files = tuple(options["corpus_release_file"])
        if not release_files:
            raise CommandError("--release-suite requires at least one --corpus-release-file")
        releases = tuple(
            ControlledCorpusRelease.model_validate_json(path.read_text(encoding="utf-8"))
            for path in release_files
        )
        return ReviewedSourceBenchmarkSuiteBuilder().build(
            suite_id=str(options["suite_id"]),
            releases=releases,
            released_by=actor,
        )

    def _run_campaign(self, store, actor_id, secret, options):
        _require(
            options,
            "run_campaign",
            "policy_file",
            "baseline_report_dir",
            "candidate_report_dir",
            "baseline_engine_revision",
            "candidate_engine_revision",
        )
        actor = authenticate_identity(store, actor_id, secret, required_role="campaign_admin")
        suite_release = ReviewedSourceBenchmarkSuite.model_validate_json(
            Path(options["run_campaign"]).read_text(encoding="utf-8")
        )
        policy = SourceBenchmarkAcceptancePolicy.model_validate_json(
            options["policy_file"].read_text(encoding="utf-8")
        )
        return ControlledBenchmarkCampaignRunner().run(
            suite_release=suite_release,
            policy=policy,
            baseline_engine_revision=str(options["baseline_engine_revision"]),
            candidate_engine_revision=str(options["candidate_engine_revision"]),
            baseline_reports=_load_reports(options["baseline_report_dir"], suite_release),
            candidate_reports=_load_reports(options["candidate_report_dir"], suite_release),
            run_by=actor,
        )
