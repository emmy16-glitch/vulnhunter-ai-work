from __future__ import annotations

import getpass
import json
import os
import stat
import sys
from pathlib import Path

from django.conf import settings
from django.core.management.base import BaseCommand, CommandError

from vulnhunter.exceptions import GovernanceError
from vulnhunter.governance.service import authenticate_identity
from vulnhunter.governance.store import GovernanceStore
from vulnhunter.learning import (
    CandidateStatus,
    ControlledLearningError,
    ControlledLearningService,
    ControlledMemoryStore,
    ControlledMemoryStoreError,
    ReviewDecision,
)


def _read_governance_secret(secret_file: Path | None) -> str:
    if secret_file is None:
        if not sys.stdin.isatty():
            raise CommandError(
                "--secret-file is required when the learning command is not running interactively"
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


def _authenticated_learning_actor(*, actor: str, secret: str, action: str) -> str:
    store = GovernanceStore.from_path(Path(settings.VULNHUNTER_GOVERNANCE_DATABASE))
    store.initialize()
    identity = authenticate_identity(store, actor, secret)
    allowed_roles = {"campaign_admin"} if action == "promote" else {"campaign_admin", "reviewer"}
    if not allowed_roles.intersection(identity.roles):
        required = "campaign administrator" if action == "promote" else "reviewer"
        raise CommandError(f"the authenticated identity is not permitted to {action}; {required} role required")
    return identity.reviewer_id


class Command(BaseCommand):
    help = "Review, evaluate, and promote controlled-memory candidates."

    def add_arguments(self, parser) -> None:
        action = parser.add_mutually_exclusive_group(required=True)
        action.add_argument("--list", action="store_true", help="List learning candidates.")
        action.add_argument("--approve", metavar="CANDIDATE_ID")
        action.add_argument("--reject", metavar="CANDIDATE_ID")
        action.add_argument("--evaluate", metavar="CANDIDATE_ID")
        action.add_argument("--promote", metavar="CANDIDATE_ID")
        parser.add_argument("--actor", required=True)
        parser.add_argument(
            "--secret-file",
            type=Path,
            help="Owner-only file containing the governance secret. Omit only for a hidden prompt.",
        )
        parser.add_argument("--reason", default="")
        parser.add_argument("--status", choices=[item.value for item in CandidateStatus])
        parser.add_argument("--limit", type=int, default=100)

    def handle(self, *args, **options) -> None:
        root = Path(
            os.environ.get(
                "VULNHUNTER_LEARNING_ROOT",
                str(Path(settings.BASE_DIR) / ".local" / "controlled-memory"),
            )
        )
        action = (
            "list"
            if options["list"]
            else "review"
            if options["approve"] or options["reject"]
            else "evaluate"
            if options["evaluate"]
            else "promote"
        )
        try:
            actor = _authenticated_learning_actor(
                actor=str(options["actor"]).strip(),
                secret=_read_governance_secret(options.get("secret_file")),
                action=action,
            )
            store = ControlledMemoryStore(root)
            service = ControlledLearningService(store)
            if options["list"]:
                status = CandidateStatus(options["status"]) if options["status"] else None
                candidates = store.list_candidates(status=status, limit=int(options["limit"]))
                for candidate in candidates:
                    self.stdout.write(
                        json.dumps(
                            {
                                "candidate_id": candidate.candidate_id,
                                "kind": candidate.kind.value,
                                "status": candidate.status.value,
                                "source_run_id": candidate.source_run_id,
                                "content": candidate.content,
                            },
                            sort_keys=True,
                        )
                    )
                return

            if options["approve"] or options["reject"]:
                reason = str(options["reason"]).strip()
                if len(reason) < 8:
                    raise CommandError("--reason must explain the human review decision")
                candidate_id = options["approve"] or options["reject"]
                decision = ReviewDecision.APPROVE if options["approve"] else ReviewDecision.REJECT
                candidate = service.review(
                    candidate_id,
                    decision=decision,
                    reviewer_id=actor,
                    reason=reason,
                )
                self.stdout.write(
                    self.style.SUCCESS(f"{candidate.candidate_id} is now {candidate.status.value}.")
                )
                return
            if options["evaluate"]:
                result = service.evaluate(options["evaluate"], evaluator_id=actor)
                self.stdout.write(result.model_dump_json(indent=2))
                if not result.passed:
                    raise CommandError("candidate failed the controlled-memory evaluation gate")
                return
            candidate = service.promote(options["promote"], promoted_by=actor)
            self.stdout.write(
                self.style.SUCCESS(f"{candidate.candidate_id} was promoted for bounded retrieval.")
            )
        except (
            ControlledLearningError,
            ControlledMemoryStoreError,
            GovernanceError,
            OSError,
            ValueError,
        ) as exc:
            raise CommandError(str(exc)) from exc
