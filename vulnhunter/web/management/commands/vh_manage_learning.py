from __future__ import annotations

import json
import os
from pathlib import Path

from django.conf import settings
from django.core.management.base import BaseCommand, CommandError

from vulnhunter.learning import (
    CandidateStatus,
    ControlledLearningError,
    ControlledLearningService,
    ControlledMemoryStore,
    ControlledMemoryStoreError,
    ReviewDecision,
)


class Command(BaseCommand):
    help = "Review, evaluate, and promote controlled-memory candidates."

    def add_arguments(self, parser) -> None:
        action = parser.add_mutually_exclusive_group(required=True)
        action.add_argument("--list", action="store_true", help="List learning candidates.")
        action.add_argument("--approve", metavar="CANDIDATE_ID")
        action.add_argument("--reject", metavar="CANDIDATE_ID")
        action.add_argument("--evaluate", metavar="CANDIDATE_ID")
        action.add_argument("--promote", metavar="CANDIDATE_ID")
        parser.add_argument("--actor", default="")
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
        try:
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

            actor = str(options["actor"]).strip()
            if not actor:
                raise CommandError("--actor is required for review, evaluation, and promotion")
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
        except (ControlledLearningError, ControlledMemoryStoreError, OSError, ValueError) as exc:
            raise CommandError(str(exc)) from exc
