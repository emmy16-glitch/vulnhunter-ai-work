"""Bounded coordinator for deterministic, non-executing web-hunter specialists."""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime
from typing import Protocol

from vulnhunter.actions.models import sha256_json
from vulnhunter.security import redact_text
from vulnhunter.web_hunters.deterministic import default_hunters
from vulnhunter.web_hunters.errors import WebHunterExecutionError
from vulnhunter.web_hunters.models import (
    HunterBudget,
    HunterContext,
    HunterExecutionSummary,
    HunterHypothesis,
    HunterRunResult,
    HunterRunStatus,
)
from vulnhunter.web_hunters.policy import build_hunter_context, validate_hypothesis
from vulnhunter.web_perception.models import WebPerceptionResult


class WebHunter(Protocol):
    hunter_id: str

    def applicable(self, context: HunterContext) -> bool: ...

    def analyze(self, context: HunterContext) -> tuple[HunterHypothesis, ...]: ...


class AdaptiveWebHunterCoordinator:
    """Route sanitized perception to bounded specialists and deduplicate suspicions."""

    def __init__(
        self,
        *,
        hunters: tuple[WebHunter, ...] | None = None,
        budget: HunterBudget | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        selected = hunters or tuple(default_hunters())
        if not selected:
            raise ValueError("at least one web hunter is required")
        hunter_ids = [hunter.hunter_id for hunter in selected]
        if len(hunter_ids) != len(set(hunter_ids)):
            raise ValueError("web hunter IDs must be unique")
        self.hunters = tuple(sorted(selected, key=lambda item: item.hunter_id))
        self.budget = budget or HunterBudget()
        self._clock = clock or (lambda: datetime.now(UTC))

    def run(self, perception: WebPerceptionResult) -> HunterRunResult:
        """Produce advisory hypotheses without creating network or execution authority."""

        context = build_hunter_context(perception)
        started_at = self._clock()
        hypotheses_by_fingerprint: dict[str, HunterHypothesis] = {}
        summaries: list[HunterExecutionSummary] = []
        dropped_total = 0

        for hunter in self.hunters:
            try:
                applicable = hunter.applicable(context)
            except Exception as exc:
                raise WebHunterExecutionError(
                    f"web hunter {hunter.hunter_id} applicability check failed: "
                    f"{redact_text(type(exc).__name__)}"
                ) from exc

            if not applicable:
                summaries.append(
                    HunterExecutionSummary(
                        hunter_id=hunter.hunter_id,
                        status=HunterRunStatus.ABSTAINED,
                        emitted_hypotheses=0,
                        dropped_hypotheses=0,
                    )
                )
                continue

            try:
                candidates = tuple(hunter.analyze(context))
            except Exception as exc:
                raise WebHunterExecutionError(
                    f"web hunter {hunter.hunter_id} failed closed: "
                    f"{redact_text(type(exc).__name__)}"
                ) from exc

            for candidate in candidates:
                validate_hypothesis(context, candidate)

            ordered = tuple(
                sorted(
                    candidates,
                    key=lambda item: (-item.priority_score, item.semantic_fingerprint),
                )
            )
            selected = ordered[: self.budget.maximum_hypotheses_per_hunter]
            dropped = len(ordered) - len(selected)

            emitted = 0
            for candidate in selected:
                if candidate.semantic_fingerprint in hypotheses_by_fingerprint:
                    dropped += 1
                    continue
                if len(hypotheses_by_fingerprint) >= self.budget.maximum_hypotheses:
                    dropped += 1
                    continue
                hypotheses_by_fingerprint[candidate.semantic_fingerprint] = candidate
                emitted += 1

            dropped_total += dropped
            summaries.append(
                HunterExecutionSummary(
                    hunter_id=hunter.hunter_id,
                    status=HunterRunStatus.COMPLETED,
                    emitted_hypotheses=emitted,
                    dropped_hypotheses=dropped,
                )
            )

        hypotheses = tuple(
            sorted(
                hypotheses_by_fingerprint.values(),
                key=lambda item: (-item.priority_score, item.hypothesis_id),
            )
        )
        completed_at = self._clock()
        payload = {
            "target_url": context.target_url,
            "perception_plan_sha256": context.perception_plan_sha256,
            "perception_evidence_sha256": context.perception_evidence_sha256,
            "graph_sha256": context.graph_sha256,
            "started_at": _json_datetime(started_at),
            "completed_at": _json_datetime(completed_at),
            "budget": self.budget.model_dump(mode="json"),
            "hypotheses": [item.model_dump(mode="json") for item in hypotheses],
            "hunter_summaries": [item.model_dump(mode="json") for item in summaries],
            "dropped_hypotheses": dropped_total,
        }
        return HunterRunResult(
            target_url=context.target_url,
            perception_plan_sha256=context.perception_plan_sha256,
            perception_evidence_sha256=context.perception_evidence_sha256,
            graph_sha256=context.graph_sha256,
            started_at=started_at,
            completed_at=completed_at,
            budget=self.budget,
            hypotheses=hypotheses,
            hunter_summaries=tuple(summaries),
            dropped_hypotheses=dropped_total,
            result_sha256=sha256_json(payload),
        )


def _json_datetime(value: datetime) -> str:
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")
