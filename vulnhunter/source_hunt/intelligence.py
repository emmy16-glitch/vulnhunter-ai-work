"""Opt-in Source Hunt Intelligence V2 orchestration over the existing fail-closed core."""

from __future__ import annotations

from collections.abc import Callable, Iterable
from datetime import UTC, datetime
from pathlib import Path

from vulnhunter.providers import ProviderCapability
from vulnhunter.source_hunt.intelligence_models import (
    AnalysisCoverage,
    HunterRole,
    SecurityProofPlan,
    SourceHuntIntelligenceBundle,
    SpecialistAssignment,
)
from vulnhunter.source_hunt.models import (
    AttackSurface,
    CandidateDisposition,
    GroqHypothesis,
    RemoteSourceProcessingApproval,
    RepositorySnapshot,
    SourceCandidate,
    SourceHuntReport,
)
from vulnhunter.source_hunt.repository_intelligence import (
    LanguageInventoryBuilder,
    PythonRepositoryGraphBuilder,
)
from vulnhunter.source_hunt.service import (
    GroqSourceHunt,
    PythonAttackSurfaceIndexer,
    RepositorySnapshotBuilder,
    SourceHuntConnector,
    SourceHuntError,
    SourceHuntPolicy,
)
from vulnhunter.source_hunt.specialists import SpecialistPlanner, specialist_focus
from vulnhunter.source_hunt.sweep_v2 import RootCauseSweeper

__all__ = [
    "AnalysisCoverage",
    "HunterRole",
    "SecurityProofPlan",
    "SourceHuntV2",
]


class SourceHuntV2(GroqSourceHunt):
    """Add independent specialist passes without adding model authority."""

    def __init__(self, *, connector: SourceHuntConnector, policy: SourceHuntPolicy) -> None:
        super().__init__(connector=connector, policy=policy)
        self._assignments: dict[str, SpecialistAssignment] = {}
        self._graph_summary = None

    def run_with_intelligence(
        self,
        repository_root: Path,
        *,
        approval: RemoteSourceProcessingApproval,
        revision: str | None = None,
        cancelled: Callable[[], bool] | None = None,
    ) -> tuple[SourceHuntReport, SourceHuntIntelligenceBundle]:
        preflight = RepositorySnapshotBuilder(self.policy).build(repository_root, revision=revision)
        try:
            approval.validate_for(preflight)
        except ValueError as exc:
            raise SourceHuntError(str(exc)) from exc
        self._graph_summary = PythonRepositoryGraphBuilder(preflight).build()

        report = super().run(
            repository_root,
            approval=approval,
            revision=revision,
            cancelled=cancelled,
        )
        if report.snapshot.snapshot_sha256 != preflight.snapshot_sha256:
            raise SourceHuntError(
                "repository changed between the V2 graph preflight and source hunt"
            )
        surfaces = PythonAttackSurfaceIndexer(
            report.snapshot,
            maximum_path_depth=self.policy.maximum_path_depth,
        ).build()[: self.policy.maximum_surfaces]
        proof_plans = tuple(
            SecurityProofPlan.create(candidate=candidate, snapshot=report.snapshot)
            for candidate in iter_surviving_candidates(report)
            if candidate.remediation is not None
        )
        bundle = SourceHuntIntelligenceBundle.create(
            report_id=report.report_id,
            snapshot_sha256=report.snapshot.snapshot_sha256,
            specialist_assignments=tuple(
                self._assignments[key] for key in sorted(self._assignments)
            ),
            root_cause_sweeps=RootCauseSweeper().build(report, surfaces),
            proof_plans=proof_plans,
            graph_summary=self._graph_summary,
            language_inventory=LanguageInventoryBuilder.build(
                Path(report.snapshot.repository_root)
            ),
            created_at=datetime.now(UTC),
        )
        return report, bundle

    def _hunt(
        self,
        snapshot: RepositorySnapshot,
        surface: AttackSurface,
        *,
        approval: RemoteSourceProcessingApproval,
        cancelled: Callable[[], bool] | None,
    ) -> GroqHypothesis:
        assignment = SpecialistPlanner.assign(surface)
        self._assignments[surface.surface_id] = assignment
        hypotheses: list[tuple[int, HunterRole, GroqHypothesis]] = []
        for order, role in enumerate(assignment.independent_roles):
            envelope = {
                "task": (
                    "Act as one bounded independent source-code security specialist. "
                    "Determine whether attacker-controlled input traverses only the supplied "
                    "deterministic path to the supplied sink. Return evidence-bound JSON."
                ),
                "specialist_role": role.value,
                "specialist_focus": specialist_focus(role),
                "independence_rule": (
                    "Do not assume another specialist's conclusion. Do not invent files, paths, "
                    "execution, network activity, or framework behavior."
                ),
                "security_boundary": self._security_boundary(),
                "repository": self._snapshot_summary(snapshot),
                "repository_graph_summary": self._graph_summary.model_dump(mode="json"),
                "surface": surface.model_dump(mode="json"),
                "source_excerpts": self._source_excerpts(
                    snapshot,
                    self._surface_references(surface),
                    approval=approval,
                ),
                "required_schema": GroqHypothesis.model_json_schema(),
            }
            try:
                hypothesis = self._stage_model(
                    GroqHypothesis,
                    capability=ProviderCapability.ATTACK_PATH_ANALYSIS,
                    request_id=f"hunt-v2-{role.value[:16]}-{surface.surface_id[-12:]}",
                    envelope=envelope,
                    cancelled=cancelled,
                )
                self._validate_hypothesis(snapshot, surface, hypothesis)
            except SourceHuntError:
                continue
            hypotheses.append((order, role, hypothesis))
        if not hypotheses:
            raise SourceHuntError("all bounded Source Hunt V2 specialists abstained or failed")
        hypotheses.sort(key=lambda item: (-item[2].confidence, item[0], item[1].value))
        return hypotheses[0][2]


def iter_surviving_candidates(report: SourceHuntReport) -> Iterable[SourceCandidate]:
    return (
        candidate
        for candidate in report.candidates
        if candidate.falsification.disposition == CandidateDisposition.SURVIVED
        and candidate.capability is not None
        and candidate.capability.meaningful
    )
