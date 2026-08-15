"""Deterministic root-cause related-occurrence sweep for Source Hunt V2."""

from __future__ import annotations

import hashlib
import json

from vulnhunter.source_hunt.intelligence_models import (
    RootCauseFingerprint,
    RootCauseOccurrence,
    RootCauseSweep,
)
from vulnhunter.source_hunt.models import (
    AttackSurface,
    CandidateDisposition,
    SourceCandidate,
    SourceHuntReport,
)


class RootCauseSweeper:
    def __init__(self, *, maximum_occurrences: int = 64) -> None:
        if not 1 <= maximum_occurrences <= 1_000:
            raise ValueError("maximum_occurrences is outside the approved range")
        self.maximum_occurrences = maximum_occurrences

    def build(
        self,
        report: SourceHuntReport,
        surfaces: tuple[AttackSurface, ...],
    ) -> tuple[RootCauseSweep, ...]:
        sweeps: list[RootCauseSweep] = []
        for candidate in report.candidates:
            if (
                candidate.falsification.disposition != CandidateDisposition.SURVIVED
                or candidate.capability is None
                or not candidate.capability.meaningful
            ):
                continue
            origin = self._origin_surface(candidate, surfaces)
            if origin is None or not origin.sink_kinds:
                continue
            fingerprint = self._fingerprint(candidate, origin)
            occurrences: list[RootCauseOccurrence] = []
            truncated = False
            for surface in surfaces:
                if surface.surface_id == origin.surface_id or not surface.sink_kinds:
                    continue
                if surface.sink_kinds[0] != fingerprint.sink_kind:
                    continue
                if len(occurrences) >= self.maximum_occurrences:
                    truncated = True
                    break
                occurrences.append(
                    RootCauseOccurrence(
                        surface_id=surface.surface_id,
                        entry_point=surface.entry_point,
                        sink=surface.reachable_sinks[0],
                        sink_kind=surface.sink_kinds[0],
                        same_guard_shape=len(surface.guards) == fingerprint.guard_count,
                    )
                )
            sweeps.append(
                RootCauseSweep(
                    candidate_id=candidate.candidate_id,
                    fingerprint=fingerprint,
                    occurrences=tuple(occurrences),
                    truncated=truncated,
                )
            )
        return tuple(sweeps)

    @staticmethod
    def _origin_surface(
        candidate: SourceCandidate,
        surfaces: tuple[AttackSurface, ...],
    ) -> AttackSurface | None:
        return next(
            (
                surface
                for surface in surfaces
                if surface.entry_point == candidate.hypothesis.entry_point
                and candidate.hypothesis.sink in surface.reachable_sinks
            ),
            None,
        )

    @staticmethod
    def _fingerprint(
        candidate: SourceCandidate,
        surface: AttackSurface,
    ) -> RootCauseFingerprint:
        canonical = {
            "vulnerability_class": candidate.hypothesis.vulnerability_class.strip().lower(),
            "sink_kind": surface.sink_kinds[0],
            "entry_kind": surface.entry_kind,
            "guard_count": len(surface.guards),
        }
        digest = hashlib.sha256(
            json.dumps(canonical, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()
        return RootCauseFingerprint(**canonical, fingerprint_sha256=digest)
