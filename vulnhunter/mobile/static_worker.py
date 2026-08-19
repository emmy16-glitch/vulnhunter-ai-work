"""Isolated, read-only static and native APK worker boundary."""

from __future__ import annotations

import json
import os
import re
import zipfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from vulnhunter.mobile.artifacts import MobileArtifactError, copy_artifact_for_analysis
from vulnhunter.mobile.intelligence import (
    MobileAnalysisIntelligence,
    build_mobile_intelligence,
)
from vulnhunter.mobile.layered_analysis import LayeredAnalysisError, analyze_package
from vulnhunter.mobile.models import MobileArtifactRecord
from vulnhunter.mobile.static_toolchain import (
    MobileStaticToolchain,
    MobileStaticToolchainError,
    MobileStaticWorkerPolicy,
    MobileToolCapture,
    ProgressCallback,
)

_ANALYSIS_REFERENCE = re.compile(r"^[a-z0-9][a-z0-9._-]{1,127}$")


class MobileStaticWorkerError(RuntimeError):
    """Raised when static mobile analysis cannot preserve its safety boundary."""


class MobileStaticAnalysisResult(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    artifact_id: str
    state: Literal["completed", "blocked", "failed"]
    captures: tuple[MobileToolCapture, ...] = ()
    candidate_observations: tuple[dict[str, object], ...] = ()
    intelligence: MobileAnalysisIntelligence | None = None
    layered_report: dict[str, object] | None = None
    layered_report_error: str | None = None
    completed_at: datetime
    reason: str = Field(min_length=3, max_length=500)


def _controlled_failure_reason(exc: BaseException) -> str:
    if isinstance(exc, MobileStaticToolchainError):
        detail = str(exc).strip() or "the static toolchain safety boundary was reached"
    elif isinstance(exc, MobileArtifactError):
        detail = str(exc).strip() or "the APK artifact failed integrity validation"
    elif isinstance(exc, zipfile.BadZipFile):
        detail = "the APK archive became unreadable during isolated inspection"
    elif isinstance(exc, ValueError):
        detail = "a validated worker input became invalid during isolated inspection"
    else:
        detail = f"an operating-system error prevented safe inspection ({type(exc).__name__})"
    detail = " ".join(detail.split())[:360]
    return f"Mobile static analysis stopped safely: {detail}."


class MobileStaticWorker:
    """Run fixed tools against a private APK copy; never execute the APK."""

    def __init__(self, policy: MobileStaticWorkerPolicy) -> None:
        self.policy = policy

    def analyze(
        self,
        record: MobileArtifactRecord,
        *,
        analysis_reference: str | None = None,
        progress_callback: ProgressCallback | None = None,
    ) -> MobileStaticAnalysisResult:
        now = datetime.now(UTC)
        if not self.policy.enabled:
            return MobileStaticAnalysisResult(
                artifact_id=record.artifact_id,
                state="blocked",
                completed_at=now,
                reason="Mobile static worker is disabled by worker policy.",
            )
        if (
            analysis_reference is not None
            and _ANALYSIS_REFERENCE.fullmatch(analysis_reference) is None
        ):
            return MobileStaticAnalysisResult(
                artifact_id=record.artifact_id,
                state="failed",
                completed_at=now,
                reason="Mobile static analysis failed closed: invalid analysis reference.",
            )
        workspace = self.policy.workspace_root / record.artifact_id
        if analysis_reference:
            workspace /= analysis_reference
        try:
            apk = copy_artifact_for_analysis(record, workspace)
            private_home = workspace / "home"
            private_home.mkdir(mode=0o700, exist_ok=True)
            self._emit(
                progress_callback,
                state="running",
                stage="ingest",
                detail=("APK identity was rebound to the ingested SHA-256 and copied read-only."),
                tools=self.policy.active_tools(),
            )
            layered_report: dict[str, object] | None = None
            layered_report_error: str | None = None
            self._emit(
                progress_callback,
                state="running",
                stage="layered_static",
                detail="Reconstructing package, DEX, native, network and evidence layers.",
            )
            try:
                layered_report = analyze_package(apk, artifact=record).model_dump(mode="json")
            except (OSError, LayeredAnalysisError, ValueError) as exc:
                layered_report_error = (
                    f"Layered static reconstruction was incomplete: {type(exc).__name__}."
                )
                self._emit(
                    progress_callback,
                    state="running",
                    stage="layered_static",
                    tool_state="failed",
                    detail=layered_report_error,
                )
            captures, observations = MobileStaticToolchain(self.policy).run(
                record=record,
                apk=apk,
                workspace=workspace,
                private_home=private_home,
                progress_callback=progress_callback,
            )
            intelligence = build_mobile_intelligence(
                artifact_sha256=record.sha256,
                observations=observations,
                captures=captures,
                layered_report=layered_report,
                planned_tools=self.policy.active_tools(),
                native_library_count=len(record.native_libraries),
            )
        except (
            OSError,
            MobileArtifactError,
            MobileStaticToolchainError,
            ValueError,
            zipfile.BadZipFile,
        ) as exc:
            reason = _controlled_failure_reason(exc)
            self._emit(
                progress_callback,
                state="failed",
                stage="worker",
                detail=reason,
            )
            return MobileStaticAnalysisResult(
                artifact_id=record.artifact_id,
                state="failed",
                completed_at=datetime.now(UTC),
                reason=reason,
            )
        result = MobileStaticAnalysisResult(
            artifact_id=record.artifact_id,
            state="completed",
            captures=captures,
            candidate_observations=observations,
            intelligence=intelligence,
            layered_report=layered_report,
            layered_report_error=layered_report_error,
            completed_at=datetime.now(UTC),
            reason="Read-only static and native APK inspection completed.",
        )
        self._write_exclusive(
            workspace / "static-analysis.json",
            result.model_dump_json(indent=2) + "\n",
        )
        if layered_report is not None:
            self._write_exclusive(
                workspace / "layered-analysis.json",
                json.dumps(layered_report, indent=2, sort_keys=True) + "\n",
            )
        completeness = (
            layered_report.get("completeness", {}).get("percentage")
            if layered_report is not None
            else None
        )
        report_detail = (
            f" Layered report completeness is {completeness:.2f}% with "
            f"{len(layered_report.get('gaps', ()))} gap(s)."
            if isinstance(completeness, (int, float)) and layered_report is not None
            else " Layered report was not available; the analysis-health gap is recorded."
        )
        self._emit(
            progress_callback,
            state="completed",
            stage="report",
            detail=(
                f"Collected {len(captures)} bounded tool receipt(s) and "
                f"{len(observations)} candidate observation(s).{report_detail}"
            ),
        )
        return result

    @staticmethod
    def _emit(callback: ProgressCallback | None, **payload: object) -> None:
        if callback is None:
            return
        callback({"at": datetime.now(UTC).isoformat(), **payload})

    @staticmethod
    def _write_exclusive(path: Path, content: str) -> None:
        descriptor = os.open(
            path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())


__all__ = [
    "MobileStaticAnalysisResult",
    "MobileStaticWorker",
    "MobileStaticWorkerError",
    "MobileStaticWorkerPolicy",
    "MobileToolCapture",
]
