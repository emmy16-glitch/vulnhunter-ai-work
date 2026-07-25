"""Isolated, read-only static and native APK worker boundary."""

from __future__ import annotations

import os
import re
import zipfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from vulnhunter.mobile.artifacts import MobileArtifactError, copy_artifact_for_analysis
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
    completed_at: datetime
    reason: str = Field(min_length=3, max_length=500)


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
                detail=(
                    "APK identity was rebound to the ingested SHA-256 and copied "
                    "read-only."
                ),
                tools=self.policy.active_tools(),
            )
            captures, observations = MobileStaticToolchain(self.policy).run(
                record=record,
                apk=apk,
                workspace=workspace,
                private_home=private_home,
                progress_callback=progress_callback,
            )
        except (
            OSError,
            MobileArtifactError,
            MobileStaticToolchainError,
            ValueError,
            zipfile.BadZipFile,
        ) as exc:
            self._emit(
                progress_callback,
                state="failed",
                stage="worker",
                detail=f"Static analysis failed closed: {type(exc).__name__}.",
            )
            return MobileStaticAnalysisResult(
                artifact_id=record.artifact_id,
                state="failed",
                completed_at=datetime.now(UTC),
                reason=f"Mobile static analysis failed closed: {type(exc).__name__}.",
            )
        result = MobileStaticAnalysisResult(
            artifact_id=record.artifact_id,
            state="completed",
            captures=captures,
            candidate_observations=observations,
            completed_at=datetime.now(UTC),
            reason="Read-only static and native APK inspection completed.",
        )
        self._write_exclusive(
            workspace / "static-analysis.json",
            result.model_dump_json(indent=2) + "\n",
        )
        self._emit(
            progress_callback,
            state="completed",
            stage="report",
            detail=(
                f"Collected {len(captures)} bounded tool receipt(s) and "
                f"{len(observations)} candidate observation(s)."
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
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_NOFOLLOW", 0),
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
