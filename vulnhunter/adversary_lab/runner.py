"""Safe synthetic runner for disposable adversary-emulation trials."""

from __future__ import annotations

import hashlib
import json
import shutil
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, field_validator

from vulnhunter.adversary_lab.models import LabPlan, LabTrialResult, TrialOutcome


class LabRunnerError(RuntimeError):
    """Raised when the synthetic lab cannot preserve its safety boundary."""


class LabWorkerPolicy(BaseModel):
    """Worker-owned policy; browser input cannot relax these controls."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    enabled: bool = False
    workspace_root: Path
    evidence_root: Path
    maximum_trials: int = 10
    network_mode: Literal["isolated-no-egress"] = "isolated-no-egress"
    synthetic_data_only: Literal[True] = True
    arbitrary_commands_allowed: Literal[False] = False
    public_targets_allowed: Literal[False] = False

    @field_validator("workspace_root", "evidence_root")
    @classmethod
    def absolute_paths_only(cls, value: Path) -> Path:
        expanded = value.expanduser()
        if not expanded.is_absolute():
            raise ValueError("lab worker paths must be absolute")
        return expanded

    @field_validator("maximum_trials")
    @classmethod
    def maximum_trials_is_bounded(cls, value: int) -> int:
        if not 1 <= value <= 10:
            raise ValueError("maximum_trials must be between one and ten")
        return value


class SyntheticScenarioRunner:
    """Execute only reviewed simulations against generated files and records."""

    def __init__(self, policy: LabWorkerPolicy) -> None:
        self.policy = policy
        self.workspace_root = self._prepare_root(policy.workspace_root)
        self.evidence_root = self._prepare_root(policy.evidence_root)

    @staticmethod
    def _prepare_root(path: Path) -> Path:
        lexical = path.expanduser().absolute()
        lexical.mkdir(parents=True, exist_ok=True)
        if lexical.is_symlink():
            raise LabRunnerError("lab root must not be a symbolic link")
        return lexical.resolve(strict=True)

    @staticmethod
    def _safe_child(root: Path, *parts: str) -> Path:
        candidate = root.joinpath(*parts).absolute()
        try:
            candidate.resolve(strict=False).relative_to(root)
        except ValueError as exc:
            raise LabRunnerError("lab path escaped the approved root") from exc
        return candidate

    def prepare(self, plan: LabPlan) -> Path:
        if not self.policy.enabled:
            raise LabRunnerError("the synthetic adversary lab is disabled by worker policy")
        if plan.maximum_trials > self.policy.maximum_trials:
            raise LabRunnerError("the signed plan exceeds the worker trial ceiling")
        if plan.plan_digest != plan.fingerprint():
            raise LabRunnerError("the signed lab plan digest does not match")
        lab_root = self._safe_child(self.workspace_root, plan.lab_id)
        if lab_root.exists():
            shutil.rmtree(lab_root)
        baseline = lab_root / "baseline"
        baseline.mkdir(parents=True, mode=0o700)
        self._build_baseline(plan, baseline)
        return lab_root

    def _build_baseline(self, plan: LabPlan, baseline: Path) -> None:
        metadata = {
            "lab_id": plan.lab_id,
            "assessment_id": plan.assessment_id,
            "finding_reference": plan.finding_reference,
            "scenario_id": plan.scenario_id,
            "synthetic_data_only": True,
            "network_mode": plan.network_mode,
        }
        (baseline / "lab-context.json").write_text(
            json.dumps(metadata, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        if plan.scenario_id == "synthetic-file-impact":
            generated = baseline / "generated-files"
            generated.mkdir()
            for index in range(1, 61):
                (generated / f"sample-{index:03d}.txt").write_text(
                    f"Synthetic lab record {index:03d}\n",
                    encoding="utf-8",
                )
        elif plan.scenario_id == "synthetic-auth-detection":
            (baseline / "synthetic-accounts.json").write_text(
                json.dumps(
                    {"accounts": ["lab-user-01", "lab-user-02"], "credentials": "synthetic"},
                    indent=2,
                )
                + "\n",
                encoding="utf-8",
            )
        elif plan.scenario_id == "internal-transfer-observation":
            source = baseline / "source"
            source.mkdir()
            records = [
                {"record_id": index, "value": f"synthetic-{index}"} for index in range(1, 51)
            ]
            (source / "records.json").write_text(
                json.dumps(records, indent=2) + "\n",
                encoding="utf-8",
            )
        elif plan.scenario_id == "service-control-observation":
            (baseline / "service-state.json").write_text(
                json.dumps({"service": "synthetic-api", "state": "running"}, indent=2) + "\n",
                encoding="utf-8",
            )
        else:
            raise LabRunnerError("the signed plan references an unsupported scenario")

    def restore_snapshot(self, plan: LabPlan) -> Path:
        lab_root = self._safe_child(self.workspace_root, plan.lab_id)
        baseline = lab_root / "baseline"
        if not baseline.is_dir() or baseline.is_symlink():
            raise LabRunnerError("the reviewed baseline snapshot is unavailable")
        working = lab_root / "working"
        if working.exists():
            shutil.rmtree(working)
        shutil.copytree(baseline, working, symlinks=False)
        return working

    def execute_trial(
        self,
        plan: LabPlan,
        *,
        trial_number: int,
        variation: str,
        started_at: datetime,
    ) -> LabTrialResult:
        working = self.restore_snapshot(plan)
        if trial_number > plan.maximum_trials or trial_number > self.policy.maximum_trials:
            raise LabRunnerError("trial number exceeds the signed plan")
        summary: dict[str, object]
        artifact_names: tuple[str, ...]
        if plan.scenario_id == "synthetic-file-impact":
            summary, artifact_names = self._file_impact(working, variation, trial_number)
        elif plan.scenario_id == "synthetic-auth-detection":
            summary, artifact_names = self._auth_detection(working, variation, trial_number)
        elif plan.scenario_id == "internal-transfer-observation":
            summary, artifact_names = self._internal_transfer(working, variation, trial_number)
        elif plan.scenario_id == "service-control-observation":
            summary, artifact_names = self._service_control(working, variation, trial_number)
        else:
            raise LabRunnerError("the signed plan references an unsupported scenario")

        completed_at = datetime.now(UTC)
        evidence_dir = self._safe_child(self.evidence_root, plan.lab_id)
        evidence_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        evidence_path = evidence_dir / f"trial-{trial_number:02d}.json"
        evidence_payload = {
            "schema_version": "1.0",
            "lab_id": plan.lab_id,
            "assessment_id": plan.assessment_id,
            "finding_reference": plan.finding_reference,
            "scenario_id": plan.scenario_id,
            "trial_number": trial_number,
            "variation": variation,
            "synthetic_data_only": True,
            "network_mode": "isolated-no-egress",
            "summary": summary,
        }
        serialized = json.dumps(evidence_payload, indent=2, sort_keys=True) + "\n"
        evidence_path.write_text(serialized, encoding="utf-8")
        evidence_path.chmod(0o600)
        digest = hashlib.sha256(serialized.encode()).hexdigest()
        return LabTrialResult(
            trial_number=trial_number,
            variation=variation,
            outcome=TrialOutcome.CONFIRMED,
            summary=str(summary["result"]),
            started_at=started_at,
            completed_at=completed_at,
            evidence_sha256=digest,
            artifact_names=(evidence_path.name, *artifact_names),
            snapshot_restored=True,
            metadata={
                "synthetic_data_only": True,
                "network_contacted": False,
                "arbitrary_command_used": False,
            },
        )

    @staticmethod
    def _file_impact(
        working: Path,
        variation: str,
        trial_number: int,
    ) -> tuple[dict[str, object], tuple[str, ...]]:
        generated = working / "generated-files"
        count = min(5 * trial_number, 50)
        selected = sorted(generated.glob("*.txt"))[:count]
        for source in selected:
            source.rename(source.with_suffix(".simulated"))
        manifest = working / "file-impact-manifest.json"
        manifest.write_text(
            json.dumps(
                {
                    "variation": variation,
                    "modified_generated_files": len(selected),
                    "operation": "extension-change-on-generated-test-files",
                },
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )
        return (
            {"result": f"Synthetic impact reproduced on {len(selected)} generated files."},
            (manifest.name,),
        )

    @staticmethod
    def _auth_detection(
        working: Path,
        variation: str,
        trial_number: int,
    ) -> tuple[dict[str, object], tuple[str, ...]]:
        auth_log = working / "synthetic-auth.log"
        auth_log.write_text(
            "\n".join(
                [
                    f"trial={trial_number} account=lab-user-01 outcome=failed source=lab-a",
                    f"trial={trial_number} account=lab-user-02 outcome=success source=lab-a",
                    f"variation={variation} detector=synthetic-auth-control observed=true",
                ]
            )
            + "\n",
            encoding="utf-8",
        )
        return (
            {"result": "Synthetic authentication pattern observed by the lab detection marker."},
            (auth_log.name,),
        )

    @staticmethod
    def _internal_transfer(
        working: Path,
        variation: str,
        trial_number: int,
    ) -> tuple[dict[str, object], tuple[str, ...]]:
        source = working / "source" / "records.json"
        sink = working / "internal-sink"
        sink.mkdir()
        destination = sink / f"trial-{trial_number:02d}-records.json"
        shutil.copy2(source, destination)
        source_digest = hashlib.sha256(source.read_bytes()).hexdigest()
        destination_digest = hashlib.sha256(destination.read_bytes()).hexdigest()
        manifest = working / "transfer-manifest.json"
        manifest.write_text(
            json.dumps(
                {
                    "variation": variation,
                    "source_sha256": source_digest,
                    "destination_sha256": destination_digest,
                    "internal_only": True,
                },
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )
        return (
            {
                "result": "Synthetic records reached the approved internal sink with matching hashes."
            },
            (manifest.name, destination.name),
        )

    @staticmethod
    def _service_control(
        working: Path,
        variation: str,
        trial_number: int,
    ) -> tuple[dict[str, object], tuple[str, ...]]:
        state_path = working / "service-state.json"
        state = json.loads(state_path.read_text(encoding="utf-8"))
        state.update(
            {
                "state": "stopped-simulated",
                "trial_number": trial_number,
                "variation": variation,
            }
        )
        state_path.write_text(json.dumps(state, indent=2) + "\n", encoding="utf-8")
        return (
            {"result": "Disposable synthetic service state changed and was recorded."},
            (state_path.name,),
        )

    def cleanup(self, plan: LabPlan) -> bool:
        lab_root = self._safe_child(self.workspace_root, plan.lab_id)
        if lab_root.exists():
            shutil.rmtree(lab_root)
        return not lab_root.exists()
