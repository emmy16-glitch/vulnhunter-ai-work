"""Separate worker service for approved MobSF and disposable runtime jobs."""

from __future__ import annotations

import hashlib
import json
import os
from datetime import UTC, datetime
from pathlib import Path

from vulnhunter.mobile.artifacts import MobileArtifactIngestor
from vulnhunter.mobile.extension_spool import (
    MobileExtensionReceipt,
    MobileExtensionSpool,
    MobileExtensionSpoolError,
    SignedMobileExtensionJob,
)
from vulnhunter.mobile.mobsf import MobSFClient, MobSFError, MobSFServiceConfig
from vulnhunter.mobile.runtime import (
    MobileRuntimeError,
    MobileRuntimeExecutor,
    MobileRuntimePolicy,
    SignedMobileRuntimeApproval,
)


class MobileExtensionServiceError(RuntimeError):
    """Raised when approved extension execution fails its safety contract."""


class MobileExtensionQueueService:
    """Claim signed jobs, rebind artifacts and execute outside the web process."""

    def __init__(
        self,
        *,
        spool: MobileExtensionSpool,
        signing_key: bytes,
        runtime_approval_key: bytes,
        ingestor: MobileArtifactIngestor,
        result_root: Path,
        mobsf_policy_path: Path,
        runtime_policy_path: Path,
    ) -> None:
        self.spool = spool
        self.signing_key = signing_key
        self.runtime_approval_key = runtime_approval_key
        self.ingestor = ingestor
        lexical = result_root.expanduser().absolute()
        lexical.mkdir(parents=True, exist_ok=True)
        if lexical.is_symlink():
            raise MobileExtensionServiceError("extension result root must not be a symbolic link")
        self.result_root = lexical.resolve(strict=True)
        self.mobsf_policy_path = mobsf_policy_path
        self.runtime_policy_path = runtime_policy_path

    def run_once(self) -> MobileExtensionReceipt | None:
        claimed = self.spool.claim_next()
        if claimed is None:
            return None
        now = datetime.now(UTC)
        job: SignedMobileExtensionJob | None = None
        try:
            job = self.spool.load_claimed(
                claimed,
                key=self.signing_key,
                now=now,
            )
            artifact = next(
                (
                    item
                    for item in self.ingestor.list_records()
                    if item.artifact_id == job.artifact_id and item.sha256 == job.artifact_sha256
                ),
                None,
            )
            if artifact is None:
                raise MobileExtensionServiceError(
                    "Approved extension artifact no longer matches the ingested record."
                )
            if job.kind == "mobsf":
                evidence, full_result = self._run_mobsf(job, artifact.stored_path)
            else:
                evidence, full_result = self._run_runtime(job, artifact.stored_path)
            result_path = self._write_result(job, full_result)
            evidence = {
                **evidence,
                "private_result_sha256": self._sha256_file(result_path),
                "private_result_bytes": result_path.stat().st_size,
            }
            receipt = self._receipt(
                job,
                state="completed",
                reason=f"Approved {job.kind} extension completed.",
                evidence=evidence,
            )
            self.spool.finish(claimed, receipt=receipt, success=True)
            return receipt
        except (
            OSError,
            ValueError,
            MobileExtensionServiceError,
            MobileExtensionSpoolError,
            MobSFError,
            MobileRuntimeError,
        ) as exc:
            reason = f"Approved extension failed closed: {type(exc).__name__}."
            if job is None:
                self.spool.reject(claimed, reason=reason, now=now)
                raise MobileExtensionServiceError(str(exc)) from exc
            receipt = self._receipt(
                job,
                state="failed",
                reason=reason,
                evidence={},
            )
            self.spool.finish(claimed, receipt=receipt, success=False)
            raise MobileExtensionServiceError(str(exc)) from exc

    def _run_mobsf(
        self,
        job: SignedMobileExtensionJob,
        apk_path: Path,
    ) -> tuple[dict[str, object], dict[str, object]]:
        config = MobSFServiceConfig.from_path(self.mobsf_policy_path)
        result = MobSFClient(config).analyse(
            apk_path,
            artifact_sha256=job.artifact_sha256,
        )
        evidence = {
            "scan_hash": result.scan_hash,
            "report_sha256": result.report_sha256,
            "report_bytes": result.report_bytes,
            "report_keys": list(result.report_keys),
            "package_name": result.package_name,
            "app_name": result.app_name,
            "security_score": result.security_score,
        }
        return evidence, result.model_dump(mode="json")

    def _run_runtime(
        self,
        job: SignedMobileExtensionJob,
        apk_path: Path,
    ) -> tuple[dict[str, object], dict[str, object]]:
        policy = MobileRuntimePolicy.from_path(self.runtime_policy_path)
        try:
            approval = SignedMobileRuntimeApproval.model_validate(job.runtime_approval)
        except ValueError as exc:
            raise MobileExtensionServiceError("runtime approval payload is invalid") from exc
        result = MobileRuntimeExecutor(policy).execute(
            apk_path=apk_path,
            artifact_sha256=job.artifact_sha256,
            package_name=str(job.package_name),
            plan_sha256=job.plan_sha256,
            approval=approval,
            approval_key=self.runtime_approval_key,
        )
        if result.state != "completed":
            raise MobileRuntimeError(result.reason)
        actions = [
            {
                "action": capture.action,
                "return_code": capture.return_code,
                "output_sha256": capture.output_sha256,
                "duration_ms": capture.duration_ms,
            }
            for capture in result.captures
        ]
        frida_capture = next(
            (item for item in result.captures if item.action == "frida-inventory"),
            None,
        )
        structured = frida_capture.evidence if frida_capture is not None else {}
        evidence = {
            "runtime_id": result.runtime_id,
            "package_name": result.package_name,
            "device_identity": result.device_identity,
            "receipt_sha256": result.receipt_sha256,
            "actions": actions,
            "module_count": len(structured.get("modules", []))
            if isinstance(structured.get("modules"), list)
            else 0,
            "loaded_class_count": len(structured.get("loaded_classes", []))
            if isinstance(structured.get("loaded_classes"), list)
            else 0,
            "java_available": bool(structured.get("java_available")),
        }
        return evidence, result.model_dump(mode="json")

    def _write_result(
        self,
        job: SignedMobileExtensionJob,
        payload: dict[str, object],
    ) -> Path:
        directory = self.result_root / job.job_id
        directory.mkdir(mode=0o700, exist_ok=False)
        path = directory / f"{job.kind}-result.json"
        descriptor = os.open(
            path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        return path

    @staticmethod
    def _receipt(
        job: SignedMobileExtensionJob,
        *,
        state: str,
        reason: str,
        evidence: dict[str, object],
    ) -> MobileExtensionReceipt:
        completed_at = datetime.now(UTC)
        unsigned = {
            "schema_version": "1.0",
            "job_id": job.job_id,
            "kind": job.kind,
            "artifact_id": job.artifact_id,
            "state": state,
            "completed_at": completed_at.isoformat(),
            "reason": reason,
            "evidence": evidence,
        }
        return MobileExtensionReceipt(
            **unsigned,
            result_sha256=hashlib.sha256(
                json.dumps(unsigned, sort_keys=True, separators=(",", ":")).encode()
            ).hexdigest(),
        )

    @staticmethod
    def _sha256_file(path: Path) -> str:
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()


__all__ = [
    "MobileExtensionQueueService",
    "MobileExtensionServiceError",
]
