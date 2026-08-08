"""Signed append-only model registry with explicit activation and rollback authority."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
from collections.abc import Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal, Self

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

from vulnhunter.governance.models import canonical_sha256
from vulnhunter.security import redact_text

ModelState = Literal[
    "candidate",
    "validated",
    "approved",
    "shadow",
    "active",
    "degraded",
    "retired",
    "revoked",
    "rejected",
]
ModelAuthorityRole = Literal[
    "training_operator",
    "evaluation_reviewer",
    "model_promotion_authority",
    "deployment_operator",
    "incident_authority",
]
ModelEventType = Literal[
    "registered",
    "validated",
    "approved",
    "shadowed",
    "activated",
    "degraded",
    "retired",
    "revoked",
    "rejected",
    "rollback_restored",
]
LifecycleTransition = Literal[
    "validated",
    "approved",
    "shadow",
    "degraded",
    "retired",
    "revoked",
    "rejected",
]

_IDENTIFIER = re.compile(r"^[a-z0-9][a-z0-9._-]{1,127}$")
_COMMIT = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
_ZERO_HASH = "0" * 64
DETERMINISTIC_FALLBACK_REF = "deterministic:no-model"


class ModelRegistryBoundaryError(RuntimeError):
    """A model registry, promotion, activation or rollback invariant failed closed."""


class ModelRegistryPackage(BaseModel):
    """Complete immutable deployable model package submitted to the registry."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    schema_version: Literal[1] = 1
    model_id: str = Field(min_length=2, max_length=128)
    version: str = Field(min_length=1, max_length=64)
    task: str = Field(min_length=2, max_length=100)
    model_artifact_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    calibration_artifact_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    ood_policy_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    feature_schema_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    feature_extractor_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    training_release_ids: tuple[str, ...] = Field(min_length=1)
    training_release_sha256s: tuple[str, ...] = Field(min_length=1)
    partition_programme_id: str = Field(min_length=2, max_length=128)
    training_code_commit: str
    application_version: str = Field(min_length=1, max_length=100)
    dependency_lock_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    random_seeds: tuple[int, ...] = Field(min_length=1)
    candidate_selection_report_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    locked_evaluation_report_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    intended_use: str = Field(min_length=1, max_length=2_000)
    prohibited_uses: tuple[str, ...] = Field(min_length=1)
    limitations: tuple[str, ...] = Field(min_length=1)
    monitoring_policy_id: str = Field(min_length=2, max_length=128)
    training_operator_id: str = Field(min_length=2, max_length=64)
    package_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @field_validator(
        "model_id",
        "version",
        "task",
        "partition_programme_id",
        "monitoring_policy_id",
    )
    @classmethod
    def stable_identifiers(cls, value: str) -> str:
        if _IDENTIFIER.fullmatch(value) is None:
            raise ValueError("registry identifiers must be stable and path-safe")
        return value

    @field_validator("training_code_commit")
    @classmethod
    def exact_commit(cls, value: str) -> str:
        if _COMMIT.fullmatch(value) is None:
            raise ValueError("training code commit must be an exact SHA")
        return value

    @field_validator("training_release_ids")
    @classmethod
    def stable_release_ids(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if any(_IDENTIFIER.fullmatch(item) is None for item in value):
            raise ValueError("training release IDs must be stable and path-safe")
        if len(set(value)) != len(value):
            raise ValueError("training release IDs must be unique")
        return value

    @field_validator("training_release_sha256s")
    @classmethod
    def release_digests(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if any(re.fullmatch(r"[0-9a-f]{64}", item) is None for item in value):
            raise ValueError("training release digests must be SHA-256 values")
        return value

    @model_validator(mode="after")
    def release_lineage_is_aligned(self) -> Self:
        if len(self.training_release_ids) != len(self.training_release_sha256s):
            raise ValueError("training release IDs and digests must align")
        if len(set(self.random_seeds)) != len(self.random_seeds):
            raise ValueError("random seeds must be unique")
        return self

    @property
    def reference(self) -> str:
        return f"{self.model_id}@{self.version}"


def model_registry_package_sha256(
    value: ModelRegistryPackage | Mapping[str, object],
) -> str:
    """Return the canonical package digest without trusting its declared digest."""

    return canonical_sha256(value, exclude={"package_sha256"})


class ModelRegistryEvent(BaseModel):
    """One signed, hash-linked immutable model lifecycle event."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    schema_version: Literal[1] = 1
    sequence: int = Field(ge=1)
    model_ref: str = Field(min_length=4, max_length=200)
    package_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    event_type: ModelEventType
    from_state: ModelState | None = None
    state: ModelState
    actor_id: str = Field(min_length=2, max_length=64)
    actor_role: ModelAuthorityRole
    reason: str = Field(min_length=1, max_length=2_000)
    rollback_target_ref: str | None = Field(default=None, max_length=200)
    occurred_at: datetime
    previous_event_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    event_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    signature_hmac_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @field_validator("occurred_at")
    @classmethod
    def timezone_required(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("model registry timestamps must include a timezone")
        return value.astimezone(UTC)


class ActiveModelPointer(BaseModel):
    """Atomic task pointer to the one model currently selected for recommendations."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    schema_version: Literal[1] = 1
    task: str = Field(min_length=2, max_length=100)
    model_ref: str = Field(min_length=4, max_length=200)
    package_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    activated_at: datetime
    activation_event_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @field_validator("activated_at")
    @classmethod
    def timezone_required(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("active model timestamps must include a timezone")
        return value.astimezone(UTC)


def model_registry_event_sha256(
    value: ModelRegistryEvent | Mapping[str, object],
) -> str:
    """Hash event content while excluding its self-hash and detached signature."""

    return canonical_sha256(value, exclude={"event_sha256", "signature_hmac_sha256"})


def _sign_event(event_sha256: str, signing_key: bytes) -> str:
    return hmac.new(signing_key, event_sha256.encode("ascii"), hashlib.sha256).hexdigest()


def _now(value: datetime | None) -> datetime:
    current = value or datetime.now(UTC)
    if current.tzinfo is None or current.utcoffset() is None:
        raise ModelRegistryBoundaryError("model registry timestamps must include a timezone")
    return current.astimezone(UTC)


def _safe_reason(reason: str) -> str:
    value = redact_text(reason).strip()[:2_000]
    if not value:
        raise ModelRegistryBoundaryError("model lifecycle transition requires a reason")
    return value


class ModelRegistry:
    """Owner-private package store, signed lifecycle ledger and atomic active pointer."""

    def __init__(
        self,
        root: Path,
        *,
        signing_key: bytes,
        authority_secrets: Mapping[ModelAuthorityRole, bytes],
    ) -> None:
        if len(signing_key) < 32:
            raise ModelRegistryBoundaryError("registry signing key must contain at least 32 bytes")
        missing = {
            "training_operator",
            "evaluation_reviewer",
            "model_promotion_authority",
            "deployment_operator",
            "incident_authority",
        } - set(authority_secrets)
        if missing:
            raise ModelRegistryBoundaryError("all model governance authority secrets are required")
        if any(len(secret) < 16 for secret in authority_secrets.values()):
            raise ModelRegistryBoundaryError(
                "model authority secrets must contain at least 16 bytes"
            )
        self.root = root.expanduser().resolve()
        self.packages_root = self.root / "packages"
        self.events_root = self.root / "events"
        self.active_root = self.root / "active"
        self.signing_key = bytes(signing_key)
        self.authority_secrets = {
            role: bytes(secret) for role, secret in authority_secrets.items()
        }
        for directory in (self.root, self.packages_root, self.events_root, self.active_root):
            directory.mkdir(parents=True, exist_ok=True)
            os.chmod(directory, 0o700)

    @staticmethod
    def _ref_name(model_ref: str) -> str:
        if "@" not in model_ref:
            raise ModelRegistryBoundaryError("model reference must contain model ID and version")
        model_id, version = model_ref.split("@", 1)
        if _IDENTIFIER.fullmatch(model_id) is None or _IDENTIFIER.fullmatch(version) is None:
            raise ModelRegistryBoundaryError("model reference is not path-safe")
        return f"{model_id}--{version}"

    def _package_path(self, model_ref: str) -> Path:
        return self.packages_root / f"{self._ref_name(model_ref)}.json"

    def _events_path(self, model_ref: str) -> Path:
        return self.events_root / f"{self._ref_name(model_ref)}.jsonl"

    def _active_path(self, task: str) -> Path:
        if _IDENTIFIER.fullmatch(task) is None:
            raise ModelRegistryBoundaryError("model task is not path-safe")
        return self.active_root / f"{task}.json"

    def _authorize(
        self,
        role: ModelAuthorityRole,
        supplied_secret: bytes,
    ) -> None:
        expected = self.authority_secrets[role]
        if not hmac.compare_digest(expected, supplied_secret):
            raise ModelRegistryBoundaryError(f"{role} authority authentication failed")

    def package(self, model_ref: str) -> ModelRegistryPackage:
        path = self._package_path(model_ref)
        if not path.exists() or path.is_symlink():
            raise ModelRegistryBoundaryError("registered model package is unavailable")
        try:
            package = ModelRegistryPackage.model_validate_json(path.read_text(encoding="utf-8"))
        except (OSError, ValidationError) as exc:
            raise ModelRegistryBoundaryError("registered model package is invalid") from exc
        if package.reference != model_ref:
            raise ModelRegistryBoundaryError("registered package key does not match its identity")
        if model_registry_package_sha256(package) != package.package_sha256:
            raise ModelRegistryBoundaryError("registered model package integrity failed")
        return package

    def events(self, model_ref: str) -> tuple[ModelRegistryEvent, ...]:
        path = self._events_path(model_ref)
        if not path.exists():
            return ()
        if path.is_symlink():
            raise ModelRegistryBoundaryError("model registry ledger path is an unsafe symlink")
        try:
            events = tuple(
                ModelRegistryEvent.model_validate_json(line)
                for line in path.read_text(encoding="utf-8").splitlines()
                if line
            )
        except (OSError, ValidationError) as exc:
            raise ModelRegistryBoundaryError(
                "model registry ledger is unavailable or invalid"
            ) from exc

        package = self.package(model_ref)
        previous = _ZERO_HASH
        for index, event in enumerate(events, start=1):
            if event.sequence != index or event.model_ref != model_ref:
                raise ModelRegistryBoundaryError(
                    "model registry ledger sequence or identity is invalid"
                )
            if event.package_sha256 != package.package_sha256:
                raise ModelRegistryBoundaryError("model package identity changed inside its ledger")
            if event.previous_event_sha256 != previous:
                raise ModelRegistryBoundaryError("model registry ledger hash chain is invalid")
            if model_registry_event_sha256(event) != event.event_sha256:
                raise ModelRegistryBoundaryError("model registry event integrity failed")
            expected_signature = _sign_event(event.event_sha256, self.signing_key)
            if not hmac.compare_digest(expected_signature, event.signature_hmac_sha256):
                raise ModelRegistryBoundaryError("model registry event signature is invalid")
            if index == 1:
                if event.event_type != "registered" or event.from_state is not None:
                    raise ModelRegistryBoundaryError(
                        "model registry ledger must begin with registration"
                    )
            elif event.from_state != events[index - 2].state:
                raise ModelRegistryBoundaryError("model registry lifecycle state chain is invalid")
            previous = event.event_sha256
        return events

    def current(self, model_ref: str) -> ModelRegistryEvent | None:
        events = self.events(model_ref)
        return events[-1] if events else None

    def active(self, task: str) -> ActiveModelPointer | None:
        path = self._active_path(task)
        if not path.exists():
            return None
        if path.is_symlink():
            raise ModelRegistryBoundaryError("active model pointer is an unsafe symlink")
        try:
            pointer = ActiveModelPointer.model_validate_json(path.read_text(encoding="utf-8"))
        except (OSError, ValidationError) as exc:
            raise ModelRegistryBoundaryError("active model pointer is invalid") from exc
        if pointer.task != task:
            raise ModelRegistryBoundaryError("active model pointer task does not match its key")
        package = self.package(pointer.model_ref)
        if pointer.package_sha256 != package.package_sha256:
            raise ModelRegistryBoundaryError("active model pointer package digest does not match")
        current = self.current(pointer.model_ref)
        if current is None or current.state not in {"active", "degraded"}:
            raise ModelRegistryBoundaryError(
                "active model pointer does not reference an active lifecycle"
            )
        activation_events = {
            event.event_sha256 for event in self.events(pointer.model_ref)
        }
        if pointer.activation_event_sha256 not in activation_events:
            raise ModelRegistryBoundaryError("active model pointer activation event is unknown")
        return pointer

    def register_candidate(
        self,
        package: ModelRegistryPackage,
        *,
        actor_id: str,
        actor_secret: bytes,
        reason: str,
        now: datetime | None = None,
    ) -> ModelRegistryEvent:
        self._authorize("training_operator", actor_secret)
        if actor_id != package.training_operator_id:
            raise ModelRegistryBoundaryError(
                "candidate must be registered by its training operator"
            )
        expected = model_registry_package_sha256(package)
        if expected != package.package_sha256:
            raise ModelRegistryBoundaryError("model package digest does not match its content")
        path = self._package_path(package.reference)
        if path.exists() or self._events_path(package.reference).exists():
            raise ModelRegistryBoundaryError("model package is already registered")
        encoded = json.dumps(
            package.model_dump(mode="json"),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        )
        path.write_text(encoded + "\n", encoding="utf-8")
        os.chmod(path, 0o600)
        return self._append_event(
            package,
            event_type="registered",
            state="candidate",
            actor_id=actor_id,
            actor_role="training_operator",
            reason=reason,
            occurred_at=_now(now),
        )

    def transition(
        self,
        model_ref: str,
        *,
        state: LifecycleTransition,
        actor_id: str,
        actor_role: ModelAuthorityRole,
        actor_secret: bytes,
        reason: str,
        now: datetime | None = None,
    ) -> ModelRegistryEvent:
        self._authorize(actor_role, actor_secret)
        package = self.package(model_ref)
        current = self.current(model_ref)
        if current is None:
            raise ModelRegistryBoundaryError("model must be registered before lifecycle transition")
        required_role: dict[str, ModelAuthorityRole] = {
            "validated": "evaluation_reviewer",
            "approved": "model_promotion_authority",
            "shadow": "deployment_operator",
            "degraded": "incident_authority",
            "retired": "deployment_operator",
            "revoked": "incident_authority",
            "rejected": "model_promotion_authority",
        }
        if actor_role != required_role[state]:
            raise ModelRegistryBoundaryError(f"{state} transition requires {required_role[state]}")
        allowed: dict[ModelState, set[ModelState]] = {
            "candidate": {"validated", "rejected", "revoked"},
            "validated": {"approved", "rejected", "revoked"},
            "approved": {"shadow", "retired", "revoked"},
            "shadow": {"retired", "revoked"},
            "active": {"degraded", "retired", "revoked"},
            "degraded": {"retired", "revoked"},
            "retired": {"revoked"},
            "revoked": set(),
            "rejected": set(),
        }
        if state not in allowed[current.state]:
            raise ModelRegistryBoundaryError(
                f"model lifecycle cannot transition from {current.state} to {state}"
            )
        if state == "validated" and actor_id == package.training_operator_id:
            raise ModelRegistryBoundaryError("training operator cannot self-validate a candidate")
        if state == "approved":
            validator = next(
                (
                    event.actor_id
                    for event in reversed(self.events(model_ref))
                    if event.state == "validated"
                ),
                None,
            )
            if actor_id in {package.training_operator_id, validator}:
                raise ModelRegistryBoundaryError(
                    "promotion authority must be independent of training and evaluation"
                )

        clear_active = False
        if state in {"retired", "revoked"}:
            active_before = self.active(package.task)
            clear_active = (
                active_before is not None and active_before.model_ref == model_ref
            )

        event_type: ModelEventType = {
            "validated": "validated",
            "approved": "approved",
            "shadow": "shadowed",
            "degraded": "degraded",
            "retired": "retired",
            "revoked": "revoked",
            "rejected": "rejected",
        }[state]
        event = self._append_event(
            package,
            event_type=event_type,
            state=state,
            actor_id=actor_id,
            actor_role=actor_role,
            reason=reason,
            occurred_at=_now(now),
        )
        if clear_active:
            self._clear_active(package.task)
        return event

    def activate(
        self,
        model_ref: str,
        *,
        actor_id: str,
        actor_secret: bytes,
        rollback_target_ref: str,
        reason: str,
        now: datetime | None = None,
    ) -> ModelRegistryEvent:
        self._authorize("deployment_operator", actor_secret)
        package = self.package(model_ref)
        current = self.current(model_ref)
        if current is None or current.state != "shadow":
            raise ModelRegistryBoundaryError("only a shadow model may be activated")
        if not package.monitoring_policy_id:
            raise ModelRegistryBoundaryError("activation requires a monitoring policy")

        existing_active = self.active(package.task)
        if existing_active is None:
            if rollback_target_ref != DETERMINISTIC_FALLBACK_REF:
                raise ModelRegistryBoundaryError(
                    "first activation must retain the deterministic no-model fallback"
                )
        else:
            if rollback_target_ref != existing_active.model_ref:
                raise ModelRegistryBoundaryError(
                    "rollback target must be the exact current active model"
                )
            previous = self.package(existing_active.model_ref)
            self._append_event(
                previous,
                event_type="retired",
                state="retired",
                actor_id=actor_id,
                actor_role="deployment_operator",
                reason=f"Standby rollback target for activation of {model_ref}.",
                occurred_at=_now(now),
            )

        event = self._append_event(
            package,
            event_type="activated",
            state="active",
            actor_id=actor_id,
            actor_role="deployment_operator",
            reason=reason,
            occurred_at=_now(now),
            rollback_target_ref=rollback_target_ref,
        )
        self._write_active(
            ActiveModelPointer(
                task=package.task,
                model_ref=package.reference,
                package_sha256=package.package_sha256,
                activated_at=event.occurred_at,
                activation_event_sha256=event.event_sha256,
            )
        )
        return event

    def rollback(
        self,
        task: str,
        *,
        actor_id: str,
        actor_secret: bytes,
        reason: str,
        now: datetime | None = None,
    ) -> ModelRegistryEvent:
        self._authorize("deployment_operator", actor_secret)
        active = self.active(task)
        if active is None:
            raise ModelRegistryBoundaryError("there is no active model to roll back")
        package = self.package(active.model_ref)
        history = self.events(active.model_ref)
        activation = next(
            (event for event in reversed(history) if event.event_type == "activated"),
            None,
        )
        if activation is None or activation.rollback_target_ref is None:
            raise ModelRegistryBoundaryError("active model has no verified rollback target")
        current = history[-1]
        if current.state == "active":
            self._append_event(
                package,
                event_type="degraded",
                state="degraded",
                actor_id=actor_id,
                actor_role="deployment_operator",
                reason=f"Rollback initiated: {_safe_reason(reason)}",
                occurred_at=_now(now),
            )
        elif current.state != "degraded":
            raise ModelRegistryBoundaryError("only active or degraded models may be rolled back")

        target_ref = activation.rollback_target_ref
        if target_ref == DETERMINISTIC_FALLBACK_REF:
            self._clear_active(task)
            current_event = self.current(active.model_ref)
            if current_event is None:
                raise ModelRegistryBoundaryError("rollback source lifecycle disappeared")
            return current_event

        target = self.package(target_ref)
        if target.task != task:
            raise ModelRegistryBoundaryError("rollback target belongs to a different model task")
        target_current = self.current(target_ref)
        if target_current is None or target_current.state != "retired":
            raise ModelRegistryBoundaryError(
                "rollback target is not the preserved retired package"
            )
        restored = self._append_event(
            target,
            event_type="rollback_restored",
            state="active",
            actor_id=actor_id,
            actor_role="deployment_operator",
            reason=reason,
            occurred_at=_now(now),
            rollback_target_ref=DETERMINISTIC_FALLBACK_REF,
        )
        self._write_active(
            ActiveModelPointer(
                task=target.task,
                model_ref=target.reference,
                package_sha256=target.package_sha256,
                activated_at=restored.occurred_at,
                activation_event_sha256=restored.event_sha256,
            )
        )
        return restored

    def _append_event(
        self,
        package: ModelRegistryPackage,
        *,
        event_type: ModelEventType,
        state: ModelState,
        actor_id: str,
        actor_role: ModelAuthorityRole,
        reason: str,
        occurred_at: datetime,
        rollback_target_ref: str | None = None,
    ) -> ModelRegistryEvent:
        existing = self.events(package.reference)
        previous = existing[-1].event_sha256 if existing else _ZERO_HASH
        data: dict[str, object] = {
            "schema_version": 1,
            "sequence": len(existing) + 1,
            "model_ref": package.reference,
            "package_sha256": package.package_sha256,
            "event_type": event_type,
            "from_state": existing[-1].state if existing else None,
            "state": state,
            "actor_id": actor_id,
            "actor_role": actor_role,
            "reason": _safe_reason(reason),
            "rollback_target_ref": rollback_target_ref,
            "occurred_at": occurred_at,
            "previous_event_sha256": previous,
            "event_sha256": _ZERO_HASH,
            "signature_hmac_sha256": _ZERO_HASH,
        }
        data["event_sha256"] = model_registry_event_sha256(data)
        data["signature_hmac_sha256"] = _sign_event(
            str(data["event_sha256"]),
            self.signing_key,
        )
        event = ModelRegistryEvent.model_validate(data)
        path = self._events_path(package.reference)
        if path.exists() and path.is_symlink():
            raise ModelRegistryBoundaryError("model registry ledger path is an unsafe symlink")
        encoded = json.dumps(
            event.model_dump(mode="json"),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        )
        with path.open("a", encoding="utf-8", newline="\n") as handle:
            handle.write(encoded)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(path, 0o600)
        self.events(package.reference)
        return event

    def _write_active(self, pointer: ActiveModelPointer) -> None:
        path = self._active_path(pointer.task)
        if path.exists() and path.is_symlink():
            raise ModelRegistryBoundaryError("active model pointer is an unsafe symlink")
        temporary = path.with_suffix(".tmp")
        encoded = json.dumps(
            pointer.model_dump(mode="json"),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        )
        temporary.write_text(encoded + "\n", encoding="utf-8")
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
        os.chmod(path, 0o600)

    def _clear_active(self, task: str) -> None:
        path = self._active_path(task)
        if path.exists():
            if path.is_symlink():
                raise ModelRegistryBoundaryError("active model pointer is an unsafe symlink")
            path.unlink()


__all__ = [
    "ActiveModelPointer",
    "DETERMINISTIC_FALLBACK_REF",
    "LifecycleTransition",
    "ModelAuthorityRole",
    "ModelRegistry",
    "ModelRegistryBoundaryError",
    "ModelRegistryEvent",
    "ModelRegistryPackage",
    "ModelState",
    "model_registry_event_sha256",
    "model_registry_package_sha256",
]
