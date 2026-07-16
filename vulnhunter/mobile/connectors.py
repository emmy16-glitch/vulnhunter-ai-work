"""Typed, non-executing contracts for complex Android analysis connectors."""

from __future__ import annotations

import re
from enum import StrEnum
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from vulnhunter.actions.models import sha256_json
from vulnhunter.mobile.models import MobileAnalysisProfile

_IDENTIFIER = re.compile(r"^[a-z0-9][a-z0-9._-]{1,127}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


class MobileConnectorType(StrEnum):
    ANDROGUARD = "androguard"
    MOBSF = "mobsf"
    GHIDRA = "ghidra"
    ADB = "adb"
    FRIDA = "frida"


class MobileConnectorRequest(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    request_id: str
    action_manifest_sha256: str
    connector: MobileConnectorType
    profile: MobileAnalysisProfile
    artifact_sha256: str
    artifact_path: Path
    output_directory: Path
    timeout_seconds: int = Field(default=900, ge=1, le=86_400)
    isolated_runtime_reference: str | None = None
    android_device_reference: str | None = None
    approved_script_id: str | None = None

    @field_validator("request_id")
    @classmethod
    def validate_identifier(cls, value: str) -> str:
        if _IDENTIFIER.fullmatch(value) is None:
            raise ValueError("request_id must be a stable lowercase identifier")
        return value

    @field_validator("action_manifest_sha256", "artifact_sha256")
    @classmethod
    def validate_sha256(cls, value: str) -> str:
        if _SHA256.fullmatch(value) is None:
            raise ValueError("digest must be a SHA-256 value")
        return value

    @field_validator("approved_script_id")
    @classmethod
    def validate_script_id(cls, value: str | None) -> str | None:
        if value is not None and _IDENTIFIER.fullmatch(value) is None:
            raise ValueError("approved_script_id must be a stable identifier")
        return value

    @model_validator(mode="after")
    def validate_runtime_requirements(self):
        dynamic_connector = self.connector in {
            MobileConnectorType.ADB,
            MobileConnectorType.FRIDA,
        }
        dynamic_profile = self.profile in {
            MobileAnalysisProfile.DYNAMIC,
            MobileAnalysisProfile.FULL,
        }
        if dynamic_connector and not dynamic_profile:
            raise ValueError("ADB and Frida require a dynamic mobile analysis profile")
        if dynamic_connector and not self.isolated_runtime_reference:
            raise ValueError("dynamic connectors require an isolated runtime reference")
        if dynamic_connector and not self.android_device_reference:
            raise ValueError("dynamic connectors require an Android device reference")
        if self.connector == MobileConnectorType.FRIDA and not self.approved_script_id:
            raise ValueError("Frida requires an approved named script identifier")
        return self


class MobileConnectorPlan(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    request_id: str
    connector: MobileConnectorType
    operations: tuple[str, ...] = Field(min_length=1)
    forbidden_operations: tuple[str, ...] = Field(min_length=1)
    artifact_sha256: str
    requires_approval: bool
    requires_isolation: bool
    output_directory: Path
    timeout_seconds: int
    plan_sha256: str


def build_mobile_connector_plan(request: MobileConnectorRequest) -> MobileConnectorPlan:
    operations = {
        MobileConnectorType.ANDROGUARD: (
            "parse-apk",
            "analyze-bytecode",
            "export-json",
        ),
        MobileConnectorType.MOBSF: (
            "upload-by-digest",
            "run-static-analysis",
            "export-json-report",
        ),
        MobileConnectorType.GHIDRA: (
            "import-native-library",
            "run-reviewed-headless-analysis",
            "export-symbol-report",
        ),
        MobileConnectorType.ADB: (
            "install-approved-apk",
            "inspect-package",
            "collect-bounded-logcat",
            "uninstall-approved-apk",
        ),
        MobileConnectorType.FRIDA: (
            "attach-approved-package",
            f"run-approved-script:{request.approved_script_id}",
            "collect-bounded-events",
            "detach",
        ),
    }[request.connector]
    forbidden = (
        "arbitrary-shell",
        "arbitrary-script",
        "host-execution",
        "persistence",
        "credential-extraction",
        "scope-bypass",
    )
    requires_isolation = request.connector in {
        MobileConnectorType.MOBSF,
        MobileConnectorType.GHIDRA,
        MobileConnectorType.ADB,
        MobileConnectorType.FRIDA,
    }
    requires_approval = request.connector in {
        MobileConnectorType.MOBSF,
        MobileConnectorType.GHIDRA,
        MobileConnectorType.ADB,
        MobileConnectorType.FRIDA,
    }
    unsigned = {
        "request_id": request.request_id,
        "connector": request.connector.value,
        "operations": operations,
        "forbidden_operations": forbidden,
        "artifact_sha256": request.artifact_sha256,
        "requires_approval": requires_approval,
        "requires_isolation": requires_isolation,
        "output_directory": str(request.output_directory),
        "timeout_seconds": request.timeout_seconds,
    }
    return MobileConnectorPlan(
        **unsigned,
        plan_sha256=sha256_json(unsigned),
    )
