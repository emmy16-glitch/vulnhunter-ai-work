"""Private MobSF REST adapter for separately queued mobile analysis."""

from __future__ import annotations

import hashlib
import json
import stat
from pathlib import Path
from typing import Literal, Self
from urllib.parse import urlparse

import httpx
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class MobSFError(RuntimeError):
    """Raised when MobSF cannot preserve its private-service contract."""


class MobSFServiceConfig(BaseModel):
    """Owner-private MobSF endpoint and credential-file configuration."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    schema_version: Literal["1.0"] = "1.0"
    enabled: bool = False
    base_url: str = "http://127.0.0.1:8008"
    api_key_file: Path
    auth_header: Literal["Authorization", "X-Mobsf-Api-Key"] = "Authorization"
    timeout_seconds: int = Field(default=900, ge=5, le=3_600)
    maximum_response_bytes: int = Field(
        default=25_000_000,
        ge=16_384,
        le=100_000_000,
    )
    image: str = "opensecurity/mobile-security-framework-mobsf:v4.4.6"
    private_service_only: bool = True

    @field_validator("api_key_file")
    @classmethod
    def validate_key_path(cls, value: Path) -> Path:
        candidate = value.expanduser()
        if not candidate.is_absolute():
            raise ValueError("MobSF API key path must be absolute")
        return candidate

    @field_validator("base_url")
    @classmethod
    def validate_base_url(cls, value: str) -> str:
        parsed = urlparse(value)
        if parsed.scheme != "http" or parsed.username or parsed.password:
            raise ValueError("MobSF must use an unauthenticated loopback HTTP URL")
        if parsed.hostname not in {"127.0.0.1", "localhost", "::1"}:
            raise ValueError("MobSF must be bound to a loopback host")
        if parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
            raise ValueError("MobSF base URL must not contain a path, query or fragment")
        if parsed.port is None:
            raise ValueError("MobSF base URL must contain an explicit port")
        return value.rstrip("/")

    @model_validator(mode="after")
    def validate_contract(self) -> Self:
        if self.enabled and not self.private_service_only:
            raise ValueError("enabled MobSF service must remain private-only")
        if "@sha256:" in self.image:
            digest = self.image.rsplit("@sha256:", 1)[-1]
            if len(digest) != 64 or any(
                character not in "0123456789abcdef" for character in digest
            ):
                raise ValueError("MobSF image digest is invalid")
        elif not self.image.endswith(":v4.4.6"):
            raise ValueError("MobSF image must use the reviewed v4.4.6 release")
        return self

    @classmethod
    def from_path(cls, path: Path) -> MobSFServiceConfig:
        candidate = path.expanduser()
        if candidate.is_symlink():
            raise MobSFError("MobSF policy must not be a symbolic link")
        try:
            metadata = candidate.stat()
            content = candidate.read_text(encoding="utf-8")
        except OSError as exc:
            raise MobSFError("MobSF policy is unavailable") from exc
        if not stat.S_ISREG(metadata.st_mode) or stat.S_IMODE(metadata.st_mode) & 0o022:
            raise MobSFError("MobSF policy permissions are unsafe")
        try:
            return cls.model_validate_json(content)
        except ValueError as exc:
            raise MobSFError("MobSF policy is invalid") from exc

    def read_api_key(self) -> str:
        candidate = self.api_key_file
        if candidate.is_symlink():
            raise MobSFError("MobSF API key must not be a symbolic link")
        try:
            metadata = candidate.stat()
            value = candidate.read_text(encoding="utf-8").strip()
        except OSError as exc:
            raise MobSFError("MobSF API key is unavailable") from exc
        if not stat.S_ISREG(metadata.st_mode) or stat.S_IMODE(metadata.st_mode) & 0o077:
            raise MobSFError("MobSF API key permissions must be owner-only")
        if not 16 <= len(value) <= 512 or any(character.isspace() for character in value):
            raise MobSFError("MobSF API key is invalid")
        return value


class MobSFUploadReceipt(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    scan_hash: str = Field(min_length=8, max_length=128)
    scan_type: str = Field(min_length=1, max_length=64)
    file_name: str = Field(min_length=1, max_length=255)
    artifact_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


class MobSFEvidenceReceipt(BaseModel):
    """Bounded projection of a MobSF report, not a confirmed vulnerability list."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    scan_hash: str
    artifact_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    report_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    report_bytes: int = Field(ge=2)
    report_keys: tuple[str, ...]
    package_name: str | None = None
    app_name: str | None = None
    security_score: float | int | None = None
    report: dict[str, object]


class MobSFClient:
    """Upload, start and retrieve one scan from the private MobSF service."""

    def __init__(self, config: MobSFServiceConfig) -> None:
        if not config.enabled:
            raise MobSFError("MobSF service is disabled by policy")
        self.config = config

    def readiness(self) -> dict[str, object]:
        response = self._request("GET", "/")
        return {
            "ready": response.status_code == 200,
            "status_code": response.status_code,
            "base_url": self.config.base_url,
            "image": self.config.image,
        }

    def analyse(
        self,
        apk_path: Path,
        *,
        artifact_sha256: str,
    ) -> MobSFEvidenceReceipt:
        apk = self._verified_apk(apk_path, artifact_sha256=artifact_sha256)
        upload = self.upload(apk, artifact_sha256=artifact_sha256)
        self.scan(upload)
        report, encoded = self.report(upload.scan_hash)
        return MobSFEvidenceReceipt(
            scan_hash=upload.scan_hash,
            artifact_sha256=artifact_sha256,
            report_sha256=hashlib.sha256(encoded).hexdigest(),
            report_bytes=len(encoded),
            report_keys=tuple(sorted(str(key) for key in report)[:512]),
            package_name=self._optional_text(report.get("package_name") or report.get("package")),
            app_name=self._optional_text(report.get("app_name") or report.get("file_name")),
            security_score=self._optional_number(report.get("security_score")),
            report=report,
        )

    def upload(
        self,
        apk_path: Path,
        *,
        artifact_sha256: str,
    ) -> MobSFUploadReceipt:
        with apk_path.open("rb") as handle:
            response = self._request(
                "POST",
                "/api/v1/upload",
                files={
                    "file": (
                        apk_path.name,
                        handle,
                        "application/vnd.android.package-archive",
                    )
                },
            )
        payload, _ = self._json_payload(response)
        scan_hash = str(payload.get("hash") or "")
        scan_type = str(payload.get("scan_type") or payload.get("scanType") or "")
        file_name = str(payload.get("file_name") or payload.get("fileName") or apk_path.name)
        try:
            return MobSFUploadReceipt(
                scan_hash=scan_hash,
                scan_type=scan_type,
                file_name=file_name,
                artifact_sha256=artifact_sha256,
            )
        except ValueError as exc:
            raise MobSFError("MobSF upload response is invalid") from exc

    def scan(self, upload: MobSFUploadReceipt) -> dict[str, object]:
        response = self._request(
            "POST",
            "/api/v1/scan",
            data={
                "hash": upload.scan_hash,
                "scan_type": upload.scan_type,
                "file_name": upload.file_name,
            },
        )
        payload, _ = self._json_payload(response)
        return payload

    def report(self, scan_hash: str) -> tuple[dict[str, object], bytes]:
        response = self._request(
            "POST",
            "/api/v1/report_json",
            data={"hash": scan_hash},
        )
        return self._json_payload(response)

    def _request(self, method: str, path: str, **kwargs: object) -> httpx.Response:
        headers = dict(kwargs.pop("headers", {}) or {})
        headers[self.config.auth_header] = self.config.read_api_key()
        try:
            with httpx.Client(
                base_url=self.config.base_url,
                timeout=self.config.timeout_seconds,
                follow_redirects=False,
                trust_env=False,
            ) as client:
                with client.stream(method, path, headers=headers, **kwargs) as streamed:
                    content = bytearray()
                    for chunk in streamed.iter_bytes():
                        content.extend(chunk)
                        if len(content) > self.config.maximum_response_bytes:
                            raise MobSFError("MobSF response exceeded the configured boundary")
                    response = httpx.Response(
                        status_code=streamed.status_code,
                        headers=streamed.headers,
                        content=bytes(content),
                        request=streamed.request,
                    )
        except (httpx.HTTPError, OSError) as exc:
            raise MobSFError("MobSF request failed") from exc
        if response.status_code < 200 or response.status_code >= 300:
            raise MobSFError(f"MobSF returned HTTP {response.status_code}")
        return response

    @staticmethod
    def _json_payload(response: httpx.Response) -> tuple[dict[str, object], bytes]:
        encoded = bytes(response.content)
        try:
            payload = json.loads(encoded)
        except (TypeError, ValueError) as exc:
            raise MobSFError("MobSF response is not valid JSON") from exc
        if not isinstance(payload, dict):
            raise MobSFError("MobSF response must be a JSON object")
        return payload, encoded

    @staticmethod
    def _verified_apk(path: Path, *, artifact_sha256: str) -> Path:
        candidate = path.expanduser()
        if candidate.is_symlink():
            raise MobSFError("MobSF APK input must not be a symbolic link")
        try:
            resolved = candidate.resolve(strict=True)
            metadata = resolved.stat()
        except OSError as exc:
            raise MobSFError("MobSF APK input is unavailable") from exc
        if not stat.S_ISREG(metadata.st_mode) or resolved.suffix.casefold() != ".apk":
            raise MobSFError("MobSF input must be an APK file")
        digest = hashlib.sha256()
        with resolved.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        if digest.hexdigest() != artifact_sha256:
            raise MobSFError("MobSF APK input does not match the ingested artifact")
        return resolved

    @staticmethod
    def _optional_text(value: object) -> str | None:
        if value is None:
            return None
        text = " ".join(str(value).split())
        return text[:500] if text else None

    @staticmethod
    def _optional_number(value: object) -> float | int | None:
        if isinstance(value, bool) or not isinstance(value, (float, int)):
            return None
        return value


__all__ = [
    "MobSFClient",
    "MobSFEvidenceReceipt",
    "MobSFError",
    "MobSFServiceConfig",
    "MobSFUploadReceipt",
]
