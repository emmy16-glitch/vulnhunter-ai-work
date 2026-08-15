"""Fail-closed exact-target OpenSandbox backend for passive Playwright perception."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from uuid import uuid4

from vulnhunter.scope.models import ApprovedTarget
from vulnhunter.scope.validator import Resolver, system_resolver
from vulnhunter.security import redact_text, redact_url
from vulnhunter.security_tools.execution_backend import OpenSandboxConnection
from vulnhunter.security_tools.opensandbox_supply_chain import (
    ApprovedWorkerRelease,
    canonical_json_bytes,
)
from vulnhunter.web_perception.errors import WebPerceptionError
from vulnhunter.web_perception.graph import build_surface_graph
from vulnhunter.web_perception.models import (
    BrowserPerceptionEvidence,
    BrowserPerceptionPolicy,
    PerceivedForm,
    PerceivedFormField,
    PerceivedNetworkRequest,
    PerceivedPage,
    WebPerceptionPlan,
    WebPerceptionResult,
)

_IMAGE_DIGEST = re.compile(r"^.+@sha256:[0-9a-f]{64}$")
_WORKER_EXECUTABLE = "/opt/vulnhunter/web_perception_worker.py"
_ROOT = "/tmp/vulnhunter/perception"
_PLAN = f"{_ROOT}/plan.json"
_RESULT = f"{_ROOT}/result.json"
_FIXED_COMMAND = f"python3 {_WORKER_EXECUTABLE} {_PLAN} {_RESULT}"
_MAX_EVIDENCE_BYTES = 5_000_000


@dataclass(frozen=True)
class PlaywrightOpenSandboxRuntimeSpec:
    """Immutable runtime settings for the passive browser worker."""

    image: str
    executable: str = _WORKER_EXECUTABLE
    cpu: str = "2"
    memory: str = "2Gi"
    uid: int = 65532
    gid: int = 65532

    def __post_init__(self) -> None:
        if _IMAGE_DIGEST.fullmatch(self.image) is None:
            raise ValueError("Playwright worker image must be pinned by SHA-256 digest")
        if self.executable != _WORKER_EXECUTABLE:
            raise ValueError("Playwright worker executable is fixed by policy")
        if self.uid <= 0 or self.gid <= 0:
            raise ValueError("Playwright worker must execute as a non-root uid/gid")
        if not self.cpu or not self.memory:
            raise ValueError("Playwright worker resource limits must not be empty")


class _OpenSandboxPlaywrightSdk:
    """Small OpenSandbox 0.1.15 seam with one exact allowed IPv4 destination."""

    def __init__(self, connection: OpenSandboxConnection) -> None:
        self.connection = connection

    def create(
        self,
        *,
        runtime: PlaywrightOpenSandboxRuntimeSpec,
        allowed_ip: str,
        lifetime_seconds: int,
        metadata: dict[str, str],
    ) -> object:
        try:
            from opensandbox import SandboxSync
            from opensandbox.config import ConnectionConfigSync
            from opensandbox.models.sandboxes import NetworkPolicy, NetworkRule
        except ImportError as exc:
            raise WebPerceptionError(
                "OpenSandbox support is not installed; install vulnhunter-ai[opensandbox]"
            ) from exc

        config = ConnectionConfigSync(
            domain=self.connection.domain,
            protocol=self.connection.protocol,
            request_timeout=timedelta(seconds=self.connection.request_timeout_seconds),
            use_server_proxy=self.connection.use_server_proxy,
        )
        return SandboxSync.create(
            runtime.image,
            connection_config=config,
            timeout=timedelta(seconds=lifetime_seconds),
            ready_timeout=timedelta(seconds=self.connection.ready_timeout_seconds),
            resource={"cpu": runtime.cpu, "memory": runtime.memory},
            network_policy=NetworkPolicy(
                defaultAction="deny",
                egress=[NetworkRule(action="allow", target=allowed_ip)],
            ),
            metadata=metadata,
            env={},
        )

    @staticmethod
    def make_directory(sandbox: object, path: str, *, mode: int) -> None:
        try:
            from opensandbox.models.filesystem import WriteEntry
        except ImportError as exc:
            raise WebPerceptionError("OpenSandbox filesystem models are unavailable") from exc
        sandbox.files.create_directories([WriteEntry(path=path, mode=_permission_mode(mode))])

    @staticmethod
    def write_file(
        sandbox: object,
        path: str,
        data: str | bytes,
        *,
        mode: int,
    ) -> None:
        sandbox.files.write_file(path, data, mode=_permission_mode(mode))

    @staticmethod
    def run_worker(
        sandbox: object,
        *,
        runtime: PlaywrightOpenSandboxRuntimeSpec,
        timeout_seconds: int,
    ) -> int:
        try:
            from opensandbox.models.execd import RunCommandOpts
        except ImportError as exc:
            raise WebPerceptionError("OpenSandbox command models are unavailable") from exc

        execution = sandbox.commands.run(
            _FIXED_COMMAND,
            opts=RunCommandOpts(
                working_directory=_ROOT,
                timeout=timedelta(seconds=timeout_seconds),
                uid=runtime.uid,
                gid=runtime.gid,
            ),
        )
        if execution.exit_code is None:
            detail = "no structured error"
            if execution.error is not None:
                name = str(execution.error.name).strip() or "ExecutionError"
                value = " ".join(str(execution.error.value).split())[:240]
                detail = f"{name}: {value}" if value else name
            raise WebPerceptionError(
                f"OpenSandbox Playwright worker returned no exit code ({detail})"
            )
        return execution.exit_code

    @staticmethod
    def read_bytes(sandbox: object, path: str) -> bytes:
        return sandbox.files.read_bytes(path)

    @staticmethod
    def destroy(sandbox: object) -> None:
        sandbox.destroy()


class OpenSandboxWebPerceptionBackend:
    """Collect passive structure-only browser evidence from one pinned lab target."""

    def __init__(
        self,
        *,
        runtime: PlaywrightOpenSandboxRuntimeSpec,
        release: ApprovedWorkerRelease,
        release_registry_sha256: str,
        release_key_id: str,
        connection: OpenSandboxConnection | None = None,
        resolver: Resolver = system_resolver,
        sdk: object | None = None,
    ) -> None:
        if release.worker_id != "playwright" or release.status != "approved":
            raise WebPerceptionError("Playwright runtime requires one approved signed release")
        if release.image != runtime.image:
            raise WebPerceptionError("Playwright runtime image does not match its approved release")
        self.runtime = runtime
        self.release = release
        self.release_registry_sha256 = release_registry_sha256
        self.release_key_id = release_key_id
        self.connection = connection or OpenSandboxConnection()
        self._resolver = resolver
        self._sdk = sdk or _OpenSandboxPlaywrightSdk(self.connection)

    def build_plan(
        self,
        target: ApprovedTarget,
        *,
        authorization_id: str,
        policy: BrowserPerceptionPolicy,
    ) -> WebPerceptionPlan:
        approved_addresses = tuple(sorted(set(target.resolved_addresses)))
        ipv4_addresses = [
            value for value in approved_addresses if ipaddress.ip_address(value).version == 4
        ]
        if not ipv4_addresses:
            raise WebPerceptionError("first Playwright worker requires an approved IPv4 target")

        return WebPerceptionPlan(
            request_id=f"perception-{uuid4().hex[:20]}",
            authorization_id=authorization_id,
            target_url=target.normalized_url,
            scheme=target.scheme,
            hostname=target.hostname,
            port=target.port,
            path_boundary=target.path,
            approved_addresses=approved_addresses,
            approved_ip=ipv4_addresses[0],
            policy=policy,
            runtime_image=self.runtime.image,
            runtime_release_id=self.release.release_id,
            runtime_sbom_sha256=self.release.sbom_sha256,
            runtime_provenance_sha256=self.release.provenance_sha256,
            runtime_source_commit=self.release.source_commit,
            runtime_release_registry_sha256=self.release_registry_sha256,
            runtime_release_key_id=self.release_key_id,
            runtime_github_provenance_attestation_sha256=(
                self.release.github_provenance_attestation_sha256
            ),
            runtime_github_sbom_attestation_sha256=(self.release.github_sbom_attestation_sha256),
            runtime_github_attestation_signer=self.release.github_attestation_signer,
        )

    def execute(
        self,
        target: ApprovedTarget,
        *,
        authorization_id: str,
        policy: BrowserPerceptionPolicy,
    ) -> WebPerceptionResult:
        """Create an immutable plan, revalidate DNS, and execute one sandbox."""

        plan = self.build_plan(
            target,
            authorization_id=authorization_id,
            policy=policy,
        )
        self._assert_release_identity(plan)
        _revalidate_plan_addresses(plan, resolver=self._resolver)

        started_at = datetime.now(UTC)
        sandbox = None
        failure: WebPerceptionError | None = None
        evidence: BrowserPerceptionEvidence | None = None
        try:
            sandbox = self._sdk.create(
                runtime=self.runtime,
                allowed_ip=plan.approved_ip,
                lifetime_seconds=_execution_timeout_seconds(policy) + 60,
                metadata={
                    "project": "vulnhunter",
                    "worker": "playwright",
                    "request": plan.request_id,
                },
            )
            self._sdk.make_directory(sandbox, _ROOT, mode=0o733)
            self._sdk.write_file(
                sandbox,
                _PLAN,
                json.dumps(
                    _worker_plan_payload(plan),
                    sort_keys=True,
                    separators=(",", ":"),
                ),
                mode=0o444,
            )
            worker_exit = self._sdk.run_worker(
                sandbox,
                runtime=self.runtime,
                timeout_seconds=_execution_timeout_seconds(policy),
            )
            if worker_exit != 0:
                raise WebPerceptionError(
                    "OpenSandbox Playwright worker failed before producing trusted evidence"
                )
            raw = self._sdk.read_bytes(sandbox, _RESULT)
            if len(raw) > _MAX_EVIDENCE_BYTES:
                raise WebPerceptionError("Playwright evidence exceeded the configured size limit")
            try:
                parsed = BrowserPerceptionEvidence.model_validate_json(raw)
            except ValueError as exc:
                raise WebPerceptionError("Playwright evidence failed schema validation") from exc
            evidence = _sanitize_evidence(parsed)
            if not evidence.pages:
                raise WebPerceptionError("Playwright perception returned no in-scope pages")
        except WebPerceptionError as exc:
            failure = exc
        except Exception as exc:
            failure = WebPerceptionError(
                f"Playwright perception failed closed: {type(exc).__name__}"
            )
            failure.__cause__ = exc
        finally:
            if sandbox is not None:
                try:
                    self._sdk.destroy(sandbox)
                except Exception as exc:
                    if failure is None:
                        raise WebPerceptionError(
                            f"OpenSandbox Playwright destruction failed: {type(exc).__name__}"
                        ) from exc

        if failure is not None:
            raise failure
        if evidence is None:
            raise WebPerceptionError("Playwright perception produced no evidence")

        safe_target = redact_url(target.normalized_url)
        graph = build_surface_graph(safe_target, evidence.pages)
        evidence_sha256 = hashlib.sha256(
            canonical_json_bytes(evidence.model_dump(mode="json"))
        ).hexdigest()
        return WebPerceptionResult(
            target_url=safe_target,
            started_at=started_at,
            completed_at=datetime.now(UTC),
            plan_sha256=plan.fingerprint(),
            evidence_sha256=evidence_sha256,
            runtime_image=plan.runtime_image,
            runtime_release_id=plan.runtime_release_id,
            runtime_release_key_id=plan.runtime_release_key_id,
            evidence=evidence,
            graph=graph,
        )

    def _assert_release_identity(self, plan: WebPerceptionPlan) -> None:
        expected = (
            self.runtime.image,
            self.release.release_id,
            self.release.sbom_sha256,
            self.release.provenance_sha256,
            self.release.source_commit,
            self.release_registry_sha256,
            self.release_key_id,
            self.release.github_provenance_attestation_sha256,
            self.release.github_sbom_attestation_sha256,
            self.release.github_attestation_signer,
        )
        actual = (
            plan.runtime_image,
            plan.runtime_release_id,
            plan.runtime_sbom_sha256,
            plan.runtime_provenance_sha256,
            plan.runtime_source_commit,
            plan.runtime_release_registry_sha256,
            plan.runtime_release_key_id,
            plan.runtime_github_provenance_attestation_sha256,
            plan.runtime_github_sbom_attestation_sha256,
            plan.runtime_github_attestation_signer,
        )
        if actual != expected:
            raise WebPerceptionError(
                "Playwright worker supply-chain identity changed after plan issuance"
            )


def _execution_timeout_seconds(policy: BrowserPerceptionPolicy) -> int:
    per_page = (policy.navigation_timeout_ms + policy.settle_time_ms) / 1_000
    return min(600, max(30, int(policy.maximum_pages * per_page) + 30))


def _worker_plan_payload(plan: WebPerceptionPlan) -> dict[str, object]:
    """Return the only browser-worker input; release metadata remains host-side."""

    return {
        "schema_version": 1,
        "target_url": plan.target_url,
        "scheme": plan.scheme,
        "hostname": plan.hostname,
        "port": plan.port,
        "path_boundary": plan.path_boundary,
        "approved_ip": plan.approved_ip,
        "policy": plan.policy.model_dump(mode="json"),
    }


def _revalidate_plan_addresses(plan: WebPerceptionPlan, *, resolver: Resolver) -> None:
    try:
        current = {str(ipaddress.ip_address(value)) for value in resolver(plan.hostname)}
    except (ValueError, OSError) as exc:
        raise WebPerceptionError("Playwright target DNS revalidation failed") from exc

    approved = set(plan.approved_addresses)
    if not current:
        raise WebPerceptionError("Playwright target resolved to no addresses")
    if not current.issubset(approved):
        raise WebPerceptionError("Playwright target DNS changed outside the authorized snapshot")
    if plan.approved_ip not in current:
        raise WebPerceptionError("Playwright pinned IPv4 disappeared during DNS revalidation")


def _sanitize_evidence(evidence: BrowserPerceptionEvidence) -> BrowserPerceptionEvidence:
    pages: list[PerceivedPage] = []
    for page in evidence.pages:
        forms = tuple(
            PerceivedForm(
                form_sha256=form.form_sha256,
                method=form.method,
                action_url=redact_url(form.action_url),
                fields=tuple(
                    PerceivedFormField(
                        name=redact_text(field.name)[:200],
                        input_type=redact_text(field.input_type)[:80],
                        required=field.required,
                    )
                    for field in form.fields
                ),
            )
            for form in page.forms
        )
        requests = tuple(
            PerceivedNetworkRequest(
                method=request.method,
                url=redact_url(request.url),
                resource_type=redact_text(request.resource_type)[:80],
                status_code=request.status_code,
            )
            for request in page.requests
        )
        pages.append(
            PerceivedPage(
                url=redact_url(page.url),
                depth=page.depth,
                status_code=page.status_code,
                dom_structure_sha256=page.dom_structure_sha256,
                links=tuple(redact_url(value) for value in page.links),
                scripts=tuple(redact_url(value) for value in page.scripts),
                forms=forms,
                requests=requests,
            )
        )
    return evidence.model_copy(update={"pages": tuple(pages)})


def _permission_mode(mode: int) -> int:
    if mode < 0 or mode > 0o7777:
        raise WebPerceptionError("OpenSandbox permission mode is outside the POSIX range")
    return int(format(mode, "o"), 10)
