"""Shell-free bounded executor for approved security-tool command plans."""

from __future__ import annotations

import hashlib
import os
import stat
import subprocess
import tempfile
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path

from vulnhunter.actions.models import sha256_json
from vulnhunter.security import redact_text
from vulnhunter.security_tools.adapters import build_command_plan
from vulnhunter.security_tools.catalog import SecurityToolCatalog
from vulnhunter.security_tools.models import (
    CommandPlan,
    SecurityToolRequest,
    ToolExecutionResult,
    ToolTargetKind,
)


class SecurityToolExecutionError(RuntimeError):
    pass


ExecutionAuthorizer = Callable[[CommandPlan, str], bool]


def _write_capture(path: Path | None, data: bytes) -> None:
    if path is None:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".part")
    temporary.write_bytes(data)
    os.chmod(temporary, 0o600)
    os.replace(temporary, path)


def _redact_capture(data: bytes, *, maximum_bytes: int, stream_name: str) -> bytes:
    redacted = redact_text(data.decode("utf-8", errors="replace")).encode("utf-8")
    if len(redacted) > maximum_bytes:
        raise SecurityToolExecutionError(
            f"Redacted tool {stream_name} exceeded the configured output limit."
        )
    return redacted


def _bounded_file_digest(path: Path, *, maximum_bytes: int) -> tuple[bytes, int]:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise SecurityToolExecutionError(
            f"Evidence artifact cannot be opened safely: {path}"
        ) from exc
    digest = hashlib.sha256()
    size = 0
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise SecurityToolExecutionError(f"Evidence artifact is not a regular file: {path}")
        with os.fdopen(descriptor, "rb", closefd=False) as handle:
            while chunk := handle.read(min(1024 * 1024, maximum_bytes - size + 1)):
                size += len(chunk)
                if size > maximum_bytes:
                    raise SecurityToolExecutionError(
                        f"Evidence artifact exceeds the configured output limit: {path}"
                    )
                digest.update(chunk)
    finally:
        os.close(descriptor)
    return digest.digest(), size


def _hash_artifact(path: Path, *, maximum_bytes: int) -> str:
    if path.is_symlink():
        raise SecurityToolExecutionError(f"Evidence artifact must not be a symbolic link: {path}")
    if path.is_file():
        digest, _ = _bounded_file_digest(path, maximum_bytes=maximum_bytes)
        return digest.hex()
    if path.is_dir():
        digest = hashlib.sha256()
        total_size = 0
        for directory, directory_names, file_names in os.walk(path, followlinks=False):
            directory_names.sort()
            file_names.sort()
            current = Path(directory)
            for name in directory_names:
                if (current / name).is_symlink():
                    raise SecurityToolExecutionError(
                        f"Evidence directory contains a symbolic link: {current / name}"
                    )
            for name in file_names:
                child = current / name
                if child.is_symlink():
                    raise SecurityToolExecutionError(
                        f"Evidence directory contains a symbolic link: {child}"
                    )
                relative = child.relative_to(path).as_posix().encode("utf-8")
                file_digest, file_size = _bounded_file_digest(
                    child,
                    maximum_bytes=maximum_bytes - total_size,
                )
                total_size += file_size
                digest.update(len(relative).to_bytes(8, "big"))
                digest.update(relative)
                digest.update(file_digest)
        return digest.hexdigest()
    raise SecurityToolExecutionError(f"Expected evidence artifact is missing: {path}")


def _read_bounded_capture(handle, *, maximum_bytes: int, stream_name: str) -> bytes:
    handle.flush()
    handle.seek(0)
    data = handle.read(maximum_bytes + 1)
    if len(data) > maximum_bytes:
        raise SecurityToolExecutionError(
            f"Tool {stream_name} exceeded the configured output limit."
        )
    return data


class SecurityToolExecutor:
    """Execute only fixed adapter commands after external policy approval."""

    def __init__(
        self,
        *,
        catalog: SecurityToolCatalog,
        execution_enabled: bool = False,
        approved_output_root: Path,
        approved_input_roots: tuple[Path, ...] = (),
        isolated_runtime: bool = False,
        execution_authorizer: ExecutionAuthorizer | None = None,
    ) -> None:
        self.catalog = catalog
        self.execution_enabled = execution_enabled
        self.approved_output_root = approved_output_root.expanduser().resolve()
        self.approved_output_root.mkdir(parents=True, exist_ok=True)
        self.approved_input_roots = tuple(
            path.expanduser().resolve() for path in approved_input_roots
        )
        self.isolated_runtime = isolated_runtime
        self.execution_authorizer = execution_authorizer
        self._issued_plans: dict[str, CommandPlan] = {}
        if self.execution_enabled and self.execution_authorizer is None:
            raise SecurityToolExecutionError(
                "External execution cannot be enabled without a pre-execution authorization gate."
            )

    def plan(self, request: SecurityToolRequest) -> CommandPlan:
        availability = self.catalog.detect(request.tool_id)
        if not availability.available or not availability.executable_path:
            raise SecurityToolExecutionError(f"Security tool is not available: {request.tool_id}")
        if not availability.usable:
            detail = availability.error_summary or availability.status.value
            raise SecurityToolExecutionError(
                f"Security tool is installed but unusable: {request.tool_id}: {detail}"
            )
        output_directory = request.output_directory.expanduser().resolve()
        try:
            output_directory.relative_to(self.approved_output_root)
        except ValueError as exc:
            raise SecurityToolExecutionError(
                "Tool output directory is outside the approved evidence root."
            ) from exc
        if request.target_kind in {
            ToolTargetKind.LOCAL_PATH,
            ToolTargetKind.BINARY_FILE,
            ToolTargetKind.APK_FILE,
        }:
            target = Path(request.target).expanduser().resolve(strict=True)
            if not self.approved_input_roots:
                raise SecurityToolExecutionError(
                    "Local artifact execution requires an approved input root."
                )
            if not any(_is_within(target, root) for root in self.approved_input_roots):
                raise SecurityToolExecutionError(
                    "Local artifact target is outside all approved input roots."
                )
        plan = build_command_plan(
            request,
            executable=availability.executable_path,
            catalog=self.catalog,
        )
        self._issued_plans[plan.fingerprint()] = plan
        return plan

    def execute(
        self,
        plan: CommandPlan,
        *,
        approval_consumed: bool,
        execution_id: str,
    ) -> ToolExecutionResult:
        if not self.execution_enabled:
            raise SecurityToolExecutionError(
                "External security-tool execution is disabled by default."
            )
        fingerprint = plan.fingerprint()
        issued = self._issued_plans.get(fingerprint)
        if issued is None or issued != plan:
            raise SecurityToolExecutionError(
                "Command plan was not issued by this executor after governed request validation."
            )
        if self.execution_authorizer is None or not self.execution_authorizer(plan, execution_id):
            raise SecurityToolExecutionError(
                "Pre-execution authorization, scope, role, skill, and approval "
                "revalidation denied the plan."
            )
        if plan.requires_approval and not approval_consumed:
            raise SecurityToolExecutionError("Required approval was not consumed.")
        if plan.requires_isolation and not self.isolated_runtime:
            raise SecurityToolExecutionError(
                "This command requires an explicitly isolated execution runtime."
            )
        self._issued_plans.pop(fingerprint, None)
        plan.working_directory.mkdir(parents=True, exist_ok=True)
        started = datetime.now(UTC)
        timed_out = False
        # Temporary files avoid unbounded in-memory pipe buffering. Their contents
        # are accepted only after the configured byte limit is checked.
        with tempfile.TemporaryFile() as stdout_capture, tempfile.TemporaryFile() as stderr_capture:
            try:
                completed = subprocess.run(
                    plan.argv,
                    cwd=plan.working_directory,
                    env=self._minimal_environment(),
                    shell=False,
                    stdin=subprocess.DEVNULL,
                    stdout=stdout_capture,
                    stderr=stderr_capture,
                    timeout=plan.timeout_seconds,
                    check=False,
                )
                return_code = completed.returncode
            except subprocess.TimeoutExpired:
                timed_out = True
                return_code = 124
            stdout = _read_bounded_capture(
                stdout_capture,
                maximum_bytes=plan.maximum_output_bytes,
                stream_name="stdout",
            )
            stderr = _read_bounded_capture(
                stderr_capture,
                maximum_bytes=plan.maximum_output_bytes,
                stream_name="stderr",
            )

        stdout = _redact_capture(
            stdout,
            maximum_bytes=plan.maximum_output_bytes,
            stream_name="stdout",
        )
        stderr = _redact_capture(
            stderr,
            maximum_bytes=plan.maximum_output_bytes,
            stream_name="stderr",
        )
        _write_capture(plan.stdout_file, stdout)
        _write_capture(plan.stderr_file, stderr)

        output_files: list[str] = []
        output_hashes: dict[str, str] = {}
        for path in plan.output_files:
            if path.exists():
                resolved = path.resolve(strict=True)
                if not _is_within(resolved, self.approved_output_root) or not _is_within(
                    resolved, plan.working_directory
                ):
                    raise SecurityToolExecutionError(
                        f"Evidence artifact escaped the approved output root: {path}"
                    )
                output_files.append(str(resolved))
                output_hashes[str(resolved)] = _hash_artifact(
                    path,
                    maximum_bytes=plan.maximum_output_bytes,
                )

        finished = datetime.now(UTC)
        evidence = {
            "execution_id": execution_id,
            "request_id": plan.request_id,
            "tool_id": plan.tool_id,
            "command_plan_sha256": plan.fingerprint(),
            "return_code": return_code,
            "timed_out": timed_out,
            "output_hashes": output_hashes,
        }
        return ToolExecutionResult(
            execution_id=execution_id,
            request_id=plan.request_id,
            tool_id=plan.tool_id,
            command_plan_sha256=plan.fingerprint(),
            started_at=started,
            finished_at=finished,
            return_code=return_code,
            timed_out=timed_out,
            stdout_preview=redact_text(stdout.decode(errors="replace")[:4000]),
            stderr_preview=redact_text(stderr.decode(errors="replace")[:4000]),
            output_files=tuple(output_files),
            evidence_sha256=sha256_json(evidence),
            success=return_code in plan.acceptable_return_codes and not timed_out,
        )

    @staticmethod
    def _minimal_environment() -> dict[str, str]:
        allowed = ("PATH", "HOME", "LANG", "LC_ALL", "SSL_CERT_FILE", "SSL_CERT_DIR")
        return {key: os.environ[key] for key in allowed if key in os.environ}


def _is_within(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True
