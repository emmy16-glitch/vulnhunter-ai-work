"""Fixed shell-free command builders for governed tool profiles."""

from __future__ import annotations

from pathlib import Path

from vulnhunter.security_tools.catalog import SecurityToolCatalog
from vulnhunter.security_tools.models import (
    CommandPlan,
    SecurityToolRequest,
    ToolProfile,
    ToolTargetKind,
)
from vulnhunter.security_tools.targets import validate_tool_target


class ToolAdapterError(ValueError):
    pass


def _output_path(directory: Path, request_id: str, suffix: str) -> Path:
    resolved = directory.expanduser().resolve()
    resolved.mkdir(parents=True, exist_ok=True)
    candidate = (resolved / f"{request_id}{suffix}").resolve()
    try:
        candidate.relative_to(resolved)
    except ValueError as exc:
        raise ToolAdapterError("output path escapes its governed directory") from exc
    return candidate


def _output_directory(directory: Path, request_id: str, suffix: str) -> Path:
    candidate = _output_path(directory, request_id, suffix)
    if candidate.exists() and not candidate.is_dir():
        raise ToolAdapterError("planned output directory conflicts with an existing file")
    return candidate


def _ruleset_path(value: object) -> str:
    if not isinstance(value, str):
        raise ToolAdapterError("yara requires an absolute governed ruleset path")
    path = Path(value).expanduser()
    if not path.is_absolute() or path.is_symlink():
        raise ToolAdapterError("yara ruleset must be a non-symlink absolute path")
    resolved = path.resolve(strict=True)
    if not resolved.is_file() or resolved.suffix.lower() not in {".yar", ".yara"}:
        raise ToolAdapterError("yara ruleset must be an existing .yar or .yara file")
    return str(resolved)


def build_command_plan(
    request: SecurityToolRequest,
    *,
    executable: str,
    catalog: SecurityToolCatalog,
) -> CommandPlan:
    definition = catalog.get(request.tool_id)
    if request.profile not in definition.profiles:
        raise ToolAdapterError(
            f"{request.tool_id} does not support profile {request.profile.value}"
        )
    if request.target_kind not in definition.target_kinds:
        raise ToolAdapterError(
            f"{request.tool_id} does not accept target kind {request.target_kind.value}"
        )
    if definition.connector_only:
        raise ToolAdapterError(
            f"{request.tool_id} requires a dedicated connector and cannot run directly"
        )

    target = validate_tool_target(request.target, request.target_kind)
    out = request.output_directory
    outputs: tuple[Path, ...] = ()
    stdout_file: Path | None = None
    stderr_file: Path | None = None
    acceptable_return_codes = (0,)

    if request.tool_id == "nmap":
        output = _output_path(out, request.request_id, ".xml")
        argv = (
            executable,
            "-Pn",
            "-sV",
            "--version-light",
            "--max-retries",
            "1",
            "--host-timeout",
            f"{request.timeout_seconds}s",
            "-oX",
            str(output),
            target,
        )
        outputs = (output,)
    elif request.tool_id == "httpx":
        output = _output_path(out, request.request_id, ".jsonl")
        argv = (
            executable,
            "-u",
            target,
            "-json",
            "-silent",
            "-no-color",
            "-o",
            str(output),
        )
        outputs = (output,)
    elif request.tool_id == "nuclei":
        output = _output_path(out, request.request_id, ".jsonl")
        severity = str(request.parameters.get("severity", "info,low,medium,high,critical"))
        allowed = {"info", "low", "medium", "high", "critical", "unknown"}
        values = tuple(item.strip() for item in severity.split(",") if item.strip())
        if not values or any(item not in allowed for item in values):
            raise ToolAdapterError("nuclei severity contains an unsupported value")
        argv = (
            executable,
            "-u",
            target,
            "-jsonl",
            "-silent",
            "-no-color",
            "-severity",
            ",".join(values),
            "-o",
            str(output),
        )
        outputs = (output,)
    elif request.tool_id == "testssl":
        output = _output_path(out, request.request_id, ".json")
        argv = (
            executable,
            "--quiet",
            "--warnings",
            "batch",
            "--jsonfile",
            str(output),
            target,
        )
        outputs = (output,)
    elif request.tool_id == "trivy":
        output = _output_path(out, request.request_id, ".json")
        default_scan = "image" if request.target_kind == ToolTargetKind.CONTAINER_IMAGE else "fs"
        scan_type = str(request.parameters.get("scan_type", default_scan))
        if scan_type not in {"fs", "config", "image"}:
            raise ToolAdapterError("trivy scan_type must be fs, config, or image")
        if request.target_kind == ToolTargetKind.CONTAINER_IMAGE and scan_type != "image":
            raise ToolAdapterError("container image targets require trivy image mode")
        if request.target_kind == ToolTargetKind.LOCAL_PATH and scan_type == "image":
            raise ToolAdapterError("local path targets cannot use trivy image mode")
        argv = (
            executable,
            scan_type,
            "--format",
            "json",
            "--output",
            str(output),
            target,
        )
        outputs = (output,)
    elif request.tool_id == "bearer":
        output = _output_path(out, request.request_id, ".bearer.json")
        argv = (
            executable,
            "scan",
            target,
            "--format",
            "json",
            "--output",
            str(output),
            "--exit-code",
            "0",
        )
        outputs = (output,)
    elif request.tool_id == "bandit":
        output = _output_path(out, request.request_id, ".bandit.json")
        argv = (
            executable,
            "-r",
            target,
            "--format",
            "json",
            "--output",
            str(output),
            "--exit-zero",
            "--quiet",
        )
        outputs = (output,)
    elif request.tool_id == "detect-secrets":
        stdout_file = _output_path(out, request.request_id, ".detect-secrets.json")
        stderr_file = _output_path(out, request.request_id, ".stderr.txt")
        argv = (executable, "scan", target, "--all-files", "--slim")
        outputs = (stdout_file, stderr_file)
    elif request.tool_id == "gitleaks":
        output = _output_path(out, request.request_id, ".gitleaks.json")
        argv = (
            executable,
            "dir",
            target,
            "--no-banner",
            "--no-color",
            "--redact=100",
            "--report-format",
            "json",
            "--report-path",
            str(output),
            "--exit-code",
            "0",
            "--max-target-megabytes",
            "50",
            "--timeout",
            str(request.timeout_seconds),
        )
        outputs = (output,)
    elif request.tool_id == "syft":
        output = _output_path(out, request.request_id, ".syft.json")
        source = target
        if request.target_kind == ToolTargetKind.LOCAL_PATH:
            local = Path(target)
            source = f"dir:{target}" if local.is_dir() else f"file:{target}"
        argv = (
            executable,
            "scan",
            source,
            "--output",
            f"syft-json={output}",
            "--parallelism",
            "1",
            "--quiet",
        )
        outputs = (output,)
    elif request.tool_id == "grype":
        output = _output_path(out, request.request_id, ".grype.json")
        source = target
        if request.target_kind == ToolTargetKind.LOCAL_PATH:
            local = Path(target)
            source = f"dir:{target}" if local.is_dir() else f"file:{target}"
        argv = (
            executable,
            source,
            "--output",
            "json",
            "--file",
            str(output),
            "--quiet",
        )
        outputs = (output,)
    elif request.tool_id == "osv-scanner":
        stdout_file = _output_path(out, request.request_id, ".osv.json")
        stderr_file = _output_path(out, request.request_id, ".stderr.txt")
        argv = (executable, "scan", "source", "--format", "json", target)
        outputs = (stdout_file, stderr_file)
        acceptable_return_codes = (0, 1)
    elif request.tool_id == "capa":
        stdout_file = _output_path(out, request.request_id, ".capa.json")
        stderr_file = _output_path(out, request.request_id, ".stderr.txt")
        argv = (executable, "-j", target)
        outputs = (stdout_file, stderr_file)
    elif request.tool_id == "amass":
        output = _output_path(out, request.request_id, ".json")
        if target.startswith("*."):
            target = target[2:]
        argv = (
            executable,
            "enum",
            "-passive",
            "-d",
            target,
            "-json",
            str(output),
        )
        outputs = (output,)
    elif request.tool_id == "ffuf":
        output = _output_path(out, request.request_id, ".json")
        wordlist = request.parameters.get("wordlist")
        if not isinstance(wordlist, str) or not wordlist.startswith("/"):
            raise ToolAdapterError("ffuf requires an absolute governed wordlist path")
        if "FUZZ" not in target:
            raise ToolAdapterError("ffuf target must contain the FUZZ marker")
        argv = (
            executable,
            "-u",
            target,
            "-w",
            wordlist,
            "-of",
            "json",
            "-o",
            str(output),
            "-maxtime",
            str(request.timeout_seconds),
        )
        outputs = (output,)
    elif request.tool_id == "sqlmap":
        if request.profile != ToolProfile.VALIDATION:
            raise ToolAdapterError("sqlmap is restricted to validation profile")
        stdout_file = _output_path(out, request.request_id, ".stdout.txt")
        stderr_file = _output_path(out, request.request_id, ".stderr.txt")
        argv = (
            executable,
            "-u",
            target,
            "--batch",
            "--smart",
            "--level=1",
            "--risk=1",
            "--flush-session",
        )
        outputs = (stdout_file, stderr_file)
    elif request.tool_id == "apksigner":
        stdout_file = _output_path(out, request.request_id, ".signature.txt")
        stderr_file = _output_path(out, request.request_id, ".stderr.txt")
        argv = (executable, "verify", "--verbose", "--print-certs", target)
        outputs = (stdout_file, stderr_file)
    elif request.tool_id == "aapt2":
        stdout_file = _output_path(out, request.request_id, ".badging.txt")
        stderr_file = _output_path(out, request.request_id, ".stderr.txt")
        argv = (executable, "dump", "badging", target)
        outputs = (stdout_file, stderr_file)
    elif request.tool_id == "apktool":
        output = _output_directory(out, request.request_id, "-apktool")
        argv = (executable, "d", "--force", "--output", str(output), target)
        outputs = (output,)
    elif request.tool_id == "jadx":
        output = _output_directory(out, request.request_id, "-jadx")
        argv = (
            executable,
            "--deobf",
            "--show-bad-code",
            "--output-dir",
            str(output),
            target,
        )
        outputs = (output,)
    elif request.tool_id == "apkid":
        stdout_file = _output_path(out, request.request_id, ".apkid.json")
        stderr_file = _output_path(out, request.request_id, ".stderr.txt")
        argv = (executable, "--json", target)
        outputs = (stdout_file, stderr_file)
    elif request.tool_id == "yara":
        ruleset = _ruleset_path(request.parameters.get("ruleset"))
        stdout_file = _output_path(out, request.request_id, ".yara.txt")
        stderr_file = _output_path(out, request.request_id, ".stderr.txt")
        argv = (executable, "--recursive", ruleset, target)
        outputs = (stdout_file, stderr_file)
    elif request.tool_id == "radare2":
        stdout_file = _output_path(out, request.request_id, ".rabin2.json")
        stderr_file = _output_path(out, request.request_id, ".stderr.txt")
        argv = (executable, "-I", "-j", target)
        outputs = (stdout_file, stderr_file)
    else:
        raise ToolAdapterError(f"{request.tool_id} has no direct fixed command adapter")

    return CommandPlan(
        request_id=request.request_id,
        tool_id=request.tool_id,
        executable=executable,
        argv=argv,
        output_files=outputs,
        stdout_file=stdout_file,
        stderr_file=stderr_file,
        timeout_seconds=request.timeout_seconds,
        maximum_output_bytes=request.maximum_output_bytes,
        working_directory=request.output_directory.expanduser().resolve(),
        action_manifest_sha256=request.action_manifest_sha256,
        requires_approval=definition.approval_required,
        requires_isolation=definition.requires_isolation,
        action_class=definition.action_class,
        acceptable_return_codes=acceptable_return_codes,
    )
