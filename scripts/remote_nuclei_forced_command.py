#!/usr/bin/env python3
"""Restricted host-side command for the VulnHunter remote Nuclei bridge.

The script accepts one bounded JSON request on stdin and returns one bounded JSON
result on stdout. It never accepts shell text, arbitrary arguments, targets,
templates, headers, credentials, or environment values from the caller.
"""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
import re
import resource
import signal
import stat
import subprocess
import sys
import tempfile
import time
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urlsplit

PROTOCOL_VERSION = "1.0"
MAX_REQUEST_BYTES = 65_536
SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
IDENTIFIER_PATTERN = re.compile(r"^[a-z0-9][a-z0-9._-]{1,127}$")
SEVERITY_PATTERN = re.compile(r"^[a-z][a-z0-9_-]{1,31}$")
_ACTIVE_PROCESS_GROUP: int | None = None


def canonical_json(value: object) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=str,
    ).encode("utf-8")


def sha256_json(value: object) -> str:
    return hashlib.sha256(canonical_json(value)).hexdigest()


def safe_text(value: object, maximum: int) -> str:
    text = str(value).replace("\r", " ").replace("\n", " ").strip()
    for marker in ("authorization:", "cookie:", "set-cookie:", "x-api-key:"):
        if marker in text.lower():
            return "redacted"
    return text[:maximum]


def fail(message: str) -> None:
    print(safe_text(message, 300) or "restricted worker failed", file=sys.stderr)
    raise SystemExit(1)


def require_absolute_regular(path_text: str, label: str, *, executable: bool = False) -> Path:
    path = Path(path_text).expanduser()
    if not path.is_absolute() or path.is_symlink():
        fail(f"{label} must be an absolute non-symlink path")
    try:
        metadata = path.stat()
    except OSError:
        fail(f"{label} is unavailable")
    if not stat.S_ISREG(metadata.st_mode):
        fail(f"{label} must be a regular file")
    if executable and not os.access(path, os.X_OK):
        fail(f"{label} is not executable")
    return path.resolve(strict=True)


def require_private_origin(value: str, *, loopback: bool) -> str:
    parsed = urlsplit(value)
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.hostname
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
        or parsed.username
        or parsed.password
    ):
        fail("worker target must be a fixed origin URL")
    try:
        address = ipaddress.ip_address(parsed.hostname)
    except ValueError:
        if loopback and parsed.hostname != "localhost":
            fail("transport target must be loopback-only")
        if not loopback:
            fail("logical target must use a literal private address")
    else:
        if loopback and not address.is_loopback:
            fail("transport target must be loopback-only")
        if not loopback and (
            not address.is_private or address.is_loopback or address.is_link_local
        ):
            fail("logical target must be an approved private laboratory address")
    return value.rstrip("/")


def read_policy(path: Path) -> dict[str, object]:
    if path.is_symlink():
        fail("host worker policy must not be a symbolic link")
    try:
        metadata = path.stat()
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        fail("host worker policy is unavailable or invalid")
    if not stat.S_ISREG(metadata.st_mode) or stat.S_IMODE(metadata.st_mode) & 0o022:
        fail("host worker policy must be an owner-controlled regular file")
    if not isinstance(payload, dict) or payload.get("schema_version") != PROTOCOL_VERSION:
        fail("host worker policy schema is unsupported")
    if payload.get("enabled") is not True:
        fail("host worker policy is disabled")
    worker_id = payload.get("worker_id")
    if not isinstance(worker_id, str) or IDENTIFIER_PATTERN.fullmatch(worker_id) is None:
        fail("host worker identity is malformed")
    for key in ("template_sha256",):
        value = payload.get(key)
        if not isinstance(value, str) or SHA256_PATTERN.fullmatch(value) is None:
            fail(f"{key} must be a SHA-256 digest")
    payload["logical_target"] = require_private_origin(
        str(payload.get("logical_target", "")), loopback=False
    )
    payload["transport_target"] = require_private_origin(
        str(payload.get("transport_target", "")), loopback=True
    )
    payload["nuclei_executable"] = str(
        require_absolute_regular(
            str(payload.get("nuclei_executable", "")),
            "Nuclei executable",
            executable=True,
        )
    )
    template = require_absolute_regular(
        str(payload.get("template_path", "")), "reviewed Nuclei template"
    )
    if hashlib.sha256(template.read_bytes()).hexdigest() != payload["template_sha256"]:
        fail("reviewed Nuclei template digest mismatch")
    payload["template_path"] = str(template)
    replay_root = Path(str(payload.get("replay_root", ""))).expanduser()
    if not replay_root.is_absolute() or replay_root.is_symlink():
        fail("replay_root must be an absolute non-symlink path")
    replay_root.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(replay_root, 0o700)
    payload["replay_root"] = str(replay_root.resolve(strict=True))
    return payload


def read_request() -> dict[str, object]:
    raw = sys.stdin.buffer.read(MAX_REQUEST_BYTES + 1)
    if len(raw) > MAX_REQUEST_BYTES:
        fail("remote worker request exceeded the input limit")
    try:
        request = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        fail("remote worker request is invalid JSON")
    if not isinstance(request, dict):
        fail("remote worker request must be an object")
    expected_keys = {
        "schema_version",
        "operation",
        "request_id",
        "worker_id",
        "logical_target",
        "transport_target",
        "engine_version",
        "template_sha256",
        "timeout_seconds",
        "maximum_candidates",
        "issued_at",
        "request_digest",
    }
    if set(request) != expected_keys:
        fail("remote worker request fields are not permitted")
    supplied_digest = request.get("request_digest")
    if not isinstance(supplied_digest, str) or SHA256_PATTERN.fullmatch(supplied_digest) is None:
        fail("request_digest is malformed")
    unsigned = {key: value for key, value in request.items() if key != "request_digest"}
    if sha256_json(unsigned) != supplied_digest:
        fail("remote worker request digest mismatch")
    try:
        issued_at = datetime.fromisoformat(str(request["issued_at"]).replace("Z", "+00:00"))
    except ValueError:
        fail("issued_at is invalid")
    age_seconds = abs((datetime.now(UTC) - issued_at.astimezone(UTC)).total_seconds())
    if issued_at.tzinfo is None or age_seconds > 300:
        fail("remote worker request is stale")
    return request


def validate_request(request: dict[str, object], policy: dict[str, object]) -> None:
    if request.get("schema_version") != PROTOCOL_VERSION:
        fail("remote worker protocol is unsupported")
    if request.get("operation") not in {"readiness", "scan"}:
        fail("remote worker operation is not permitted")
    if request.get("worker_id") != policy["worker_id"]:
        fail("remote worker identity mismatch")
    if request.get("logical_target") != policy["logical_target"]:
        fail("logical target differs from the host policy")
    if request.get("transport_target") != policy["transport_target"]:
        fail("transport target differs from the host policy")
    if request.get("engine_version") != policy.get("engine_version"):
        fail("Nuclei engine version differs from the host policy")
    if request.get("template_sha256") != policy["template_sha256"]:
        fail("Nuclei template digest differs from the host policy")
    timeout = request.get("timeout_seconds")
    maximum_candidates = request.get("maximum_candidates")
    if not isinstance(timeout, int) or not 1 <= timeout <= int(
        policy.get("maximum_timeout_seconds", 300)
    ):
        fail("requested timeout exceeds the host policy")
    if not isinstance(maximum_candidates, int) or not 0 <= maximum_candidates <= int(
        policy.get("maximum_candidates", 250)
    ):
        fail("requested candidate limit exceeds the host policy")


def reserve_request(request: dict[str, object], policy: dict[str, object]) -> None:
    if request["operation"] != "scan":
        return
    replay_root = Path(str(policy["replay_root"]))
    marker = replay_root / f"{request['request_digest']}.used"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(marker, flags, 0o600)
    except FileExistsError:
        fail("remote worker request replay was rejected")
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        handle.write(str(request["request_id"]) + "\n")
        handle.flush()
        os.fsync(handle.fileno())


def read_engine_version(policy: dict[str, object]) -> str:
    executable = str(policy["nuclei_executable"])
    environment = {
        "PATH": str(Path(executable).parent),
        "HOME": str(Path(str(policy["replay_root"])).parent),
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
    }
    try:
        result = subprocess.run(
            [executable, "-version"],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            check=False,
            timeout=10,
            env=environment,
        )
    except (OSError, subprocess.TimeoutExpired):
        fail("Nuclei readiness check failed")
    text = (result.stdout + result.stderr).decode("utf-8", errors="replace")
    expected = str(policy.get("engine_version", ""))
    if result.returncode != 0 or expected not in text:
        fail("installed Nuclei engine does not match the reviewed version")
    return expected


def normalize_identifier(value: object, fallback: str) -> str:
    normalized = re.sub(r"[^a-z0-9._-]+", "-", str(value).strip().lower()).strip("-._")
    if len(normalized) < 2 or IDENTIFIER_PATTERN.fullmatch(normalized[:127]) is None:
        return fallback
    return normalized[:127]


def parse_candidates(output: bytes, maximum: int) -> list[dict[str, object]]:
    candidates: list[dict[str, object]] = []
    for raw_line in output.splitlines():
        if len(candidates) >= maximum:
            break
        try:
            item = json.loads(raw_line.decode("utf-8", errors="strict"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            continue
        if not isinstance(item, dict):
            continue
        info = item.get("info") if isinstance(item.get("info"), dict) else {}
        template_id = normalize_identifier(
            item.get("template-id") or item.get("template_id"), "nuclei-match"
        )
        title = safe_text(info.get("name") or template_id, 500)
        if len(title) < 3:
            title = "Nuclei candidate match"
        severity = normalize_identifier(info.get("severity") or "info", "info")[:32]
        if SEVERITY_PATTERN.fullmatch(severity) is None:
            severity = "info"
        candidates.append(
            {
                "template_id": template_id,
                "title": title,
                "severity": severity,
                "matcher_name": safe_text(item.get("matcher-name") or "", 200),
                "protocol": normalize_identifier(item.get("type") or "http", "http")[:50],
            }
        )
    return candidates


def terminate_active(signum: int, _frame: object) -> None:
    del signum
    if _ACTIVE_PROCESS_GROUP is not None:
        try:
            os.killpg(_ACTIVE_PROCESS_GROUP, signal.SIGTERM)
        except ProcessLookupError:
            pass
    raise SystemExit(143)


def run_scan(
    request: dict[str, object], policy: dict[str, object]
) -> tuple[str, str, list[dict[str, object]]]:
    global _ACTIVE_PROCESS_GROUP
    executable = str(policy["nuclei_executable"])
    maximum_stdout = int(policy.get("maximum_stdout_bytes", 200_000))
    maximum_stderr = int(policy.get("maximum_stderr_bytes", 100_000))
    command = [
        executable,
        "-target",
        str(policy["transport_target"]),
        "-jsonl",
        "-silent",
        "-no-color",
        "-disable-update-check",
        "-no-interactsh",
        "-no-stdin",
        "-rate-limit",
        "1",
        "-concurrency",
        "1",
        "-bulk-size",
        "1",
        "-retries",
        "0",
        "-timeout",
        "5",
        "-templates",
        str(policy["template_path"]),
    ]
    environment = {
        "PATH": str(Path(executable).parent),
        "HOME": str(Path(str(policy["replay_root"])).parent),
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
    }
    timeout = int(request["timeout_seconds"])

    def apply_limits() -> None:
        maximum = max(maximum_stdout, maximum_stderr)
        resource.setrlimit(resource.RLIMIT_FSIZE, (maximum, maximum))
        resource.setrlimit(resource.RLIMIT_NOFILE, (32, 32))
        resource.setrlimit(resource.RLIMIT_CPU, (timeout + 1, timeout + 2))

    with tempfile.TemporaryDirectory(prefix="vulnhunter-nuclei-") as directory:
        stdout_path = Path(directory) / "stdout.jsonl"
        stderr_path = Path(directory) / "stderr.txt"
        with stdout_path.open("wb") as stdout_handle, stderr_path.open("wb") as stderr_handle:
            process = subprocess.Popen(
                command,
                stdin=subprocess.DEVNULL,
                stdout=stdout_handle,
                stderr=stderr_handle,
                env=environment,
                cwd=directory,
                start_new_session=True,
                preexec_fn=apply_limits,
            )
            _ACTIVE_PROCESS_GROUP = process.pid
            deadline = time.monotonic() + timeout
            timed_out = False
            while process.poll() is None:
                if time.monotonic() >= deadline:
                    timed_out = True
                    try:
                        os.killpg(process.pid, signal.SIGTERM)
                    except ProcessLookupError:
                        pass
                    time.sleep(0.2)
                    if process.poll() is None:
                        try:
                            os.killpg(process.pid, signal.SIGKILL)
                        except ProcessLookupError:
                            pass
                    break
                time.sleep(0.05)
            process.wait()
            _ACTIVE_PROCESS_GROUP = None
        stdout = stdout_path.read_bytes()[: maximum_stdout + 1]
        stderr = stderr_path.read_bytes()[: maximum_stderr + 1]

    if len(stdout) > maximum_stdout or len(stderr) > maximum_stderr:
        return "failed", "Nuclei output exceeded the reviewed limit.", []
    candidates = parse_candidates(stdout, int(request["maximum_candidates"]))
    if timed_out:
        return "timed_out", "Restricted passive Nuclei scan timed out.", candidates
    if process.returncode != 0:
        reason = safe_text(stderr.decode("utf-8", errors="replace"), 300)
        return "failed", reason or f"Nuclei exited with code {process.returncode}.", candidates
    return "completed", "Restricted passive Nuclei scan completed.", candidates


def build_result(
    request: dict[str, object],
    policy: dict[str, object],
    *,
    state: str,
    reason: str,
    candidates: list[dict[str, object]],
) -> dict[str, object]:
    result: dict[str, object] = {
        "schema_version": PROTOCOL_VERSION,
        "operation": request["operation"],
        "worker_id": policy["worker_id"],
        "request_digest": request["request_digest"],
        "execution_state": state,
        "reason": safe_text(reason, 500),
        "engine_version": policy["engine_version"],
        "template_sha256": policy["template_sha256"],
        "candidate_count": len(candidates),
        "candidates": candidates,
        "http_status": None,
        "completed_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
    }
    result["result_digest"] = sha256_json(result)
    return result


def main() -> None:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--policy", required=True)
    arguments = parser.parse_args()
    signal.signal(signal.SIGTERM, terminate_active)
    signal.signal(signal.SIGHUP, terminate_active)

    policy = read_policy(Path(arguments.policy).expanduser())
    request = read_request()
    validate_request(request, policy)
    read_engine_version(policy)
    reserve_request(request, policy)

    if request["operation"] == "readiness":
        result = build_result(
            request,
            policy,
            state="ready",
            reason="Restricted remote Nuclei worker is ready.",
            candidates=[],
        )
    else:
        state, reason, candidates = run_scan(request, policy)
        result = build_result(
            request,
            policy,
            state=state,
            reason=reason,
            candidates=candidates,
        )
    encoded = canonical_json(result)
    if len(encoded) > int(policy.get("maximum_response_bytes", 131_072)):
        fail("remote worker response exceeded the host policy")
    sys.stdout.buffer.write(encoded + b"\n")
    sys.stdout.buffer.flush()


if __name__ == "__main__":
    main()
