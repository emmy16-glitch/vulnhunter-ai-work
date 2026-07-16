import importlib.util
import json
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from vulnhunter.actions.models import ActionClass
from vulnhunter.security_tools import catalog as catalog_module
from vulnhunter.security_tools.adapters import build_command_plan
from vulnhunter.security_tools.catalog import (
    SecurityToolCatalog,
    default_catalog,
    readiness_probe_worker_count,
    run_ordered_readiness_probes,
)
from vulnhunter.security_tools.models import (
    SecurityToolDefinition,
    SecurityToolRequest,
    ToolAvailabilityStatus,
    ToolProfile,
    ToolTargetKind,
)
from vulnhunter.security_tools.parsers import parse_structured_findings
from vulnhunter.security_tools.targets import (
    TargetValidationError,
    validate_tool_target,
)


def _request(tmp_path: Path, tool_id: str, target: Path, **updates):
    values = {
        "request_id": f"{tool_id}-request",
        "action_manifest_sha256": "a" * 64,
        "tool_id": tool_id,
        "profile": ToolProfile.SAFE_ASSESSMENT,
        "operation": "scan",
        "target": str(target.resolve()),
        "target_kind": ToolTargetKind.LOCAL_PATH,
        "timeout_seconds": 90,
        "maximum_output_bytes": 500_000,
        "output_directory": tmp_path / "evidence",
    }
    values.update(updates)
    return SecurityToolRequest(**values)


def _probe_definition(*, executable: str = "probe-tool") -> SecurityToolDefinition:
    return SecurityToolDefinition(
        tool_id="nmap",
        display_name="Probe",
        executable_candidates=(executable,),
        profiles=(ToolProfile.DISCOVERY,),
        target_kinds=(ToolTargetKind.NETWORK,),
        action_class=ActionClass.READ_ONLY,
        approval_required=False,
        description="Probe definition for a focused readiness test.",
    )


def _load_script(name: str):
    path = Path(__file__).resolve().parents[2] / "scripts" / f"{name}.py"
    spec = importlib.util.spec_from_file_location(f"test_{name}", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_catalog_registers_installed_local_toolchain():
    ids = {item.tool_id for item in default_catalog().list()}
    assert {
        "bearer",
        "bandit",
        "detect-secrets",
        "gitleaks",
        "syft",
        "grype",
        "osv-scanner",
        "capa",
    } <= ids
    assert "semgrep" not in ids


def test_health_probe_distinguishes_ready_and_unusable(monkeypatch):
    monkeypatch.setattr(catalog_module.shutil, "which", lambda _candidate: "/opt/probe")
    calls = []

    def run_probe(*argv, **kwargs):
        calls.append((argv, kwargs))
        return subprocess.CompletedProcess(argv, 0, "good-tool-1.0\n", "")

    monkeypatch.setattr(catalog_module.subprocess, "run", run_probe)
    definition = _probe_definition()
    catalog = SecurityToolCatalog((definition,))
    ready = catalog.detect("nmap")
    assert ready.usable is True
    assert ready.status == ToolAvailabilityStatus.READY

    monkeypatch.setattr(
        catalog_module.subprocess,
        "run",
        lambda *argv, **kwargs: subprocess.CompletedProcess(argv, 7, "", "broken\n"),
    )
    broken = SecurityToolCatalog((definition,)).detect("nmap")
    assert broken.available is True
    assert broken.usable is False
    assert broken.status == ToolAvailabilityStatus.UNUSABLE
    assert broken.return_code == 7
    assert calls[0][1]["shell"] is False
    assert calls[0][1]["stdin"] is subprocess.DEVNULL
    assert calls[0][1]["timeout"] == 20
    assert calls[0][1]["capture_output"] is True
    assert calls[0][1]["env"] == catalog_module._probe_environment()


def test_readiness_worker_count_is_nonzero_cpu_aware_and_capped(monkeypatch):
    monkeypatch.setattr(catalog_module.os, "cpu_count", lambda: None)
    assert readiness_probe_worker_count(0) == 1
    assert readiness_probe_worker_count(20) == 1

    monkeypatch.setattr(catalog_module.os, "cpu_count", lambda: 64)
    assert readiness_probe_worker_count(20) == 2
    assert readiness_probe_worker_count(1) == 1


def test_default_readiness_worker_count_does_not_exceed_two():
    assert 1 <= readiness_probe_worker_count(100) <= 2


def test_detect_all_uses_shared_policy_and_keeps_sorted_order(monkeypatch):
    first = _probe_definition(executable="z-probe")
    second = first.model_copy(update={"tool_id": "httpx", "executable_candidates": ("a-probe",)})
    catalog = SecurityToolCatalog((first, second))
    observed = []

    def ordered(items, probe):
        ordered_items = tuple(items)
        observed.append((ordered_items, probe))
        return ordered_items

    monkeypatch.setattr(catalog_module, "run_ordered_readiness_probes", ordered)
    assert catalog.detect_all() == ("httpx", "nmap")
    assert observed == [(("httpx", "nmap"), catalog.detect)]


def test_ordered_readiness_helper_preserves_input_order():
    assert run_ordered_readiness_probes(("third", "first", "second"), str.upper) == (
        "THIRD",
        "FIRST",
        "SECOND",
    )


def test_probe_timeout_missing_and_nonzero_all_fail_closed(monkeypatch):
    definition = _probe_definition()
    catalog = SecurityToolCatalog((definition,))

    monkeypatch.setattr(catalog_module.shutil, "which", lambda _candidate: None)
    missing = catalog.detect("nmap")
    assert missing.available is False
    assert missing.usable is False
    assert missing.status == ToolAvailabilityStatus.NOT_DETECTED

    monkeypatch.setattr(catalog_module.shutil, "which", lambda _candidate: "/opt/probe")
    monkeypatch.setattr(
        catalog_module.subprocess,
        "run",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            subprocess.TimeoutExpired(args[0], kwargs["timeout"])
        ),
    )
    timed_out = catalog.detect("nmap")
    assert timed_out.available is True
    assert timed_out.usable is False
    assert timed_out.status == ToolAvailabilityStatus.TIMED_OUT

    monkeypatch.setattr(
        catalog_module.subprocess,
        "run",
        lambda *args, **kwargs: subprocess.CompletedProcess(args[0], 9, "", "failed"),
    )
    nonzero = catalog.detect("nmap")
    assert nonzero.available is True
    assert nonzero.usable is False
    assert nonzero.status == ToolAvailabilityStatus.UNUSABLE


def test_standard_status_uses_catalog_bulk_policy_and_never_enables_execution(
    tmp_path, monkeypatch
):
    status_script = _load_script("security_tool_status")
    detected_ids = []

    class FakeCatalog:
        def detect_many(self, tool_ids):
            detected_ids.extend(tool_ids)
            return (
                SimpleNamespace(
                    tool_id="nmap",
                    usable=True,
                    model_dump=lambda **_kwargs: {"tool_id": "nmap", "usable": True},
                ),
            )

    output = tmp_path / "status.json"
    monkeypatch.setattr(status_script, "default_catalog", FakeCatalog)
    monkeypatch.setattr(status_script, "enable_tools_path", lambda: tmp_path)
    monkeypatch.setattr(sys, "argv", ["security_tool_status.py", "--output", str(output)])
    assert status_script.main() == 0
    report = json.loads(output.read_text())
    assert tuple(detected_ids) == status_script.STANDARD_TOOL_IDS
    assert report["execution_enabled"] is False


def test_dependency_status_uses_shared_ordered_probe_policy(tmp_path, monkeypatch):
    dependency_script = _load_script("dependency_readiness")
    calls = []

    def ordered(items, probe):
        ordered_items = tuple(items)
        calls.append(ordered_items)
        return tuple(probe(item) for item in ordered_items)

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(dependency_script, "TOOLS", {"probe": ("probe", "--version")})
    monkeypatch.setattr(dependency_script, "probe", lambda _argv: {"installed": False})
    monkeypatch.setattr(dependency_script, "run_ordered_readiness_probes", ordered)
    assert dependency_script.main() == 0
    assert calls == [(("probe", ("probe", "--version")),)]


@pytest.mark.parametrize(
    ("tool_id", "suffix", "needle"),
    [
        ("bearer", ".bearer.json", "--format"),
        ("bandit", ".bandit.json", "--exit-zero"),
        ("gitleaks", ".gitleaks.json", "--redact=100"),
        ("syft", ".syft.json", "syft-json="),
        ("grype", ".grype.json", "--file"),
    ],
)
def test_local_tool_plans_are_shell_free_and_bounded(tmp_path, tool_id, suffix, needle):
    target = tmp_path / "source"
    target.mkdir()
    request = _request(tmp_path, tool_id, target)
    plan = build_command_plan(
        request, executable=f"/opt/tools/{tool_id}", catalog=default_catalog()
    )
    assert plan.argv[0] == f"/opt/tools/{tool_id}"
    assert any(needle in item for item in plan.argv)
    assert plan.output_files[0].name.endswith(suffix)
    assert plan.working_directory == (tmp_path / "evidence").resolve()


def test_stdout_capture_adapters(tmp_path):
    target = tmp_path / "source"
    target.mkdir()
    for tool_id, expected in (("detect-secrets", "scan"), ("osv-scanner", "source")):
        request = _request(tmp_path, tool_id, target)
        plan = build_command_plan(
            request, executable=f"/opt/tools/{tool_id}", catalog=default_catalog()
        )
        assert expected in plan.argv
        assert plan.stdout_file is not None
        assert plan.stderr_file is not None


def test_capa_requires_a_regular_binary_file(tmp_path):
    directory = tmp_path / "not-a-binary"
    directory.mkdir()
    with pytest.raises(TargetValidationError, match="regular file"):
        validate_tool_target(str(directory), ToolTargetKind.BINARY_FILE)

    binary = tmp_path / "sample.bin"
    binary.write_bytes(b"MZ")
    request = _request(
        tmp_path,
        "capa",
        binary,
        target_kind=ToolTargetKind.BINARY_FILE,
    )
    plan = build_command_plan(request, executable="/opt/tools/capa", catalog=default_catalog())
    assert plan.argv == ("/opt/tools/capa", "-j", str(binary.resolve()))


def test_parsers_normalize_bandit_and_secret_results(tmp_path):
    bandit = tmp_path / "bandit.json"
    bandit.write_text(
        json.dumps(
            {
                "results": [
                    {
                        "issue_text": "subprocess call with shell=True",
                        "issue_severity": "HIGH",
                        "issue_confidence": "HIGH",
                        "test_id": "B602",
                        "filename": "app.py",
                        "line_number": 8,
                    }
                ]
            }
        )
    )
    findings = parse_structured_findings(bandit, tool_id="bandit", target_reference="/workspace")
    assert len(findings) == 1
    assert findings[0].severity == "high"
    assert findings[0].evidence["test_id"] == "B602"

    secrets = tmp_path / "secrets.json"
    secrets.write_text(
        json.dumps(
            {
                "results": {
                    "settings.py": [
                        {
                            "type": "Secret Keyword",
                            "line_number": 4,
                            "hashed_secret": "abc123",
                        }
                    ]
                }
            }
        )
    )
    findings = parse_structured_findings(
        secrets, tool_id="detect-secrets", target_reference="/workspace"
    )
    assert findings[0].evidence["filename"] == "settings.py"
    assert "Secret Keyword" in findings[0].title


def test_osv_plan_accepts_vulnerability_exit_code(tmp_path):
    target = tmp_path / "source"
    target.mkdir()
    request = _request(tmp_path, "osv-scanner", target)
    plan = build_command_plan(
        request, executable="/opt/tools/osv-scanner", catalog=default_catalog()
    )
    assert plan.acceptable_return_codes == (0, 1)


def test_execution_artifacts_are_connected_to_normalization(tmp_path):
    from datetime import UTC, datetime

    from vulnhunter.security_tools.integration import normalize_execution_findings
    from vulnhunter.security_tools.models import ToolExecutionResult

    output = tmp_path / "scan.bandit.json"
    output.write_text(
        json.dumps(
            {
                "results": [
                    {
                        "issue_text": "hardcoded password",
                        "issue_severity": "HIGH",
                        "test_id": "B105",
                        "filename": "settings.py",
                        "line_number": 3,
                    }
                ]
            }
        )
    )
    now = datetime.now(UTC)
    result = ToolExecutionResult(
        execution_id="execution-01",
        request_id="request-01",
        tool_id="bandit",
        command_plan_sha256="b" * 64,
        started_at=now,
        finished_at=now,
        return_code=0,
        timed_out=False,
        stdout_preview="",
        stderr_preview="",
        output_files=(str(output),),
        evidence_sha256="c" * 64,
        success=True,
    )
    findings = normalize_execution_findings(result, target_reference="/workspace")
    assert len(findings) == 1
    assert findings[0].tool_id == "bandit"
    assert findings[0].evidence["test_id"] == "B105"
