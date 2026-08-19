from pathlib import Path

from vulnhunter.mobile.static_toolchain import (
    MobileStaticToolchain,
    MobileStaticToolchainError,
)
from vulnhunter.mobile.static_worker import _controlled_failure_reason

ROOT = Path(__file__).resolve().parents[2]


def _text(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


def test_python_mobile_tools_use_a_dedicated_fixed_environment():
    installer = _text(".devcontainer/install-mobile-static-tools.sh")
    policy = _text("scripts/prepare_mobile_static_worker.py")

    assert "python -m venv --copies" in installer
    assert ".codespaces/tools/mobile-python" in installer
    assert '"$PYTHON_TOOLS_ROOT/bin/python" -m pip install' in installer
    assert 'PYTHON_TOOLS_ROOT / "bin" / "apkid"' in policy
    assert '_module_available(python, "androguard")' in policy
    assert '_module_available(python, "yara")' in policy


def test_large_apk_static_workspace_remains_bounded_but_practical():
    policy = _text("scripts/prepare_mobile_static_worker.py")

    assert '"maximum_generated_bytes": 3_000_000_000' in policy
    assert '"maximum_generated_file_bytes": 750_000_000' in policy
    assert '"maximum_memory_bytes": 8_000_000_000' in policy


def test_controlled_worker_failure_explains_the_actual_boundary():
    reason = _controlled_failure_reason(
        MobileStaticToolchainError("tool generated an oversized analysis workspace")
    )

    assert reason == (
        "Mobile static analysis stopped safely: tool generated an oversized analysis workspace."
    )
    assert "MobileStaticToolchainError" not in reason


def test_apktool_framework_link_is_materialized_inside_private_home(tmp_path):
    trusted_framework = Path("/usr/share/android-framework-res/framework-res.apk")
    if not trusted_framework.is_file():
        return
    framework = tmp_path / "home" / ".local" / "share" / "apktool" / "framework"
    framework.mkdir(parents=True)
    link = framework / "1.apk"
    link.symlink_to(trusted_framework)

    MobileStaticToolchain._materialize_apktool_framework(tmp_path / "home")

    assert link.is_file()
    assert not link.is_symlink()
    assert link.read_bytes() == trusted_framework.read_bytes()


def test_assessment_creation_is_only_exposed_in_the_conversation_workspace():
    history = _text("vulnhunter/web/templates/web/agent_runs.html")

    assert "Assessment history" in history
    assert "Open workspace" in history
    assert "data-assessment-open" not in history
    assert "New Assessment" not in history
    assert "vh-assessment-dialog" not in history


def test_scrollable_workspace_regions_have_visible_scrollbars():
    conversation = _text("vulnhunter/web/static/web/conversation.css")

    assert ".vh-analysis-panels" in conversation
    assert "overflow-y: auto" in conversation
    assert ".vh-chat-feed" in conversation
    assert "scrollbar-width: thin" in conversation
    assert "min-height: 44px" in conversation


def test_directory_writing_tools_use_aggregate_kernel_file_limit():
    toolchain = _text("vulnhunter/mobile/static_toolchain.py")

    assert "file_limit = self.policy.maximum_generated_bytes" in toolchain
    assert "enforce_workspace_bound(workspace)" in toolchain
    assert "RLIMIT_FSIZE is a limit on each individual file" in toolchain


def test_multithreaded_tools_get_separate_cpu_guard_from_wall_timeout():
    toolchain = _text("vulnhunter/mobile/static_toolchain.py")

    assert "cpu_limit = spec.timeout_seconds * 4" in toolchain
    assert "RLIMIT_CPU" in toolchain
    assert "subprocess.run(timeout=...) is wall-clock time" in toolchain
