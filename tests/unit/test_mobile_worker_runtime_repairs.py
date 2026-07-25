from pathlib import Path

from vulnhunter.mobile.static_toolchain import MobileStaticToolchainError
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


def test_assessment_creation_is_only_exposed_in_the_conversation_workspace():
    history = _text("vulnhunter/web/templates/web/agent_runs.html")

    assert "Assessment History" in history
    assert "Open workspace" in history
    assert "data-assessment-open" not in history
    assert "New Assessment" not in history
    assert "vh-assessment-dialog" not in history


def test_scrollable_workspace_regions_have_visible_scrollbars():
    polish = _text("vulnhunter/web/static/web/workspace-polish.css")

    assert ".vh-analysis-panel" in polish
    assert "overflow-y: auto" in polish
    assert "scrollbar-width: auto" in polish
    assert ".vh-chat-feed::-webkit-scrollbar" in polish
    assert "width: 11px" in polish
    assert "min-height: 44px" in polish
