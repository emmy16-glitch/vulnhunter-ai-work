"""Tests for the standalone project-intelligence audit."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path


def load_audit_module():
    """Load the audit script without requiring a package installation."""
    root = Path(__file__).resolve().parents[2]
    path = root / "scripts" / "project_audit.py"
    spec = importlib.util.spec_from_file_location("project_audit", path)

    assert spec is not None
    assert spec.loader is not None

    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_required_intelligence_manifest_contains_operating_manual() -> None:
    module = load_audit_module()

    assert "AGENTS.md" in module.REQUIRED_INTELLIGENCE_FILES
    assert "docs/intelligence/SECURITY_BOUNDARIES.md" in (module.REQUIRED_INTELLIGENCE_FILES)


def test_render_markdown_includes_security_checks() -> None:
    module = load_audit_module()

    result = module.AuditResult(
        generated_at="2026-07-09T00:00:00+00:00",
        repository_root="/tmp/vulnhunter-ai",
        git_commit="abc123",
        git_branch="main",
        working_tree_clean=True,
        python_file_count=10,
        test_file_count=5,
        markdown_file_count=4,
        package_presence={"scope": True},
        required_intelligence_presence={"AGENTS.md": True},
        tracked_sensitive_name_hits=(),
        tracked_generated_artifact_hits=(),
        largest_tracked_files=({"path": "README.md", "bytes": 100},),
        repository_tree_sha256="0" * 64,
        warnings=(),
    )

    output = module.render_markdown(result)

    assert "Working tree clean: `yes`" in output
    assert "No sensitive-looking tracked filenames detected." in output
    assert "No tracked database/model artifact paths detected." in output
    assert "Warnings" in output


def test_sensitive_path_check_allows_environment_templates() -> None:
    module = load_audit_module()

    safe_templates = (
        ".env.example",
        "config/.env.sample",
        "deployment/nested/.env.template",
    )

    for path in safe_templates:
        assert module.is_sensitive_tracked_path(path) is False


def test_sensitive_path_check_still_flags_real_secret_names() -> None:
    module = load_audit_module()

    sensitive_paths = (
        ".env",
        "config/.env.production",
        "config/credentials.json",
        "secrets/private_key.pem",
        "keys/id_rsa",
        "runtime/token.txt",
    )

    for path in sensitive_paths:
        assert module.is_sensitive_tracked_path(path) is True
