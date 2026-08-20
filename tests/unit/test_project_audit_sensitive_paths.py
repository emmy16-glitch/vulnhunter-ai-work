from __future__ import annotations

import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
AUDIT_SCRIPT = ROOT / "scripts" / "project_audit.py"

spec = importlib.util.spec_from_file_location("vulnhunter_project_audit", AUDIT_SCRIPT)
assert spec is not None and spec.loader is not None
project_audit = importlib.util.module_from_spec(spec)
spec.loader.exec_module(project_audit)


def test_source_modules_with_security_terms_are_not_treated_as_secret_material() -> None:
    assert not project_audit.is_sensitive_tracked_path(
        "mobile/lib/core/storage/secure_credentials.dart"
    )
    assert not project_audit.is_sensitive_tracked_path("vulnhunter/security/secrets.py")
    assert not project_audit.is_sensitive_tracked_path("frontend/src/credential-store.ts")


def test_secret_material_filenames_still_fail_closed() -> None:
    assert project_audit.is_sensitive_tracked_path(".env")
    assert project_audit.is_sensitive_tracked_path("config/credentials.json")
    assert project_audit.is_sensitive_tracked_path("keys/private_key.pem")
    assert project_audit.is_sensitive_tracked_path("keys/id_rsa")
    assert project_audit.is_sensitive_tracked_path("runtime/token.txt")


def test_safe_environment_templates_remain_allowed() -> None:
    assert not project_audit.is_sensitive_tracked_path(".env.example")
    assert not project_audit.is_sensitive_tracked_path("config/.env.sample")
    assert not project_audit.is_sensitive_tracked_path("deploy/.env.template")
