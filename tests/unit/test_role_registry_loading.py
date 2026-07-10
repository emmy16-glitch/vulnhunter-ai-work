from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from vulnhunter.roles.registry import RegistryIntegrityError, RoleRegistry

REGISTRY_ROOT = Path("config/roles")


def copied_registry(tmp_path: Path) -> Path:
    destination = tmp_path / "roles"
    shutil.copytree(REGISTRY_ROOT, destination)
    return destination


def read_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, value: dict) -> None:
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")


def test_registry_loads_all_required_roles_and_skills() -> None:
    registry = RoleRegistry.from_path(REGISTRY_ROOT)

    assert len(registry.roles) == 13
    assert len(registry.skills) == 13
    assert set(registry.manifest.required_role_ids) == {role.role_id for role in registry.roles}
    assert set(registry.manifest.required_skill_ids) == {
        skill.skill_id for skill in registry.skills
    }


def test_initial_registry_is_planned_untrusted_and_connector_disabled() -> None:
    registry = RoleRegistry.from_path(REGISTRY_ROOT)

    assert all(role.status == "planned" for role in registry.roles)
    assert all(role.trust_assumption == "untrusted" for role in registry.roles)
    assert all(not role.connector_policy.grants for role in registry.roles)
    assert all(not role.external_dependencies for role in registry.roles)
    assert all(not skill.external_dependencies for skill in registry.skills)


def test_registry_fingerprint_is_deterministic() -> None:
    first = RoleRegistry.from_path(REGISTRY_ROOT).fingerprint()
    second = RoleRegistry.from_path(REGISTRY_ROOT).fingerprint()

    assert first == second
    assert len(first) == 64


def test_registry_fingerprint_changes_when_a_role_changes(tmp_path: Path) -> None:
    root = copied_registry(tmp_path)
    before = RoleRegistry.from_path(root).fingerprint()
    role_path = root / "roles" / "report-writer.json"
    role = read_json(role_path)
    role["purpose"] += " This sentence changes the immutable registry snapshot."
    write_json(role_path, role)

    after = RoleRegistry.from_path(root).fingerprint()

    assert after != before


def test_registry_rejects_unknown_skill_reference(tmp_path: Path) -> None:
    root = copied_registry(tmp_path)
    role_path = root / "roles" / "report-writer.json"
    role = read_json(role_path)
    role["skill_ids"] = ["missing-skill"]
    write_json(role_path, role)

    with pytest.raises(RegistryIntegrityError, match="unknown skills"):
        RoleRegistry.from_path(root)


def test_registry_rejects_undeclared_role_file(tmp_path: Path) -> None:
    root = copied_registry(tmp_path)
    source = root / "roles" / "report-writer.json"
    shutil.copy2(source, root / "roles" / "undeclared-role.json")

    with pytest.raises(RegistryIntegrityError, match="Undeclared role files"):
        RoleRegistry.from_path(root)


def test_registry_rejects_role_allowing_globally_denied_action(tmp_path: Path) -> None:
    root = copied_registry(tmp_path)
    role_path = root / "roles" / "report-writer.json"
    role = read_json(role_path)
    role["allowed_actions"].append("git.push")
    role["denied_actions"].remove("git.push")
    write_json(role_path, role)

    with pytest.raises(RegistryIntegrityError, match="globally denied"):
        RoleRegistry.from_path(root)


def test_registry_rejects_path_escape(tmp_path: Path) -> None:
    root = copied_registry(tmp_path)
    manifest_path = root / "registry.json"
    manifest = read_json(manifest_path)
    manifest["role_files"][0] = "../outside.json"
    write_json(manifest_path, manifest)

    with pytest.raises(RegistryIntegrityError, match="escapes"):
        RoleRegistry.from_path(root)
