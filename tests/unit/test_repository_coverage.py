from pathlib import Path

from vulnhunter.repository_coverage import CoverageExclusion, build_inventory
from vulnhunter.repository_coverage import service as coverage_service


def _paths(inventory) -> set[str]:
    return {item.path for item in inventory.items}


def _exclusion_reasons(inventory) -> dict[str, str]:
    return {item.path: item.reason for item in inventory.exclusions}


def test_external_symlink_is_never_read_or_hashed(tmp_path, monkeypatch):
    root = tmp_path / "repository"
    root.mkdir()
    external = tmp_path / "external-secret.txt"
    external.write_text("must not be read", encoding="utf-8")
    link = root / "external-link.txt"
    link.symlink_to(external)
    real_hash = coverage_service._hash_stable_regular_file

    def guarded_hash(path, *, root):
        assert path != link
        return real_hash(path, root=root)

    monkeypatch.setattr(coverage_service, "_hash_stable_regular_file", guarded_hash)

    inventory = build_inventory(root)

    assert "external-link.txt" not in _paths(inventory)
    assert _exclusion_reasons(inventory)["external-link.txt"] == (
        "symbolic links are not inventoried"
    )


def test_internal_and_broken_symlinks_are_safely_excluded(tmp_path):
    root = tmp_path / "repository"
    root.mkdir()
    (root / "source.py").write_text("value = 1\n", encoding="utf-8")
    (root / "internal.py").symlink_to(root / "source.py")
    (root / "broken.py").symlink_to(root / "missing.py")

    inventory = build_inventory(root)

    assert _paths(inventory) == {"source.py"}
    reasons = _exclusion_reasons(inventory)
    assert reasons["internal.py"] == "symbolic links are not inventoried"
    assert reasons["broken.py"] == "symbolic links are not inventoried"


def test_nested_generated_directories_are_excluded_by_component(tmp_path):
    root = tmp_path / "repository"
    kept = root / "src" / "package"
    kept.mkdir(parents=True)
    (kept / "app.py").write_text("value = 1\n", encoding="utf-8")
    generated_paths = (
        root / "src" / "node_modules",
        root / "src" / "package" / "__pycache__",
        root / "tools" / "build",
        root / "web" / "dist",
        root / "reports" / "coverage",
        root / "outputs" / "artifacts",
    )
    for directory in generated_paths:
        directory.mkdir(parents=True)
        (directory / "ignored.py").write_text("secret = 1\n", encoding="utf-8")

    inventory = build_inventory(root)

    assert _paths(inventory) == {"src/package/app.py"}
    reasons = _exclusion_reasons(inventory)
    for directory in generated_paths:
        relative = directory.relative_to(root).as_posix()
        assert reasons[relative] == "generated directory excluded by policy"


def test_disappearing_file_fails_safely(tmp_path, monkeypatch):
    root = tmp_path / "repository"
    root.mkdir()
    disappearing = root / "disappearing.py"
    disappearing.write_text("value = 1\n", encoding="utf-8")
    real_open = coverage_service.os.open

    def disappearing_open(path, flags):
        if Path(path) == disappearing:
            disappearing.unlink()
            raise FileNotFoundError(path)
        return real_open(path, flags)

    monkeypatch.setattr(coverage_service.os, "open", disappearing_open)

    inventory = build_inventory(root)

    assert not inventory.items
    assert _exclusion_reasons(inventory)["disappearing.py"] == ("file disappeared during inventory")


def test_file_replacement_race_is_rejected(tmp_path, monkeypatch):
    root = tmp_path / "repository"
    root.mkdir()
    replaced = root / "replaced.py"
    replaced.write_text("value = 1\n", encoding="utf-8")
    real_open = coverage_service.os.open

    def replacing_open(path, flags):
        if Path(path) == replaced:
            replaced.unlink()
            replaced.write_text("value = 2\n", encoding="utf-8")
        return real_open(path, flags)

    monkeypatch.setattr(coverage_service.os, "open", replacing_open)

    inventory = build_inventory(root)

    assert not inventory.items
    assert _exclusion_reasons(inventory)["replaced.py"] == ("file changed during inventory")


def test_permission_error_is_recorded_without_exposing_exception_detail(tmp_path, monkeypatch):
    root = tmp_path / "repository"
    root.mkdir()
    blocked = root / "blocked.py"
    blocked.write_text("value = 1\n", encoding="utf-8")
    real_open = coverage_service.os.open

    def permission_open(path, flags):
        if Path(path) == blocked:
            raise PermissionError(path)
        return real_open(path, flags)

    monkeypatch.setattr(coverage_service.os, "open", permission_open)

    inventory = build_inventory(root)

    assert _exclusion_reasons(inventory)["blocked.py"] == (
        "file could not be read under current permissions"
    )


def test_ordinary_internal_files_and_root_digest_are_deterministic(tmp_path):
    root = tmp_path / "repository"
    (root / "src").mkdir(parents=True)
    (root / "src" / "app.py").write_text("value = 1\n", encoding="utf-8")
    (root / "README.md").write_text("# Project\n", encoding="utf-8")

    first = build_inventory(root)
    second = build_inventory(root)

    assert first == second
    assert [item.path for item in first.items] == ["README.md", "src/app.py"]


def test_root_digest_is_path_state_and_exclusion_sensitive(tmp_path):
    first_root = tmp_path / "first"
    second_root = tmp_path / "second"
    first_root.mkdir()
    second_root.mkdir()
    (first_root / "app.py").write_text("value = 1\n", encoding="utf-8")
    (second_root / "renamed.py").write_text("value = 1\n", encoding="utf-8")

    original = build_inventory(first_root)
    renamed = build_inventory(second_root)
    (first_root / "app.py").write_text("value = 2\n", encoding="utf-8")
    changed = build_inventory(first_root)
    excluded = build_inventory(
        first_root,
        exclusions=(CoverageExclusion(path="app.py", reason="reviewed elsewhere"),),
    )

    assert original.root_sha256 != renamed.root_sha256
    assert original.root_sha256 != changed.root_sha256
    assert changed.root_sha256 != excluded.root_sha256


def test_generated_directory_contents_do_not_affect_root_digest(tmp_path):
    root = tmp_path / "repository"
    generated = root / "src" / "node_modules"
    generated.mkdir(parents=True)
    ignored = generated / "package.js"
    ignored.write_text("first\n", encoding="utf-8")

    first = build_inventory(root)
    ignored.write_text("second\n", encoding="utf-8")
    second = build_inventory(root)

    assert first.root_sha256 == second.root_sha256
