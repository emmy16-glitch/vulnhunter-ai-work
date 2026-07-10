from __future__ import annotations

import json
from pathlib import Path

import pytest

from vulnhunter.product_spec.cli import main
from vulnhunter.product_spec.registry import ProductInterfaceSpec, SpecValidationError

SPEC_ROOT = Path("config/product_interface")


def copy_spec(tmp_path: Path) -> Path:
    destination = tmp_path / "product_interface"
    destination.mkdir()
    for source in SPEC_ROOT.glob("*.json"):
        (destination / source.name).write_text(
            source.read_text(encoding="utf-8"),
            encoding="utf-8",
        )
    return destination


def mutate(tmp_path: Path, filename: str, callback) -> Path:
    root = copy_spec(tmp_path)
    path = root / filename
    data = json.loads(path.read_text(encoding="utf-8"))
    callback(data)
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return root


def test_loads_valid_blueprint() -> None:
    spec = ProductInterfaceSpec.from_path(SPEC_ROOT)
    assert spec.manifest["blueprint_id"] == "vulnhunter-product-interface"
    assert len(spec.pages) == 23
    assert len(spec.roles) == 8


def test_fingerprint_is_deterministic() -> None:
    first = ProductInterfaceSpec.from_path(SPEC_ROOT).fingerprint()
    second = ProductInterfaceSpec.from_path(SPEC_ROOT).fingerprint()
    assert first == second
    assert len(first) == 64


def test_fingerprint_changes_with_blueprint_content(tmp_path: Path) -> None:
    original = ProductInterfaceSpec.from_path(SPEC_ROOT).fingerprint()
    root = mutate(
        tmp_path,
        "pages.json",
        lambda data: data["pages"][0].update({"title": "Changed"}),
    )
    assert ProductInterfaceSpec.from_path(root).fingerprint() != original


def test_missing_required_file_is_rejected(tmp_path: Path) -> None:
    root = copy_spec(tmp_path)
    (root / "pages.json").unlink()
    with pytest.raises(SpecValidationError, match="missing"):
        ProductInterfaceSpec.from_path(root)


def test_duplicate_page_id_is_rejected(tmp_path: Path) -> None:
    def change(data):
        data["pages"][1]["page_id"] = data["pages"][0]["page_id"]

    root = mutate(tmp_path, "pages.json", change)
    with pytest.raises(SpecValidationError, match="identifiers must be unique"):
        ProductInterfaceSpec.from_path(root)


def test_duplicate_route_is_rejected(tmp_path: Path) -> None:
    def change(data):
        data["pages"][1]["route"] = data["pages"][0]["route"]

    root = mutate(tmp_path, "pages.json", change)
    with pytest.raises(SpecValidationError, match="routes must be unique"):
        ProductInterfaceSpec.from_path(root)


def test_unknown_navigation_page_is_rejected(tmp_path: Path) -> None:
    def change(data):
        data["sections"][0]["items"][0]["page_id"] = "missing-page"

    root = mutate(tmp_path, "navigation.json", change)
    with pytest.raises(SpecValidationError, match="Navigation references unknown"):
        ProductInterfaceSpec.from_path(root)


def test_unknown_page_role_is_rejected(tmp_path: Path) -> None:
    def change(data):
        data["pages"][0]["allowed_roles"].append("invented-role")

    root = mutate(tmp_path, "pages.json", change)
    with pytest.raises(SpecValidationError, match="unknown roles"):
        ProductInterfaceSpec.from_path(root)


def test_unknown_page_resource_is_rejected(tmp_path: Path) -> None:
    def change(data):
        data["pages"][0]["required_api_resources"].append("invented-resource")

    root = mutate(tmp_path, "pages.json", change)
    with pytest.raises(SpecValidationError, match="unknown API resources"):
        ProductInterfaceSpec.from_path(root)


def test_dangerous_action_without_confirmation_is_rejected(tmp_path: Path) -> None:
    def change(data):
        page = next(item for item in data["pages"] if item["page_id"] == "new-scan")
        page["actions"][0]["confirmation_required"] = False

    root = mutate(tmp_path, "pages.json", change)
    with pytest.raises(SpecValidationError, match="must require confirmation"):
        ProductInterfaceSpec.from_path(root)


def test_new_scan_requires_authorization_reference(tmp_path: Path) -> None:
    def change(data):
        page = next(item for item in data["pages"] if item["page_id"] == "new-scan")
        page["requires_authorization_reference"] = False

    root = mutate(tmp_path, "pages.json", change)
    with pytest.raises(SpecValidationError, match="authorization reference"):
        ProductInterfaceSpec.from_path(root)


def test_release_pages_expose_blockers_and_prohibit_bypass() -> None:
    spec = ProductInterfaceSpec.from_path(SPEC_ROOT)
    for page_id in ("releases", "release-detail"):
        page = spec.page(page_id)
        assert page["shows_blockers"] is True
        assert page["allows_bypass"] is False


def test_release_bypass_is_rejected_for_any_role(tmp_path: Path) -> None:
    def change(data):
        data["roles"][0]["allowed_actions"].append("release.bypass")

    root = mutate(tmp_path, "role_permissions.json", change)
    with pytest.raises(SpecValidationError, match="forbidden actions"):
        ProductInterfaceSpec.from_path(root)


def test_reviewer_and_adjudicator_actions_are_separated() -> None:
    spec = ProductInterfaceSpec.from_path(SPEC_ROOT)
    roles = {role["role_id"]: role for role in spec.roles}
    assert "adjudication.submit" not in roles["reviewer"]["allowed_actions"]
    assert "review.submit" not in roles["adjudicator"]["allowed_actions"]


def test_reviewer_cannot_be_given_adjudication_action(tmp_path: Path) -> None:
    def change(data):
        role = next(item for item in data["roles"] if item["role_id"] == "reviewer")
        role["allowed_actions"].append("adjudication.submit")

    root = mutate(tmp_path, "role_permissions.json", change)
    with pytest.raises(SpecValidationError, match="reviewer role must not adjudicate"):
        ProductInterfaceSpec.from_path(root)


def test_connectors_and_model_training_remain_disabled() -> None:
    spec = ProductInterfaceSpec.from_path(SPEC_ROOT)
    assert spec.manifest["connectors_enabled"] is False
    assert spec.manifest["model_training_enabled"] is False


def test_connector_enable_cannot_be_allowed(tmp_path: Path) -> None:
    def change(data):
        data["roles"][0]["allowed_actions"].append("connector.enable")

    root = mutate(tmp_path, "role_permissions.json", change)
    with pytest.raises(SpecValidationError, match="forbidden actions"):
        ProductInterfaceSpec.from_path(root)


def test_breakpoints_cover_mobile_tablet_desktop_and_wide() -> None:
    spec = ProductInterfaceSpec.from_path(SPEC_ROOT)
    values = spec.documents["responsive_breakpoints.json"]["breakpoints"]
    assert [item["breakpoint_id"] for item in values] == [
        "mobile",
        "tablet",
        "desktop",
        "wide",
    ]
    assert spec.documents["responsive_breakpoints.json"]["minimum_touch_target_px"] >= 44


def test_error_catalog_has_safe_recovery_guidance() -> None:
    spec = ProductInterfaceSpec.from_path(SPEC_ROOT)
    errors = spec.documents["error_catalog.json"]["errors"]
    assert len(errors) >= 20
    assert all(item["safe_message"] for item in errors)
    assert all(item["recovery_action"] for item in errors)
    assert not any(item["exposes_internal_detail"] for item in errors)


def test_figma_handoff_has_foundations_components_and_responsive_pages() -> None:
    spec = ProductInterfaceSpec.from_path(SPEC_ROOT)
    figma = spec.documents["figma_handoff.json"]
    page_names = [item["name"] for item in figma["figma_pages"]]
    assert page_names[0] == "00 — Foundations"
    assert page_names[-1] == "09 — Responsive States"
    assert len(figma["component_sets"]) >= 12


def test_design_tokens_include_security_status_semantics() -> None:
    spec = ProductInterfaceSpec.from_path(SPEC_ROOT)
    colors = spec.documents["design_tokens.json"]["colors"]
    assert {"success", "warning", "danger", "info", "focus"}.issubset(colors)


def test_every_page_declares_roles_resources_and_responsive_priority() -> None:
    spec = ProductInterfaceSpec.from_path(SPEC_ROOT)
    for page in spec.pages:
        assert page["allowed_roles"]
        assert page["required_api_resources"]
        assert page["responsive_priority"] in {"critical", "high", "medium"}


def test_cli_validate_outputs_summary(capsys) -> None:
    assert main(["--root", str(SPEC_ROOT), "validate"]) == 0
    output = json.loads(capsys.readouterr().out)
    assert output["page_count"] == 23
    assert output["connector_enabled"] is False


def test_cli_fingerprint_outputs_sha256(capsys) -> None:
    assert main(["--root", str(SPEC_ROOT), "fingerprint"]) == 0
    assert len(capsys.readouterr().out.strip()) == 64


def test_cli_lists_pages(capsys) -> None:
    assert main(["--root", str(SPEC_ROOT), "list-pages"]) == 0
    output = capsys.readouterr().out
    assert "new-scan\t/scans/new\tNew Bounded Scan" in output
    assert "review-workspace" in output


def test_cli_shows_one_page(capsys) -> None:
    assert main(["--root", str(SPEC_ROOT), "show-page", "release-detail"]) == 0
    output = json.loads(capsys.readouterr().out)
    assert output["allows_bypass"] is False


def test_summary_is_read_only_and_planned() -> None:
    summary = ProductInterfaceSpec.from_path(SPEC_ROOT).summary()
    assert summary["status"] == "planned"
    assert summary["connector_enabled"] is False
    assert summary["model_training_enabled"] is False
