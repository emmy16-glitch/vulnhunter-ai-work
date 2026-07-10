"""Load, validate, and fingerprint the product-interface blueprint."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

REQUIRED_DOCUMENTS = (
    "manifest.json",
    "navigation.json",
    "pages.json",
    "role_permissions.json",
    "api_resources.json",
    "error_catalog.json",
    "workflow_states.json",
    "responsive_breakpoints.json",
    "design_tokens.json",
    "figma_handoff.json",
)


class SpecValidationError(ValueError):
    """Raised when the blueprint is missing, malformed, or internally inconsistent."""


@dataclass(frozen=True)
class ProductInterfaceSpec:
    """Immutable loaded view of the machine-readable product blueprint."""

    root: Path
    documents: dict[str, Any]

    @classmethod
    def from_path(
        cls,
        root: Path | str = Path("config/product_interface"),
    ) -> ProductInterfaceSpec:
        resolved = Path(root).expanduser().resolve()
        if not resolved.is_dir():
            raise SpecValidationError(f"Product-interface directory not found: {resolved}")

        documents: dict[str, Any] = {}
        for filename in REQUIRED_DOCUMENTS:
            path = resolved / filename
            if not path.is_file():
                raise SpecValidationError(f"Required product-interface file is missing: {filename}")
            try:
                documents[filename] = json.loads(path.read_text(encoding="utf-8"))
            except json.JSONDecodeError as exc:
                raise SpecValidationError(f"Malformed JSON in {filename}: {exc}") from exc

        spec = cls(root=resolved, documents=documents)
        spec.validate()
        return spec

    @property
    def manifest(self) -> dict[str, Any]:
        return self.documents["manifest.json"]

    @property
    def pages(self) -> list[dict[str, Any]]:
        return self.documents["pages.json"]["pages"]

    @property
    def roles(self) -> list[dict[str, Any]]:
        return self.documents["role_permissions.json"]["roles"]

    @property
    def resources(self) -> list[dict[str, Any]]:
        return self.documents["api_resources.json"]["resources"]

    def page(self, page_id: str) -> dict[str, Any]:
        for page in self.pages:
            if page["page_id"] == page_id:
                return page
        raise KeyError(page_id)

    def fingerprint(self) -> str:
        canonical = json.dumps(
            self.documents,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
        return hashlib.sha256(canonical).hexdigest()

    def summary(self) -> dict[str, Any]:
        return {
            "blueprint_id": self.manifest["blueprint_id"],
            "version": self.manifest["version"],
            "status": self.manifest["status"],
            "page_count": len(self.pages),
            "role_count": len(self.roles),
            "api_resource_count": len(self.resources),
            "connector_enabled": self.manifest["connectors_enabled"],
            "model_training_enabled": self.manifest["model_training_enabled"],
            "fingerprint": self.fingerprint(),
        }

    def validate(self) -> None:
        errors: list[str] = []
        manifest = self.manifest
        if manifest.get("status") != "planned":
            errors.append("The blueprint must remain planned until product implementation begins.")
        if manifest.get("backend_is_authoritative") is not True:
            errors.append(
                "The backend must remain authoritative for security and governance rules."
            )
        if manifest.get("ui_may_not_bypass_policy") is not True:
            errors.append("The UI must be explicitly forbidden from bypassing backend policy.")
        if manifest.get("connectors_enabled") is not False:
            errors.append("External connectors must remain disabled in the blueprint.")
        if manifest.get("model_training_enabled") is not False:
            errors.append("Model training must remain disabled in this blueprint milestone.")

        role_ids = self._unique_values(self.roles, "role_id", "role", errors)
        page_ids = self._unique_values(self.pages, "page_id", "page", errors)
        routes = [page.get("route") for page in self.pages]
        if len(routes) != len(set(routes)):
            errors.append("Page routes must be unique.")

        resource_ids = self._unique_values(
            self.resources,
            "resource_id",
            "API resource",
            errors,
        )
        operation_ids: set[str] = set()
        for resource in self.resources:
            for operation in resource.get("operations", []):
                operation_id = operation.get("operation_id")
                if not operation_id or operation_id in operation_ids:
                    errors.append(f"Duplicate or missing API operation ID: {operation_id!r}")
                operation_ids.add(operation_id)
                unknown = set(operation.get("allowed_roles", [])) - role_ids
                if unknown:
                    errors.append(
                        f"API operation {operation_id!r} references unknown roles: "
                        f"{sorted(unknown)}"
                    )

        for page in self.pages:
            page_id = page.get("page_id")
            unknown_roles = set(page.get("allowed_roles", [])) - role_ids
            if unknown_roles:
                errors.append(f"Page {page_id!r} references unknown roles: {sorted(unknown_roles)}")
            unknown_resources = set(page.get("required_api_resources", [])) - resource_ids
            if unknown_resources:
                errors.append(
                    f"Page {page_id!r} references unknown API resources: "
                    f"{sorted(unknown_resources)}"
                )
            for action in page.get("actions", []):
                if action.get("api_resource_id") not in resource_ids:
                    errors.append(
                        f"Action {action.get('action_id')!r} on {page_id!r} references an "
                        "unknown API resource."
                    )
                action_roles = set(action.get("allowed_roles", []))
                if not action_roles or not action_roles.issubset(
                    set(page.get("allowed_roles", []))
                ):
                    errors.append(
                        f"Action {action.get('action_id')!r} on {page_id!r} has invalid roles."
                    )
                if action.get("dangerous") and not action.get("confirmation_required"):
                    errors.append(
                        f"Dangerous action {action.get('action_id')!r} must require confirmation."
                    )

        try:
            new_scan = self.page("new-scan")
            if new_scan.get("requires_authorization_reference") is not True:
                errors.append("The new scan page must require an authorization reference.")
            if "authorizations" not in new_scan.get("required_api_resources", []):
                errors.append("The new scan page must load authorization data.")
        except KeyError:
            errors.append("The required new-scan page is missing.")

        for release_page_id in ("releases", "release-detail"):
            try:
                release_page = self.page(release_page_id)
            except KeyError:
                errors.append(f"The required {release_page_id!r} page is missing.")
                continue
            if release_page.get("shows_blockers") is not True:
                errors.append(f"{release_page_id!r} must expose release blockers.")
            if release_page.get("allows_bypass") is not False:
                errors.append(f"{release_page_id!r} must explicitly prohibit bypass actions.")

        reviewer = next((role for role in self.roles if role["role_id"] == "reviewer"), None)
        adjudicator = next(
            (role for role in self.roles if role["role_id"] == "adjudicator"),
            None,
        )
        if reviewer is None or adjudicator is None:
            errors.append("Reviewer and adjudicator roles are required.")
        else:
            if "adjudication.submit" in reviewer.get("allowed_actions", []):
                errors.append("The reviewer role must not adjudicate.")
            if "review.submit" in adjudicator.get("allowed_actions", []):
                errors.append("The adjudicator role must not submit reviewer decisions.")

        navigation = self.documents["navigation.json"]
        for section in navigation.get("sections", []):
            for item in section.get("items", []):
                if item.get("page_id") not in page_ids:
                    errors.append(f"Navigation references unknown page: {item.get('page_id')!r}")

        breakpoints = self.documents["responsive_breakpoints.json"].get(
            "breakpoints",
            [],
        )
        minimums = [item.get("min_width") for item in breakpoints]
        if len(breakpoints) < 4 or minimums != sorted(minimums):
            errors.append("Responsive breakpoints must define ordered mobile through wide layouts.")
        if (
            self.documents["responsive_breakpoints.json"].get(
                "minimum_touch_target_px",
                0,
            )
            < 44
        ):
            errors.append("The minimum touch target must be at least 44 pixels.")

        error_codes: set[str] = set()
        for item in self.documents["error_catalog.json"].get("errors", []):
            code = item.get("code")
            if not code or code in error_codes:
                errors.append(f"Duplicate or missing error code: {code!r}")
            error_codes.add(code)
            if not item.get("safe_message") or not item.get("recovery_action"):
                errors.append(f"Error {code!r} needs a safe message and recovery action.")
            if item.get("exposes_internal_detail") is not False:
                errors.append(f"Error {code!r} must not expose internal detail.")

        tokens = self.documents["design_tokens.json"]
        required_colors = {
            "background",
            "surface",
            "border",
            "text_primary",
            "text_secondary",
            "accent",
            "success",
            "warning",
            "danger",
            "focus",
        }
        if not required_colors.issubset(tokens.get("colors", {})):
            errors.append("Design tokens are missing required semantic colors.")

        figma = self.documents["figma_handoff.json"]
        if len(figma.get("figma_pages", [])) < 10:
            errors.append("The Figma handoff must define foundations through responsive states.")
        if len(figma.get("component_sets", [])) < 12:
            errors.append("The Figma handoff must define the core reusable component sets.")
        if figma.get("plugin_usage", {}).get("runtime_connectors_enabled") is not False:
            errors.append("Figma plugin use must not enable runtime product connectors.")

        forbidden_actions = {"release.bypass", "connector.enable", "model.train"}
        for role in self.roles:
            overlap = forbidden_actions.intersection(role.get("allowed_actions", []))
            if overlap:
                errors.append(
                    f"Role {role.get('role_id')!r} allows forbidden actions: {sorted(overlap)}"
                )

        if errors:
            raise SpecValidationError("\n".join(f"- {error}" for error in errors))

    @staticmethod
    def _unique_values(
        records: list[dict[str, Any]],
        key: str,
        label: str,
        errors: list[str],
    ) -> set[str]:
        values: list[str] = []
        for record in records:
            value = record.get(key)
            if not isinstance(value, str) or not value:
                errors.append(f"Every {label} requires a non-empty {key}.")
                continue
            values.append(value)
        if len(values) != len(set(values)):
            errors.append(f"{label.title()} identifiers must be unique.")
        return set(values)
