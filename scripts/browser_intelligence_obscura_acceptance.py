#!/usr/bin/env python3
"""Run real Obscura through VulnHunter's governed BrowserAction service."""

from __future__ import annotations

import argparse
import json
import shutil
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from tests.fixtures.browser_intelligence_app import local_browser_fixture  # noqa: E402
from vulnhunter.browser_intelligence import (
    BrowserAction,
    BrowserActionStatus,
    BrowserActionType,
    BrowserIntelligenceService,
    BrowserIntelligenceStore,
    BrowserMode,
    BrowserPolicy,
    ObscuraMcpProcess,
    ObscuraRuntimeConfig,
)
from vulnhunter.scope.validator import validate_target


def _action(
    action_type: BrowserActionType, parameters: dict[str, object] | None = None
) -> BrowserAction:
    return BrowserAction(
        action_type=action_type,
        parameters=parameters or {},
        requested_by="deterministic-browser-acceptance",
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--binary",
        type=Path,
        default=Path("/home/ubuntu/.local/share/vulnhunter/browser-tools/obscura-0.2.0/obscura"),
    )
    parser.add_argument(
        "--artifact-root",
        type=Path,
        default=Path("/tmp/vulnhunter-browser-intelligence-acceptance"),
    )
    arguments = parser.parse_args()
    artifact_root = arguments.artifact_root.expanduser().absolute()
    if artifact_root.exists():
        shutil.rmtree(artifact_root)
    artifact_root.mkdir(parents=True, exist_ok=True)

    with local_browser_fixture() as base_url:
        target = validate_target(base_url + "/")
        runtime = ObscuraMcpProcess(
            ObscuraRuntimeConfig(binary=arguments.binary, allow_private_network=True)
        )
        store = BrowserIntelligenceStore(artifact_root)
        policy = BrowserPolicy(
            target=target,
            authorization_id="authorization-browser-acceptance",
            mode=BrowserMode.CONTROLLED_INTERACTIVE,
            allow_credentials=True,
        )
        service = BrowserIntelligenceService.create_session(
            assessment_id="assessment-browser-acceptance",
            attempt_id="attempt-browser-acceptance",
            workspace_id="workspace-browser-acceptance",
            owner_id="owner-browser-acceptance",
            authorization_id="authorization-browser-acceptance",
            target=target,
            policy=policy,
            runtime=runtime,
            store=store,
        )
        actions = [
            _action(BrowserActionType.NAVIGATE, {"url": base_url + "/login"}),
            _action(BrowserActionType.SNAPSHOT, {"max_chars": 2_000}),
            _action(BrowserActionType.DETECT_FORMS),
            _action(BrowserActionType.GET_INTERACTIVE_ELEMENTS),
            _action(BrowserActionType.FILL, {"ref": "e1", "value": "fixture-user"}),
            _action(BrowserActionType.FILL, {"ref": "e2", "value": "fixture-password"}),
            _action(BrowserActionType.CLICK, {"ref": "e3"}),
            _action(BrowserActionType.NAVIGATE, {"url": base_url + "/dashboard"}),
            _action(BrowserActionType.WAIT, {"seconds": 1}),
            _action(BrowserActionType.SNAPSHOT, {"max_chars": 2_000}),
            _action(BrowserActionType.GET_NETWORK_REQUESTS),
            _action(BrowserActionType.GET_CONSOLE_MESSAGES),
            _action(BrowserActionType.TAKE_SCREENSHOT, {"width": 1_280, "height": 900}),
            _action(BrowserActionType.GET_CURRENT_URL),
        ]
        receipts = [service.execute_action(action) for action in actions]
        failures = [
            receipt for receipt in receipts if receipt.status != BrowserActionStatus.COMPLETED
        ]
        report = service.cancel() if failures else service.finish()
        if failures:
            raise SystemExit(
                "Obscura acceptance action failed: "
                + "; ".join(
                    (
                        f"{receipt.action_type.value}:"
                        f"{receipt.error_category.value if receipt.error_category else 'unknown'}"
                    )
                    for receipt in failures
                )
            )
        if not report.screenshots:
            raise SystemExit("Obscura acceptance did not produce screenshot evidence")
        if not report.current_url or not report.current_url.endswith("/dashboard"):
            raise SystemExit("Obscura acceptance did not navigate to the dashboard")
        snapshots = [
            receipt.result_summary.get("text_preview", "")
            for receipt in report.action_receipts
            if receipt.action_type == BrowserActionType.SNAPSHOT
        ]
        if not any(
            "Dashboard ready" in text and "JavaScript executed" in text for text in snapshots
        ):
            raise SystemExit("Obscura acceptance did not prove rendered dashboard JavaScript")
        if not {"/api/profile", "/api/settings"}.issubset(set(report.endpoint_paths)):
            raise SystemExit("Obscura acceptance did not observe the expected runtime endpoints")
        console_receipts = [
            receipt
            for receipt in report.action_receipts
            if receipt.action_type == BrowserActionType.GET_CONSOLE_MESSAGES
        ]
        if not console_receipts or console_receipts[0].status != BrowserActionStatus.COMPLETED:
            raise SystemExit("Obscura console MCP action did not complete")
        console_capture_status = (
            "observed" if report.console_observations else "runtime_returned_no_messages"
        )
        screenshot_path = (
            artifact_root
            / report.screenshots[0].workspace_id
            / report.session_id
            / report.screenshots[0].relative_path
        )
        if not screenshot_path.is_file() or screenshot_path.stat().st_size == 0:
            raise SystemExit("Obscura acceptance screenshot artifact is missing or empty")
        payload = {
            "status": "accepted",
            "runtime": report.runtime.value,
            "runtime_version": report.runtime_version,
            "session_id": report.session_id,
            "report_sha256": report.report_sha256,
            "actions": [receipt.model_dump(mode="json") for receipt in report.action_receipts],
            "network_observations": [
                item.model_dump(mode="json") for item in report.network_observations
            ],
            "console_observations": [
                item.model_dump(mode="json") for item in report.console_observations
            ],
            "console_capture_status": console_capture_status,
            "screenshots": [item.model_dump(mode="json") for item in report.screenshots],
            "screenshot_path": str(screenshot_path),
            "endpoint_paths": list(report.endpoint_paths),
        }
        print(json.dumps(payload, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
