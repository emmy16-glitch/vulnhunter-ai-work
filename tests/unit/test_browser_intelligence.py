from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from vulnhunter.browser_intelligence import (
    BrowserAction,
    BrowserActionLimits,
    BrowserActionStatus,
    BrowserActionType,
    BrowserIntelligenceService,
    BrowserIntelligenceStore,
    BrowserMode,
    BrowserPolicy,
    BrowserPolicyError,
    BrowserRuntimeCapabilities,
    BrowserRuntimeName,
    BrowserSession,
)
from vulnhunter.scope.models import ApprovedTarget


class _FakeRuntime:
    def __init__(self) -> None:
        self.calls: list[tuple[str, dict[str, object]]] = []
        self.closed = False

    def start(self) -> BrowserRuntimeCapabilities:
        return BrowserRuntimeCapabilities(
            runtime=BrowserRuntimeName.OBSCURA,
            version="0.2.0",
            mcp_available=True,
            screenshot_available=True,
            network_available=True,
            console_available=True,
            forms_available=True,
            interactive_elements_available=True,
            preflight_passed=True,
        )

    def execute(self, action: BrowserAction) -> dict[str, object]:
        self.calls.append((action.action_type.value, dict(action.parameters)))
        if action.action_type == BrowserActionType.TAKE_SCREENSHOT:
            return {"images": [b"not-a-real-png"]}
        if action.action_type == BrowserActionType.GET_NETWORK_REQUESTS:
            return {
                "requests": [
                    {"url": "http://127.0.0.1:8000/api/profile", "method": "GET", "status": 200}
                ]
            }
        if action.action_type == BrowserActionType.GET_CONSOLE_MESSAGES:
            return {"messages": [{"level": "log", "message": "safe fixture message"}]}
        if action.action_type == BrowserActionType.NAVIGATE:
            return {"url": action.parameters["url"], "text": "navigated"}
        return {"text": "ok"}

    def close(self) -> None:
        self.closed = True


class _LargeScreenshotRuntime(_FakeRuntime):
    def execute(self, action: BrowserAction) -> dict[str, object]:
        if action.action_type == BrowserActionType.TAKE_SCREENSHOT:
            self.calls.append((action.action_type.value, dict(action.parameters)))
            return {"images": [b"x" * 2_048]}
        return super().execute(action)


def _target() -> ApprovedTarget:
    return ApprovedTarget(
        original_url="http://127.0.0.1:8000/app",
        normalized_url="http://127.0.0.1:8000/app",
        scheme="http",
        hostname="127.0.0.1",
        port=8000,
        path="/app",
        resolved_addresses=("127.0.0.1",),
    )


def _session(now: datetime) -> BrowserSession:
    return BrowserSession(
        session_id="browser-test-session",
        assessment_id="assessment-test",
        workspace_id="workspace-test",
        owner_id="owner-a",
        authorization_id="authorization-test",
        target_url="http://127.0.0.1:8000/app",
        allowed_origins=("http://127.0.0.1:8000",),
        runtime=BrowserRuntimeName.OBSCURA,
        runtime_version="0.2.0",
        capabilities=BrowserRuntimeCapabilities(
            runtime=BrowserRuntimeName.OBSCURA,
            version="0.2.0",
            preflight_passed=True,
        ),
        state="ready",
        current_url="http://127.0.0.1:8000/app",
        started_at=now,
        last_activity=now,
        expires_at=now + timedelta(minutes=5),
    )


def test_policy_rejects_out_of_scope_navigation_and_arbitrary_evaluate() -> None:
    policy = BrowserPolicy(target=_target(), authorization_id="authorization-test")
    session = _session(datetime.now(UTC))
    with pytest.raises(BrowserPolicyError, match="outside the authorized path"):
        policy.validate_action(
            BrowserAction(
                action_type="navigate",
                parameters={"url": "http://127.0.0.1:8000/admin"},
                requested_by="test",
            ),
            session=session,
        )
    with pytest.raises(BrowserPolicyError, match="evaluation"):
        policy.validate_action(
            BrowserAction(
                action_type="snapshot",
                parameters={"script": "document.cookie"},
                requested_by="test",
            ),
            session=session,
        )


def test_passive_policy_rejects_form_mutation() -> None:
    policy = BrowserPolicy(
        target=_target(), authorization_id="authorization-test", mode=BrowserMode.PASSIVE
    )
    with pytest.raises(BrowserPolicyError, match="controlled interactive"):
        policy.validate_action(
            BrowserAction(
                action_type="fill",
                parameters={"selector": "#username", "value": "tester"},
                requested_by="test",
            ),
            session=_session(datetime.now(UTC)),
        )


def test_get_attribute_requires_a_valid_attribute_name() -> None:
    policy = BrowserPolicy(target=_target(), authorization_id="authorization-test")
    session = _session(datetime.now(UTC))
    with pytest.raises(BrowserPolicyError, match="non-empty attribute"):
        policy.validate_action(
            BrowserAction(
                action_type="get_attribute",
                parameters={"selector": "#account"},
                requested_by="test",
            ),
            session=session,
        )
    with pytest.raises(BrowserPolicyError, match="attribute name is invalid"):
        policy.validate_action(
            BrowserAction(
                action_type="get_attribute",
                parameters={"selector": "#account", "attribute": "data\u0000secret"},
                requested_by="test",
            ),
            session=session,
        )


def test_store_isolates_workspace_and_owner(tmp_path: Path) -> None:
    store = BrowserIntelligenceStore(tmp_path)
    session = _session(datetime.now(UTC))
    store.save_session(session)
    assert (
        store.load_session(
            session.session_id, owner_id="owner-a", workspace_id="workspace-test"
        ).session_id
        == session.session_id
    )
    with pytest.raises(Exception, match="not accessible"):
        store.load_session(session.session_id, owner_id="owner-b", workspace_id="workspace-test")


def test_service_persists_receipts_network_console_and_screenshot(tmp_path: Path) -> None:
    now = datetime.now(UTC)
    runtime = _FakeRuntime()
    session = _session(now)
    store = BrowserIntelligenceStore(tmp_path)
    store.save_session(session)
    service = BrowserIntelligenceService(
        session=session,
        target=_target(),
        policy=BrowserPolicy(
            target=_target(),
            authorization_id="authorization-test",
            mode=BrowserMode.CONTROLLED_INTERACTIVE,
            limits=BrowserActionLimits(maximum_screenshots=2),
        ),
        runtime=runtime,
        store=store,
        owner_id="owner-a",
    )
    fill = service.execute_action(
        BrowserAction(
            action_type="fill",
            parameters={"selector": "#username", "value": "tester"},
            requested_by="test",
        )
    )
    assert fill.status == BrowserActionStatus.COMPLETED
    service.execute_action(BrowserAction(action_type="get_network_requests", requested_by="test"))
    service.execute_action(BrowserAction(action_type="get_console_messages", requested_by="test"))
    screenshot = service.execute_action(
        BrowserAction(
            action_type="take_screenshot",
            parameters={"width": 800, "height": 600},
            requested_by="test",
        )
    )
    assert screenshot.status == BrowserActionStatus.COMPLETED

    # Runtime observations must already be durable before the session finishes, so a UI
    # refresh or worker failure does not erase captured browser evidence.
    persisted_network = store.list_network(owner_id="owner-a", session=service.session)
    persisted_console = store.list_console(owner_id="owner-a", session=service.session)
    assert len(persisted_network) == 1
    assert persisted_network[0].path == "/api/profile"
    assert len(persisted_console) == 1
    assert persisted_console[0].message == "safe fixture message"

    report = service.finish()
    assert report.screenshots[0].sha256
    assert (
        tmp_path / "workspace-test" / "browser-test-session" / "screenshots" / "0004-00.png"
    ).is_file()
    assert len(store.list_receipts(owner_id="owner-a", session=service.session)) == 4
    assert store.load_report(owner_id="owner-a", session=service.session) == report
    assert runtime.closed is True


def test_service_blocks_screenshot_before_persisting_when_evidence_budget_is_exceeded(
    tmp_path: Path,
) -> None:
    runtime = _LargeScreenshotRuntime()
    session = _session(datetime.now(UTC))
    store = BrowserIntelligenceStore(tmp_path)
    store.save_session(session)
    service = BrowserIntelligenceService(
        session=session,
        target=_target(),
        policy=BrowserPolicy(
            target=_target(),
            authorization_id="authorization-test",
            mode=BrowserMode.CONTROLLED_INTERACTIVE,
            limits=BrowserActionLimits(maximum_screenshots=2, maximum_evidence_bytes=1_024),
        ),
        runtime=runtime,
        store=store,
        owner_id="owner-a",
    )

    screenshot = service.execute_action(
        BrowserAction(
            action_type="take_screenshot",
            parameters={"width": 800, "height": 600},
            requested_by="test",
        )
    )

    assert screenshot.status == BrowserActionStatus.BLOCKED
    assert screenshot.error_message == "browser evidence byte budget is exhausted"
    assert service.session.screenshot_count == 0
    assert service.session.evidence_ids == ()
    assert not (
        tmp_path / "workspace-test" / "browser-test-session" / "screenshots" / "0001-00.png"
    ).exists()
