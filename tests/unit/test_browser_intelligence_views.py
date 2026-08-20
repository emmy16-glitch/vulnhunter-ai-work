from __future__ import annotations

import json
from types import SimpleNamespace
from unittest.mock import Mock, patch

from django.test import RequestFactory

from vulnhunter.browser_intelligence import BrowserMode
from vulnhunter.web import browser_intelligence_views as views


def _user() -> SimpleNamespace:
    return SimpleNamespace(is_authenticated=True, is_active=True, pk=7)


def _service() -> SimpleNamespace:
    capabilities = SimpleNamespace(
        screenshot_available=True,
        network_available=True,
        console_available=True,
        forms_available=True,
        interactive_elements_available=True,
        model_dump=lambda mode=None: {
            "screenshot_available": True,
            "network_available": True,
            "console_available": True,
            "forms_available": True,
            "interactive_elements_available": True,
        },
    )
    session = SimpleNamespace(
        session_id="browser-session-1",
        owner_id="reviewer-1",
        runtime="obscura",
        runtime_version="0.2.0",
        mode=BrowserMode.PASSIVE,
        capabilities=capabilities,
        model_dump=lambda mode=None: {
            "session_id": "browser-session-1",
            "owner_id": "reviewer-1",
            "mode": "passive",
        },
    )
    service = SimpleNamespace(session=session)
    service.execute_action = Mock(
        return_value=SimpleNamespace(
            status="completed",
            action_type="snapshot",
            result_summary={},
            model_dump=lambda mode=None: {"status": "completed", "action_type": "snapshot"},
        )
    )
    return service


def test_start_returns_authoritative_session_and_message():
    factory = RequestFactory()
    request = factory.post(
        "/workspace/browser-intelligence/start/",
        data=json.dumps(
            {"target_url": "https://authorized.example/", "authorization_id": "auth-1"}
        ),
        content_type="application/json",
    )
    request.user = _user()
    request.session = {"session_key": "workspace-1"}
    service = _service()

    with patch.object(views, "_service_for_request", return_value=service):
        response = views.browser_intelligence_start_view(request)

    assert response.status_code == 201
    payload = json.loads(response.content)
    assert payload["ok"] is True
    assert payload["session"]["session_id"] == "browser-session-1"
    assert payload["message"]["kind"] == "browser_intelligence"
    assert payload["runtime_attached"] is True
    assert "snapshot" in payload["allowed_actions"]
    assert "take_screenshot" in payload["allowed_actions"]
    assert "fill" not in payload["allowed_actions"]
    assert "type" not in payload["allowed_actions"]
    assert "select_option" not in payload["allowed_actions"]
    assert payload["blocked_actions"] == [
        "evaluate",
        "request_interception",
        "response_mutation",
        "fill",
        "type",
        "select_option",
    ]


def test_action_dispatch_is_owner_bound_and_typed():
    factory = RequestFactory()
    request = factory.post(
        "/workspace/browser-intelligence/browser-session-1/action/",
        data=json.dumps({"action": "snapshot", "parameters": {"max_chars": 1000}}),
        content_type="application/json",
    )
    request.user = _user()
    service = _service()
    actor = SimpleNamespace(governance_identity=SimpleNamespace(reviewer_id="reviewer-1"))
    views._RUNTIME_MANAGER.register(service)

    try:
        with patch.object(views, "_actor", return_value=actor):
            response = views.browser_intelligence_action_view(request, "browser-session-1")
    finally:
        views._RUNTIME_MANAGER.remove("browser-session-1")

    assert response.status_code == 200
    service.execute_action.assert_called_once()
    assert json.loads(response.content)["receipt"]["action_type"] == "snapshot"


def test_action_rejects_unknown_action_without_runtime_call():
    factory = RequestFactory()
    request = factory.post(
        "/workspace/browser-intelligence/browser-session-1/action/",
        data=json.dumps({"action": "evaluate", "parameters": {"expression": "1+1"}}),
        content_type="application/json",
    )
    request.user = _user()
    service = _service()
    actor = SimpleNamespace(governance_identity=SimpleNamespace(reviewer_id="reviewer-1"))
    views._RUNTIME_MANAGER.register(service)

    try:
        with patch.object(views, "_actor", return_value=actor):
            response = views.browser_intelligence_action_view(request, "browser-session-1")
    finally:
        views._RUNTIME_MANAGER.remove("browser-session-1")

    assert response.status_code == 400
    service.execute_action.assert_not_called()


def test_action_denies_other_owner_before_runtime_call():
    factory = RequestFactory()
    request = factory.post(
        "/workspace/browser-intelligence/browser-session-1/action/",
        data=json.dumps({"action": "snapshot", "parameters": {}}),
        content_type="application/json",
    )
    request.user = _user()
    service = _service()
    actor = SimpleNamespace(governance_identity=SimpleNamespace(reviewer_id="reviewer-other"))
    views._RUNTIME_MANAGER.register(service)

    try:
        with patch.object(views, "_actor", return_value=actor):
            response = views.browser_intelligence_action_view(request, "browser-session-1")
    finally:
        views._RUNTIME_MANAGER.remove("browser-session-1")

    assert response.status_code == 400
    service.execute_action.assert_not_called()


def test_state_restores_persisted_session_without_spawning_runtime():
    factory = RequestFactory()
    request = factory.get(
        "/workspace/browser-intelligence/browser-session-1/state/?workspace_id=workspace-1"
    )
    request.user = _user()
    request.session = SimpleNamespace(session_key="workspace-1")
    actor = SimpleNamespace(governance_identity=SimpleNamespace(reviewer_id="reviewer-1"))
    persisted_session = _service().session
    store = SimpleNamespace(load_session=Mock(return_value=persisted_session))
    views._RUNTIME_MANAGER.remove("browser-session-1")

    with patch.object(views, "_actor", return_value=actor), patch.object(
        views, "_store", return_value=store
    ):
        response = views.browser_intelligence_state_view(request, "browser-session-1")

    assert response.status_code == 200
    payload = json.loads(response.content)
    assert payload["ok"] is True
    assert payload["runtime_attached"] is False
    assert payload["allowed_actions"] == []
    assert "fill" in payload["blocked_actions"]
    assert "runtime_detached" in payload["blocked_actions"]
    assert "Persisted browser state was restored" in payload["recovery"]
    store.load_session.assert_called_once_with(
        "browser-session-1", owner_id="reviewer-1", workspace_id="workspace-1"
    )
