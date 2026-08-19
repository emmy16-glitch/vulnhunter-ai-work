"""Chat-first Browser Intelligence views with an owner-scoped Obscura manager."""

from __future__ import annotations

import json
import threading
from pathlib import Path
from typing import Any

from django.conf import settings
from django.contrib.auth.decorators import login_required
from django.http import FileResponse, Http404, JsonResponse
from django.views.decorators.http import require_GET, require_POST

from vulnhunter.authorization.service import validate_scan_authorization
from vulnhunter.authorization.store import AuthorizationStore
from vulnhunter.browser_intelligence import (
    BrowserAction,
    BrowserActionType,
    BrowserIntelligenceService,
    BrowserIntelligenceStore,
    BrowserMode,
    BrowserPolicy,
    BrowserRuntimeName,
)
from vulnhunter.browser_intelligence.activation import (
    BrowserActivationConfig,
    BrowserActivationError,
)
from vulnhunter.scope.validator import validate_target
from vulnhunter.web.services import WebPermissionDenied, authorized_actor


class BrowserIntelligenceWebError(ValueError):
    """Raised for safe, user-facing Browser Intelligence request errors."""


class _RuntimeManager:
    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._services: dict[str, BrowserIntelligenceService] = {}

    def register(self, service: BrowserIntelligenceService) -> None:
        with self._lock:
            self._services[service.session.session_id] = service

    def get(self, session_id: str) -> BrowserIntelligenceService | None:
        with self._lock:
            return self._services.get(session_id)

    def remove(self, session_id: str) -> BrowserIntelligenceService | None:
        with self._lock:
            return self._services.pop(session_id, None)


_RUNTIME_MANAGER = _RuntimeManager()


def _store() -> BrowserIntelligenceStore:
    root = Path(
        getattr(
            settings, "VULNHUNTER_BROWSER_INTELLIGENCE_ROOT", "/tmp/vulnhunter-browser-intelligence"
        )
    )
    return BrowserIntelligenceStore(root)


def _actor(request):
    return authorized_actor(request.user, required_actions=("scan.create",))


def _json_body(request) -> dict[str, Any]:
    try:
        body = json.loads(request.body.decode("utf-8") or "{}")
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise BrowserIntelligenceWebError("Request body must be valid JSON.") from exc
    if not isinstance(body, dict):
        raise BrowserIntelligenceWebError("Request body must be an object.")
    return body


def _validate_target_and_authorization(body: dict[str, Any]):
    target_url = body.get("target_url")
    authorization_id = body.get("authorization_id")
    if not isinstance(target_url, str) or not target_url.strip():
        raise BrowserIntelligenceWebError("An authorized target URL is required.")
    if not isinstance(authorization_id, str) or not authorization_id.strip():
        raise BrowserIntelligenceWebError("An authorization reference is required.")
    try:
        target = validate_target(target_url.strip(), allow_public=True)
        authorization_store = AuthorizationStore.from_path(
            Path(settings.VULNHUNTER_AUTHORIZATION_DATABASE)
        )
        authorization_store.initialize()
        validate_scan_authorization(
            authorization_store,
            authorization_id.strip(),
            target,
            maximum_pages=5,
            maximum_depth=2,
            maximum_requests=50,
            request_delay_seconds=0.2,
            allow_public=True,
        )
    except Exception as exc:
        raise BrowserIntelligenceWebError(
            "The target or authorization could not be validated."
        ) from exc
    return target, authorization_id.strip()


def _service_for_request(request, body: dict[str, Any]) -> BrowserIntelligenceService:
    target, authorization_id = _validate_target_and_authorization(body)
    try:
        activation = BrowserActivationConfig.from_environment()
        runtime = activation.build_obscura()
    except BrowserActivationError as exc:
        raise BrowserIntelligenceWebError(str(exc)) from exc
    if runtime is None:
        raise BrowserIntelligenceWebError(
            "Browser Intelligence is unavailable because the Obscura runtime is not enabled."
        )
    actor = _actor(request)
    workspace_id = str(body.get("workspace_id") or request.session.session_key or "workspace")
    owner_id = str(actor.governance_identity.reviewer_id)
    policy = BrowserPolicy(
        target=target,
        authorization_id=authorization_id,
        mode=BrowserMode.PASSIVE,
    )
    return BrowserIntelligenceService.create_session(
        assessment_id=str(body.get("assessment_id") or f"browser-assessment-{request.user.pk}"),
        attempt_id=str(body.get("attempt_id")) if body.get("attempt_id") else None,
        workspace_id=workspace_id,
        owner_id=owner_id,
        authorization_id=authorization_id,
        target=target,
        policy=policy,
        runtime=runtime,
        store=_store(),
    )


def _session_payload(service: BrowserIntelligenceService) -> dict[str, Any]:
    session = service.session
    return {
        "session": session.model_dump(mode="json"),
        "capabilities": session.capabilities.model_dump(mode="json"),
        "runtime": BrowserRuntimeName.OBSCURA.value,
        "allowed_actions": [item.value for item in BrowserActionType],
        "blocked_actions": ["evaluate", "request_interception", "response_mutation"],
    }


def _error_response(exc: Exception, status: int = 400) -> JsonResponse:
    return JsonResponse({"ok": False, "error": str(exc)}, status=status)


@login_required
@require_POST
def browser_intelligence_start_view(request):
    try:
        service = _service_for_request(request, _json_body(request))
        _RUNTIME_MANAGER.register(service)
        payload = _session_payload(service)
        payload["ok"] = True
        payload["message"] = {
            "role": "assistant",
            "kind": "browser_intelligence",
            "content": "Browser Intelligence is ready for the authorized target.",
            "metadata": dict(payload),
        }
        return JsonResponse(payload, status=201)
    except WebPermissionDenied as exc:
        return _error_response(exc, 403)
    except BrowserIntelligenceWebError as exc:
        return _error_response(exc, 400)
    except Exception:
        return _error_response(
            BrowserIntelligenceWebError("Browser Intelligence could not start safely."), 503
        )


@login_required
@require_POST
def browser_intelligence_action_view(request, session_id: str):
    try:
        actor = _actor(request)
        service = _RUNTIME_MANAGER.get(session_id)
        if service is None or service.session.owner_id != str(
            actor.governance_identity.reviewer_id
        ):
            raise BrowserIntelligenceWebError("Browser session is unavailable or not accessible.")
        body = _json_body(request)
        action_name = body.get("action")
        if not isinstance(action_name, str):
            raise BrowserIntelligenceWebError("A typed browser action is required.")
        try:
            action_type = BrowserActionType(action_name)
        except ValueError as exc:
            raise BrowserIntelligenceWebError("Unknown browser action rejected.") from exc
        parameters = body.get("parameters", {})
        if not isinstance(parameters, dict):
            raise BrowserIntelligenceWebError("Browser action parameters must be an object.")
        receipt = service.execute_action(
            BrowserAction(
                action_type=action_type,
                parameters=parameters,
                requested_by=str(actor.governance_identity.reviewer_id),
            )
        )
        return JsonResponse(
            {
                "ok": True,
                "receipt": receipt.model_dump(mode="json"),
                "session": service.session.model_dump(mode="json"),
            }
        )
    except WebPermissionDenied as exc:
        return _error_response(exc, 403)
    except BrowserIntelligenceWebError as exc:
        return _error_response(exc, 400)


@login_required
@require_GET
def browser_intelligence_state_view(request, session_id: str):
    try:
        actor = _actor(request)
        service = _RUNTIME_MANAGER.get(session_id)
        if service is None or service.session.owner_id != str(
            actor.governance_identity.reviewer_id
        ):
            raise BrowserIntelligenceWebError("Browser session is unavailable or not accessible.")
        return JsonResponse({"ok": True, **_session_payload(service)})
    except WebPermissionDenied as exc:
        return _error_response(exc, 403)
    except BrowserIntelligenceWebError as exc:
        return _error_response(exc, 404)


@login_required
@require_POST
def browser_intelligence_finish_view(request, session_id: str):
    try:
        actor = _actor(request)
        service = _RUNTIME_MANAGER.get(session_id)
        if service is None or service.session.owner_id != str(
            actor.governance_identity.reviewer_id
        ):
            raise BrowserIntelligenceWebError("Browser session is unavailable or not accessible.")
        body = _json_body(request)
        report = service.finish(cancelled=bool(body.get("cancelled", False)))
        _RUNTIME_MANAGER.remove(session_id)
        return JsonResponse({"ok": True, "report": report.model_dump(mode="json")})
    except WebPermissionDenied as exc:
        return _error_response(exc, 403)
    except BrowserIntelligenceWebError as exc:
        return _error_response(exc, 404)


@login_required
@require_GET
def browser_intelligence_evidence_view(request, session_id: str, relative_path: str):
    try:
        actor = _actor(request)
        store = _store()
        session = store.load_session(
            session_id,
            owner_id=str(actor.governance_identity.reviewer_id),
            workspace_id=str(
                request.GET.get("workspace_id") or request.session.session_key or "workspace"
            ),
        )
        path = store.artifact_path(session.workspace_id, session.session_id, relative_path)
        if path.suffix.casefold() != ".png" or not path.is_file():
            raise Http404
        return FileResponse(path.open("rb"), content_type="image/png")
    except WebPermissionDenied as exc:
        return _error_response(exc, 403)
    except Exception as exc:
        if isinstance(exc, Http404):
            raise
        raise Http404 from exc
