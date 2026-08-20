from __future__ import annotations

from secrets import token_urlsafe

from django.core import signing
from django.http import Http404
from django.utils import timezone
from rest_framework.authentication import SessionAuthentication
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from vulnhunter.web.conversational_views import (
    _conversation_stream_payload,
    _recent_runs,
    _run_payload,
    _visible_run,
)
from vulnhunter.web.readiness import deployment_readiness
from vulnhunter.web.services import (
    WebPermissionDenied,
    authorized_actor,
)

_REALTIME_TICKET_SALT = "vulnhunter.realtime.ticket.v1"
_REALTIME_TICKET_MAX_AGE_SECONDS = 60


def _actor(request):
    try:
        return authorized_actor(request.user, required_actions=("scan.read",))
    except WebPermissionDenied as exc:
        from rest_framework.exceptions import PermissionDenied

        raise PermissionDenied(str(exc)) from exc


class APIBaseView(APIView):
    authentication_classes = (SessionAuthentication,)
    permission_classes = (IsAuthenticated,)


class MeView(APIBaseView):
    def get(self, request):
        actor = _actor(request)
        return Response(
            {
                "id": str(request.user.pk),
                "username": request.user.get_username(),
                "roles": list(actor.product_roles),
                "reviewer_id": actor.governance_identity.reviewer_id,
            }
        )


class ReadinessView(APIBaseView):
    def get(self, request):
        _actor(request)
        report = deployment_readiness()
        return Response(report.as_payload(), status=200 if report.ready else 503)


class AssessmentListView(APIBaseView):
    def get(self, request):
        actor = _actor(request)
        try:
            assessments = list(_recent_runs(actor))
        except (OSError, RuntimeError, ValueError):
            assessments = []
        return Response({"results": assessments, "count": len(assessments)})


class AssessmentDetailView(APIBaseView):
    def get(self, request, assessment_id: str):
        actor = _actor(request)
        try:
            run = _visible_run(assessment_id, actor)
        except Http404 as exc:
            raise Http404("Assessment does not exist.") from exc
        return Response(_run_payload(run))


class AssessmentEventsView(APIBaseView):
    def get(self, request, assessment_id: str):
        actor = _actor(request)
        try:
            run = _visible_run(assessment_id, actor)
        except Http404 as exc:
            raise Http404("Assessment does not exist.") from exc
        try:
            after_sequence = int(request.query_params.get("after_sequence", "0"))
        except (TypeError, ValueError) as exc:
            from rest_framework.exceptions import ValidationError

            raise ValidationError({"after_sequence": "Must be a non-negative integer."}) from exc
        if after_sequence < 0:
            from rest_framework.exceptions import ValidationError

            raise ValidationError({"after_sequence": "Must be a non-negative integer."})
        payload = _conversation_stream_payload(run, after_sequence=after_sequence)
        events = payload.get("events") if isinstance(payload.get("events"), list) else []
        return Response(
            {
                "assessment_id": assessment_id,
                "events": events,
                "last_sequence": int(payload.get("last_sequence", after_sequence)),
                "run_state": payload.get("run_state"),
                "terminal": bool(payload.get("terminal", False)),
                "activity_tree": payload.get("activity_tree")
                or {
                    "schema_version": "1.0",
                    "task_id": assessment_id,
                    "status": "running",
                    "last_sequence": int(payload.get("last_sequence", after_sequence)),
                    "nodes": [],
                },
            }
        )


class RealtimeTicketView(APIBaseView):
    def post(self, request):
        actor = _actor(request)
        assessment_id = str(request.data.get("assessment_id") or "").strip()
        if not assessment_id:
            from rest_framework.exceptions import ValidationError

            raise ValidationError({"assessment_id": "This field is required."})
        try:
            _visible_run(assessment_id, actor)
        except Http404 as exc:
            raise Http404("Assessment does not exist.") from exc
        issued_at = timezone.now()
        payload = {
            "ticket_id": token_urlsafe(18),
            "assessment_id": assessment_id,
            "user_id": str(request.user.pk),
            "reviewer_id": actor.governance_identity.reviewer_id,
            "issued_at": issued_at.isoformat(),
        }
        token = signing.dumps(payload, salt=_REALTIME_TICKET_SALT, compress=True)
        return Response(
            {
                "ticket": token,
                "expires_in": _REALTIME_TICKET_MAX_AGE_SECONDS,
                "assessment_id": assessment_id,
            },
            status=201,
        )


def decode_realtime_ticket(token: str) -> dict[str, object]:
    return signing.loads(
        token,
        salt=_REALTIME_TICKET_SALT,
        max_age=_REALTIME_TICKET_MAX_AGE_SECONDS,
    )
