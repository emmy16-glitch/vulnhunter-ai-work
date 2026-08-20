from django.urls import path

from vulnhunter.api.views import (
    AssessmentDetailView,
    AssessmentEventsView,
    AssessmentListView,
    MeView,
    ReadinessView,
    RealtimeTicketView,
)

urlpatterns = [
    path("me/", MeView.as_view(), name="api-v1-me"),
    path("readiness/", ReadinessView.as_view(), name="api-v1-readiness"),
    path("assessments/", AssessmentListView.as_view(), name="api-v1-assessments"),
    path(
        "assessments/<str:assessment_id>/",
        AssessmentDetailView.as_view(),
        name="api-v1-assessment-detail",
    ),
    path(
        "assessments/<str:assessment_id>/events/",
        AssessmentEventsView.as_view(),
        name="api-v1-assessment-events",
    ),
    path("realtime/ticket/", RealtimeTicketView.as_view(), name="api-v1-realtime-ticket"),
]
