from django.urls import path

from vulnhunter.realtime.consumers import AssessmentEventsConsumer

websocket_urlpatterns = [
    path(
        "ws/api/v1/assessments/<str:assessment_id>/events/",
        AssessmentEventsConsumer.as_asgi(),
    ),
]
