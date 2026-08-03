from __future__ import annotations

from django.urls import path

from vulnhunter.web.conversation_mobile_retry_views import mobile_retry_view
from vulnhunter.web.urls_base import urlpatterns as base_urlpatterns

urlpatterns = [
    *base_urlpatterns,
    path(
        "workspace/mobile-retry/",
        mobile_retry_view,
        name="web-conversation-mobile-retry",
    ),
]
