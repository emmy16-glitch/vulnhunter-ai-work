import json
from pathlib import Path

from django.test import RequestFactory

from vulnhunter.web.middleware import ContentSecurityPolicyMiddleware

ROOT = Path(__file__).resolve().parents[2]
WEB = ROOT / "vulnhunter" / "web"
STATIC = WEB / "static" / "web"
TEMPLATES = WEB / "templates" / "web"


def _text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def test_legacy_mobile_url_serves_the_unified_workspace():
    urls = _text(WEB / "urls.py")
    assert '"mobile-analysis/"' in urls
    assert "dashboard_dispatch_views.dashboard_view" in urls
    assert "operations_views.mobile_analysis_view" not in urls


def test_workspace_copy_and_shared_product_styles_are_final():
    conversation = _text(TEMPLATES / "conversation.html")
    polish = _text(STATIC / "workspace-polish.css")
    assert "Ask a security question, paste an authorised target" not in conversation
    assert "AI conversation ready" not in conversation
    assert (
        "Message VulnHunter — describe a target, attach an APK, or ask about a finding"
        in conversation
    )
    assert ".vh-product-heading" in polish
    assert '.vh-nav-list li:has(a[href$="/mobile-analysis/"])' not in polish
    assert "--vh-final-sidebar: 264px" in polish


def test_workspace_non_json_failures_are_converted_to_json(settings):
    settings.VULNHUNTER_CSP = "default-src 'self'"
    request = RequestFactory().post(
        "/workspace/attachments/",
        HTTP_ACCEPT="application/json",
    )
    middleware = ContentSecurityPolicyMiddleware(lambda _request: None)
    response = middleware.process_exception(request, RuntimeError("private failure"))
    assert response is not None
    assert response.status_code == 500
    assert response["Content-Type"].startswith("application/json")
    payload = json.loads(response.content)
    assert "could not complete this request" in payload["detail"]
    assert "private failure" not in payload["detail"]


def test_codespaces_setup_is_repeatable_and_mobile_versions_resolve():
    post_create = _text(ROOT / ".devcontainer" / "post-create.sh")
    mobile_tools = _text(ROOT / ".devcontainer" / "install-mobile-static-tools.sh")
    assert 'chmod -R u+w "$TEMPLATE_ROOT"' in post_create
    assert "frida==17.10.1" in mobile_tools
    assert "frida==17.9.11" not in mobile_tools
