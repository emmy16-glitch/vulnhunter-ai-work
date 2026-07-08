from vulnhunter.observations.analyzers import analyze_response
from vulnhunter.scanner.models import SafeHttpResponse
from vulnhunter.scope.models import ScopedUrl


def response(*, status=200, headers=None, body=b"ok", url="http://lab.internal:8000/app/"):
    scoped = ScopedUrl(
        url=url,
        scheme="http",
        hostname="lab.internal",
        port=8000,
        path="/app/",
        resolved_addresses=("10.0.0.5",),
    )
    return SafeHttpResponse(
        method="GET",
        final_url=scoped,
        status_code=status,
        headers=headers or {},
        body=body,
        elapsed_ms=1,
    )


def test_reports_missing_security_headers_and_clickjacking_protection():
    observations = analyze_response(response(headers={"content-type": "text/html"}))
    categories = {item.category for item in observations}
    assert "missing_security_headers" in categories
    assert "clickjacking_protection_missing" in categories


def test_accepts_csp_frame_ancestors_as_clickjacking_protection():
    observations = analyze_response(
        response(
            headers={
                "content-type": "text/html",
                "content-security-policy": "default-src 'self'; frame-ancestors 'none'",
                "x-content-type-options": "nosniff",
                "referrer-policy": "same-origin",
            }
        )
    )
    assert "clickjacking_protection_missing" not in {item.category for item in observations}


def test_reports_debug_error_without_storing_body():
    observations = analyze_response(
        response(
            status=500,
            body=b"Traceback (most recent call last): secret-value",
            headers={"content-type": "text/html"},
        )
    )
    item = next(x for x in observations if x.category == "debug_error_exposure")
    assert item.severity == "high"
    assert "secret-value" not in str(item.evidence)
    assert "secret-value" not in item.description


def test_reports_directory_listing():
    observations = analyze_response(
        response(
            body=b"<html><title>Index of /files</title><h1>Index of /files</h1></html>",
            headers={"content-type": "text/html"},
        )
    )
    assert "directory_listing" in {item.category for item in observations}
