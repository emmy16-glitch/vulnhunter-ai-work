"""Passive, non-destructive security analysis of bounded HTTP responses."""

from __future__ import annotations

from bs4 import BeautifulSoup

from vulnhunter.observations.models import Observation
from vulnhunter.scanner.models import SafeHttpResponse

_BASELINE_SECURITY_HEADERS = {
    "content-security-policy": "Content-Security-Policy",
    "x-content-type-options": "X-Content-Type-Options",
    "referrer-policy": "Referrer-Policy",
}

_DEBUG_INDICATORS = (
    "traceback (most recent call last)",
    "django debug",
    "stack trace",
    "uncaught exception",
    "fatal error:",
    "werkzeug debugger",
)


def _normalise_headers(headers: dict[str, str]) -> dict[str, str]:
    return {name.lower(): value for name, value in headers.items()}


def _decode_text(response: SafeHttpResponse) -> str:
    return response.body.decode("utf-8", errors="replace")


def _security_header_observations(
    response: SafeHttpResponse,
    headers: dict[str, str],
) -> list[Observation]:
    required_headers = dict(_BASELINE_SECURITY_HEADERS)

    if response.final_url.scheme == "https":
        required_headers["strict-transport-security"] = "Strict-Transport-Security"

    missing = [
        display_name
        for header_name, display_name in required_headers.items()
        if header_name not in headers
    ]

    observations: list[Observation] = []

    if missing:
        severity = "medium" if "Content-Security-Policy" in missing else "low"
        observations.append(
            Observation.create(
                category="missing_security_headers",
                severity=severity,
                title="Recommended security headers are missing",
                description=(
                    "The response omitted one or more defensive HTTP headers. "
                    "This is a passive configuration signal and requires human review."
                ),
                url=response.final_url.url,
                evidence={"missing_headers": missing},
            )
        )

    content_security_policy = headers.get("content-security-policy", "").lower()
    has_frame_ancestors = "frame-ancestors" in content_security_policy
    has_x_frame_options = "x-frame-options" in headers

    if not has_frame_ancestors and not has_x_frame_options:
        observations.append(
            Observation.create(
                category="clickjacking_protection_missing",
                severity="medium",
                title="Clickjacking protection was not detected",
                description=(
                    "Neither X-Frame-Options nor a CSP frame-ancestors directive "
                    "was detected on the response."
                ),
                url=response.final_url.url,
                evidence={
                    "x_frame_options_present": has_x_frame_options,
                    "csp_frame_ancestors_present": has_frame_ancestors,
                },
            )
        )

    return observations


def _technology_disclosure_observation(
    response: SafeHttpResponse,
    headers: dict[str, str],
) -> Observation | None:
    disclosed_headers = {
        name: headers[name]
        for name in ("server", "x-powered-by")
        if name in headers and headers[name].strip()
    }

    if not disclosed_headers:
        return None

    return Observation.create(
        category="technology_disclosure",
        severity="info",
        title="Server technology details were disclosed",
        description=(
            "The response exposed implementation details through HTTP headers. "
            "This is informational and should be reviewed in context."
        ),
        url=response.final_url.url,
        evidence={"headers": disclosed_headers},
    )


def _debug_exposure_observation(response: SafeHttpResponse) -> Observation | None:
    if response.status_code < 500 or not response.body:
        return None

    body_text = _decode_text(response).lower()
    detected = sorted({indicator for indicator in _DEBUG_INDICATORS if indicator in body_text})

    if not detected:
        return None

    return Observation.create(
        category="debug_error_exposure",
        severity="high",
        title="Detailed application error information was exposed",
        description=(
            "A server-error response contained indicators associated with stack traces "
            "or development debug pages. Raw response content was not persisted."
        ),
        url=response.final_url.url,
        evidence={
            "status_code": response.status_code,
            "detected_indicators": detected,
        },
    )


def _directory_listing_observation(
    response: SafeHttpResponse,
    headers: dict[str, str],
) -> Observation | None:
    content_type = headers.get("content-type", "").lower()

    if response.status_code != 200 or "html" not in content_type:
        return None

    soup = BeautifulSoup(response.body, "html.parser")
    title = soup.title.get_text(" ", strip=True).lower() if soup.title else ""
    heading = soup.find("h1")
    heading_text = heading.get_text(" ", strip=True).lower() if heading else ""

    if not (title.startswith("index of /") or heading_text.startswith("index of /")):
        return None

    return Observation.create(
        category="directory_listing",
        severity="medium",
        title="Directory listing appears to be enabled",
        description=(
            "The HTML page resembles an automatically generated directory index. "
            "Verify whether file enumeration is intended."
        ),
        url=response.final_url.url,
        evidence={"page_title": title[:200], "heading": heading_text[:200]},
    )


def analyze_response(response: SafeHttpResponse) -> tuple[Observation, ...]:
    """Return passive observations without mutating or probing the target."""
    headers = _normalise_headers(response.headers)
    observations = _security_header_observations(response, headers)

    for optional_observation in (
        _technology_disclosure_observation(response, headers),
        _debug_exposure_observation(response),
        _directory_listing_observation(response, headers),
    ):
        if optional_observation is not None:
            observations.append(optional_observation)

    return tuple(observations)
