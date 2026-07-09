"""Deterministic controlled benchmark scenario catalog."""

from __future__ import annotations

from html import escape

from vulnhunter.benchmark.models import BenchmarkPage, BenchmarkScenario

CATALOG_VERSION = 1


def _root_page(scenario_id: str, title: str, links: tuple[str, ...]) -> BenchmarkPage:
    root = f"/benchmark/{scenario_id}/"
    link_markup = "\n".join(
        f'<li><a href="{escape(link)}">{escape(link)}</a></li>' for link in links
    )
    return BenchmarkPage(
        path=root,
        body=(
            "<!doctype html><html><head>"
            f"<title>{escape(title)}</title></head><body>"
            f"<h1>{escape(title)}</h1><ul>{link_markup}</ul>"
            '<a href="/outside-benchmark/">Outside scenario</a>'
            "</body></html>"
        ),
    )


def _page(
    scenario_id: str,
    relative_path: str,
    title: str,
    *,
    body: str | None = None,
    status_code: int = 200,
    headers: tuple[tuple[str, str], ...] = (),
) -> BenchmarkPage:
    return BenchmarkPage(
        path=f"/benchmark/{scenario_id}/{relative_path}",
        status_code=status_code,
        headers=headers,
        body=body
        or (
            "<!doctype html><html><head>"
            f"<title>{escape(title)}</title></head><body>"
            f"<h1>{escape(title)}</h1></body></html>"
        ),
    )


def _confirmed_scenario(scenario_id: str, title: str, technology: str) -> BenchmarkScenario:
    return BenchmarkScenario(
        scenario_id=scenario_id,
        title=title,
        suggested_label="confirmed",
        rationale=(
            "This controlled scenario represents a sensitive application where the "
            "passive findings are deliberately present and should be confirmed after "
            "reviewing the generated evidence."
        ),
        pages=(
            _root_page(
                scenario_id,
                title,
                ("login.html", "files/", "error.html"),
            ),
            _page(
                scenario_id,
                "login.html",
                "Sensitive sign-in",
                headers=(("X-Powered-By", technology),),
            ),
            _page(
                scenario_id,
                "files/",
                "Private files",
                body=(
                    "<!doctype html><html><head><title>Index of /private/</title>"
                    "</head><body><h1>Index of /private/</h1>"
                    '<a href="backup.zip">backup.zip</a></body></html>'
                ),
            ),
            _page(
                scenario_id,
                "error.html",
                "Application failure",
                status_code=500,
                headers=(("Server", technology),),
                body=(
                    "<!doctype html><html><head><title>Application failure</title>"
                    "</head><body><h1>Unhandled failure</h1>"
                    "<pre>Traceback (most recent call last):\n"
                    "RuntimeError: controlled benchmark exception</pre>"
                    "</body></html>"
                ),
            ),
        ),
        required_categories=(
            "missing_security_headers",
            "clickjacking_protection_missing",
            "technology_disclosure",
            "directory_listing",
            "debug_error_exposure",
        ),
    )


def _false_positive_scenario(
    scenario_id: str,
    title: str,
    technology: str,
) -> BenchmarkScenario:
    return BenchmarkScenario(
        scenario_id=scenario_id,
        title=title,
        suggested_label="false_positive",
        rationale=(
            "This controlled scenario represents intentionally public, non-sensitive, "
            "and embeddable static content. The passive signals are expected, but the "
            "benchmark context treats them as false-positive vulnerability reports."
        ),
        pages=(
            _root_page(
                scenario_id,
                title,
                ("guide.html", "widget.html", "about.html"),
            ),
            _page(
                scenario_id,
                "guide.html",
                "Public documentation guide",
                headers=(("X-Powered-By", technology),),
            ),
            _page(
                scenario_id,
                "widget.html",
                "Intentionally embeddable public widget",
            ),
            _page(
                scenario_id,
                "about.html",
                "Public project information",
                headers=(("Server", technology),),
            ),
        ),
        required_categories=(
            "missing_security_headers",
            "clickjacking_protection_missing",
            "technology_disclosure",
        ),
    )


SCENARIOS: tuple[BenchmarkScenario, ...] = (
    _confirmed_scenario("sensitive-admin-alpha", "Sensitive admin alpha", "AlphaStack/1.4"),
    _confirmed_scenario("sensitive-admin-beta", "Sensitive admin beta", "BetaStack/2.1"),
    _confirmed_scenario("legacy-operations", "Legacy operations portal", "LegacyOps/7.0"),
    _false_positive_scenario("public-docs-alpha", "Public documentation alpha", "DocsGen/3.2"),
    _false_positive_scenario("public-docs-beta", "Public documentation beta", "DocsGen/4.0"),
    _false_positive_scenario("embeddable-widget", "Embeddable public widget", "WidgetHost/1.1"),
)


def get_scenario(scenario_id: str) -> BenchmarkScenario:
    """Return one catalog scenario or raise a clear error."""
    for scenario in SCENARIOS:
        if scenario.scenario_id == scenario_id:
            return scenario
    raise ValueError(f"Unknown benchmark scenario: {scenario_id}")
