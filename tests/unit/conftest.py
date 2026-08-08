from pathlib import Path

import pytest


@pytest.fixture(autouse=True)
def freeze_remediation_graph_clock_for_fixed_time_web_fixtures(request, monkeypatch):
    """Keep fixed-time remediation web fixtures independent of wall-clock date."""

    if request.module.__name__ not in {
        "test_final_remediation_report_web",
        "test_independent_remediation_review_web",
    }:
        return

    from django.conf import settings

    from vulnhunter.assessment_graph import RemediationAssessmentGraphService
    import vulnhunter.web.remediation_assessment_graph as graph_module

    clock = lambda: request.module.NOW
    monkeypatch.setattr(
        graph_module,
        "_service",
        lambda: RemediationAssessmentGraphService(
            Path(settings.VULNHUNTER_TASK_GRAPH_ROOT),
            clock=clock,
        ),
    )
