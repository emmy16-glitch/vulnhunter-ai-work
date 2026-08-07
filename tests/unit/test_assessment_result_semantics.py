from pathlib import Path

SCRIPT = Path("vulnhunter/web/static/web/conversation-mobile-inspector.js")
TEMPLATE = Path("vulnhunter/web/templates/web/_mobile_analysis_inspector.html")


def _script() -> str:
    return SCRIPT.read_text(encoding="utf-8")


def _template() -> str:
    return TEMPLATE.read_text(encoding="utf-8")


def test_findings_keep_rejected_records_and_surface_persisted_verification_outcomes() -> None:
    script = _script()

    assert 'safeArray(hunt()?.rejected).map((candidate) =>' in script
    assert 'state: "rejected"' in script
    assert 'const findings = [...candidates, ...rejected]' in script
    assert '["verified", "rejected", "abstained", "mixed"]' in script
    assert 'title.textContent = "Persisted verification outcome"' in script
    assert 'verification.abstained_count' in script
    assert '.filter(\n      (candidate) => candidate.state !== "rejected"' not in script


def test_finding_count_comes_from_authoritative_projection_or_stays_unavailable() -> None:
    script = _script()

    assert 'const projectedFindings = state.projection?.findings || {}' in script
    assert 'String(candidateCount + rejectedCount)' in script
    assert ': "—";' in script
    assert 'Number.isInteger(candidateCount) && Number.isInteger(rejectedCount)' in script


def test_graph_is_hidden_until_persisted_relationships_are_meaningful() -> None:
    script = _script()
    template = _template()

    assert 'graphSection: select("graph-section")' in script
    assert 'const meaningful = nodes.length > 1 && edges.length > 0' in script
    assert 'elements.graphSection.hidden = !meaningful' in script
    assert 'if (!meaningful) return;' in script
    assert 'data-inspector-graph-section hidden' in template
    assert 'data-inspector-tab="graph"' not in template


def test_graph_summary_never_treats_a_lone_artifact_as_an_attack_path() -> None:
    script = _script()

    meaningful = script.index('const meaningful = nodes.length > 1 && edges.length > 0')
    canvas = script.index('const canvas = document.createElement("div")', meaningful)
    guard = script.index('if (!meaningful) return;', meaningful)
    assert meaningful < guard < canvas
