from vulnhunter.advanced import (
    AdvancedAssessmentPlanner,
    AssessmentProfile,
    AssessmentRequest,
)
from vulnhunter.security_tools.catalog import default_catalog


def test_deep_discovery_builds_hash_bound_multi_tool_graph():
    request = AssessmentRequest(
        assessment_id="assessment-01",
        campaign_id="campaign-01",
        run_id="run-01",
        requested_by="operator-01",
        profile=AssessmentProfile.DEEP_DISCOVERY,
        target_references=("target-network-01",),
        authorization_references=("authorization-01",),
    )
    manifests, graph = AdvancedAssessmentPlanner(default_catalog()).build(request)
    assert [manifest.tool_id for manifest in manifests] == [
        "amass",
        "nmap",
        "httpx",
        "testssl",
    ]
    assert len(graph.nodes) == 4
    assert graph.nodes[1].dependencies == (graph.nodes[0].node_id,)
    assert all(manifest.approval_required for manifest in manifests)


def test_validation_profile_uses_separately_approved_tools():
    request = AssessmentRequest(
        assessment_id="assessment-02",
        campaign_id="campaign-01",
        run_id="run-02",
        requested_by="operator-01",
        profile=AssessmentProfile.EXPLOITABILITY_VALIDATION,
        target_references=("candidate-finding-01",),
        authorization_references=("authorization-01",),
    )
    manifests, _ = AdvancedAssessmentPlanner(default_catalog()).build(request)
    assert [manifest.tool_id for manifest in manifests] == ["sqlmap", "metasploit"]
    assert all(manifest.approval_required for manifest in manifests)
