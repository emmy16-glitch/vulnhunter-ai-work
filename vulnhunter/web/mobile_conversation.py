"""Prepare governed mobile-analysis and hunt plans for the chat workspace."""

from __future__ import annotations

import re
from uuid import uuid4

from vulnhunter.hunt import build_mobile_hunt_plan
from vulnhunter.mobile import (
    MobileAnalysisPlanner,
    MobileAnalysisProfile,
    MobileAnalysisRequest,
)
from vulnhunter.mobile.models import MobileArtifactRecord
from vulnhunter.security_tools.catalog import default_catalog
from vulnhunter.web.conversation_attachments import ConversationAttachment
from vulnhunter.web.mobile_infrastructure import mobile_infrastructure_status

_ID_SANITIZER = re.compile(r"[^a-z0-9._-]+")
_DYNAMIC_TOOL_IDS = ("mobsf", "adb", "frida")


def _identifier(value: str, *, fallback: str) -> str:
    normalized = _ID_SANITIZER.sub("-", value.casefold()).strip("-._")
    if len(normalized) < 2:
        normalized = fallback
    return normalized[:120]


def _profile_request(
    text: str,
    artifact: MobileArtifactRecord,
) -> tuple[MobileAnalysisProfile, MobileAnalysisProfile, bool]:
    lowered = " ".join(text.casefold().split())
    has_native = bool(artifact.native_libraries)
    static_profile = (
        MobileAnalysisProfile.STATIC_AND_NATIVE if has_native else MobileAnalysisProfile.STATIC
    )
    if "retest" in lowered or "test the fix" in lowered:
        return MobileAnalysisProfile.RETEST, MobileAnalysisProfile.RETEST, False
    if any(term in lowered for term in ("dynamic", "runtime", "frida", "emulator")):
        return MobileAnalysisProfile.DYNAMIC, static_profile, True
    if any(
        term in lowered
        for term in ("full", "complete", "thorough", "deep", "everything", "all checks")
    ):
        return MobileAnalysisProfile.FULL, static_profile, True
    if "native" in lowered and has_native:
        return (
            MobileAnalysisProfile.STATIC_AND_NATIVE,
            MobileAnalysisProfile.STATIC_AND_NATIVE,
            False,
        )
    return static_profile, static_profile, False


def _tool_projection(catalog, tool_id: str) -> dict[str, object]:
    definition = catalog.get(tool_id)
    if definition.connector_only:
        gate = "connector"
    elif definition.approval_required:
        gate = "approval"
    else:
        gate = "policy"
    return {
        "tool_id": tool_id,
        "name": definition.display_name,
        "gate": gate,
        "requires_isolation": definition.requires_isolation,
    }


def _deferred_tools(catalog) -> list[dict[str, object]]:
    infrastructure = mobile_infrastructure_status()
    deferred: list[dict[str, object]] = []
    for tool_id in _DYNAMIC_TOOL_IDS:
        readiness = infrastructure[tool_id]
        deferred.append(
            {
                **_tool_projection(catalog, tool_id),
                **readiness,
                "status": readiness["state"],
            }
        )
    return deferred


def build_mobile_chat_plan(
    *,
    text: str,
    requested_by: str,
    attachment: ConversationAttachment,
    artifact: MobileArtifactRecord,
) -> dict[str, object]:
    """Build an immutable task graph and multi-altitude hunt plan without executing tools."""

    requested_profile, effective_profile, dynamic_deferred = _profile_request(text, artifact)
    token = uuid4().hex[:20]
    run_id = f"mobile-{token}"
    analysis_id = f"analysis-{token}"
    catalog = default_catalog()
    request = MobileAnalysisRequest(
        analysis_id=analysis_id,
        campaign_id=f"chat-{token}",
        run_id=run_id,
        requested_by=_identifier(requested_by, fallback="chat-operator"),
        artifact_id=artifact.artifact_id,
        artifact_sha256=artifact.sha256,
        artifact_path=artifact.stored_path,
        profile=effective_profile,
        authorization_references=(f"uploaded-artifact:{attachment.attachment_id}",),
    )
    manifests, graph = MobileAnalysisPlanner(catalog).build(request, artifact)
    selected_tool_ids = tuple(item.tool_id for item in manifests)
    hunt = build_mobile_hunt_plan(
        hunt_id=f"hunt-{token}",
        run_id=run_id,
        artifact=artifact,
        profile=effective_profile.value,
        selected_tool_ids=selected_tool_ids,
        dynamic_deferred=dynamic_deferred,
    )
    tools = [_tool_projection(catalog, tool_id) for tool_id in selected_tool_ids]
    deferred_tools = _deferred_tools(catalog) if dynamic_deferred else []
    rounds = [
        {
            "round_id": item.round_id,
            "altitude": item.altitude.value,
            "label": item.label,
            "purpose": item.purpose,
            "tool_ids": item.tool_ids,
            "status": item.status.value,
            "blocked_reason": item.blocked_reason,
        }
        for item in hunt.rounds
    ]
    deferred_ready = sum(item.get("state") == "approval_required" for item in deferred_tools)
    if dynamic_deferred and deferred_ready == len(deferred_tools):
        dynamic_note = (
            "MobSF and the registered disposable Android runtime are configured, but exact "
            "digest-bound approval is still required before dynamic execution."
        )
    elif dynamic_deferred:
        dynamic_note = (
            "Dynamic execution remains gated. Configure private MobSF and register a disposable "
            "Android emulator before requesting exact digest-bound approval."
        )
    else:
        dynamic_note = None
    return {
        "plan_id": analysis_id,
        "run_id": run_id,
        "task_graph_id": graph.graph_id,
        "plan_digest": hunt.plan_sha256,
        "requested_profile": requested_profile.value,
        "profile": effective_profile.value,
        "status": "prepared",
        "tool_count": len(tools) + len(deferred_tools),
        "executable_tool_count": len(tools),
        "tools": tools,
        "deferred_tools": deferred_tools,
        "rounds": rounds,
        "coverage_cells": len(hunt.coverage),
        "maximum_rounds": hunt.maximum_rounds,
        "dynamic_deferred": dynamic_deferred,
        "dynamic_note": dynamic_note,
        "artifact": attachment.payload(),
    }


def mobile_plan_reply(plan: dict[str, object]) -> str:
    profile = str(plan["profile"]).replace("_", " ")
    tool_count = int(plan["tool_count"])
    rounds = plan.get("rounds", [])
    round_count = len(rounds) if isinstance(rounds, list) else 0
    copy = (
        f"I validated the APK envelope and prepared a bounded {profile} hunt with "
        f"{tool_count} registered tools across {round_count} investigation rounds. "
        "The loop starts with identity and attack-surface coverage, then traces code and native "
        "candidates, challenges them against raw evidence and performs a variant sweep."
    )
    dynamic_note = plan.get("dynamic_note")
    if isinstance(dynamic_note, str) and dynamic_note:
        copy = f"{copy} {dynamic_note}"
    return copy
