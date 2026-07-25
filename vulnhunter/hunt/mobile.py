"""Build deterministic multi-altitude hunt coverage for one Android artifact."""

from __future__ import annotations

import hashlib
import json

from vulnhunter.hunt.models import (
    CoverageCell,
    CoverageStatus,
    HuntAltitude,
    HuntPlan,
    HuntRound,
)
from vulnhunter.mobile.models import MobileArtifactRecord


def _plan_digest(payload: dict[str, object]) -> str:
    encoded = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def build_mobile_hunt_plan(
    *,
    hunt_id: str,
    run_id: str,
    artifact: MobileArtifactRecord,
    profile: str,
    selected_tool_ids: tuple[str, ...],
    dynamic_deferred: bool,
) -> HuntPlan:
    """Create net-new coverage rounds without pretending any tool has run."""

    rounds: list[HuntRound] = [
        HuntRound(
            round_id=f"{hunt_id}-identity",
            altitude=HuntAltitude.ARTIFACT,
            label="APK identity and integrity",
            purpose="Confirm package metadata, SDK levels, signatures, packing and inventory.",
            tool_ids=tuple(
                item for item in ("apksigner", "aapt2", "apkid") if item in selected_tool_ids
            ),
        ),
        HuntRound(
            round_id=f"{hunt_id}-surface",
            altitude=HuntAltitude.ATTACK_SURFACE,
            label="Manifest and attack surface",
            purpose=(
                "Map permissions, exported components, intent filters, backups and "
                "cleartext policy."
            ),
            tool_ids=tuple(
                item for item in ("aapt2", "apktool", "androguard") if item in selected_tool_ids
            ),
        ),
        HuntRound(
            round_id=f"{hunt_id}-code",
            altitude=HuntAltitude.CODE,
            label="Code and data-flow candidates",
            purpose="Trace untrusted inputs into security-sensitive Android and Java sinks.",
            tool_ids=tuple(
                item for item in ("jadx", "androguard", "yara") if item in selected_tool_ids
            ),
        ),
    ]
    if artifact.native_libraries:
        rounds.append(
            HuntRound(
                round_id=f"{hunt_id}-native",
                altitude=HuntAltitude.NATIVE,
                label="Native-library scrutiny",
                purpose="Inspect JNI boundaries, symbols, hardening and native capability indicators.",
                tool_ids=tuple(item for item in ("radare2", "ghidra") if item in selected_tool_ids),
            )
        )
    if dynamic_deferred:
        rounds.append(
            HuntRound(
                round_id=f"{hunt_id}-runtime",
                altitude=HuntAltitude.RUNTIME,
                label="Dynamic runtime validation",
                purpose="Validate selected candidates in a disposable Android runtime.",
                tool_ids=("mobsf", "adb", "frida"),
                status=CoverageStatus.BLOCKED,
                blocked_reason=(
                    "Dynamic analysis needs a separately approved disposable emulator "
                    "and device identity."
                ),
            )
        )
    rounds.extend(
        (
            HuntRound(
                round_id=f"{hunt_id}-verify",
                altitude=HuntAltitude.VERIFICATION,
                label="Adversarial judge and verification",
                purpose="Attempt to disprove candidates using raw evidence before disposition.",
            ),
            HuntRound(
                round_id=f"{hunt_id}-variants",
                altitude=HuntAltitude.VARIANT_SWEEP,
                label="Variant sweep and stopping check",
                purpose=(
                    "Search for sibling instances and stop only after net-new coverage "
                    "is exhausted."
                ),
            ),
        )
    )

    coverage = tuple(
        CoverageCell(
            cell_id=f"{hunt_id}-cell-{index:02d}",
            altitude=round_.altitude,
            object_reference=artifact.artifact_id,
            weakness_class="all-applicable-mobile-classes",
            status=round_.status,
        )
        for index, round_ in enumerate(rounds, start=1)
    )
    digest_payload = {
        "hunt_id": hunt_id,
        "run_id": run_id,
        "artifact_id": artifact.artifact_id,
        "artifact_sha256": artifact.sha256,
        "profile": profile,
        "selected_tool_ids": selected_tool_ids,
        "rounds": [item.model_dump(mode="json") for item in rounds],
        "coverage": [item.model_dump(mode="json") for item in coverage],
    }
    return HuntPlan(
        hunt_id=hunt_id,
        run_id=run_id,
        subject_reference=artifact.artifact_id,
        subject_sha256=artifact.sha256,
        profile=profile,
        rounds=tuple(rounds),
        coverage=coverage,
        plan_sha256=_plan_digest(digest_payload),
    )
