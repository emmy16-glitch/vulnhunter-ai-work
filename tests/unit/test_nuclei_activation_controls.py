import hashlib
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from pydantic import ValidationError

from vulnhunter.security_tools.nuclei_activation import (
    EngagementAuthorization,
    NucleiActivationError,
    NucleiCancellationError,
    NucleiCommandPlan,
    NucleiPlanApproval,
    NucleiRunControl,
    NucleiTemplateManifest,
    NucleiTemplateManifestEntry,
    NucleiTimeoutError,
    TemplateApprovalLevel,
    TemplateRiskClass,
    validate_evidence_directory,
    validate_nuclei_plan_approval,
    validate_nuclei_redirect_scope,
    validate_nuclei_target_scope,
    verify_redacted_evidence,
)

_PROHIBITED = (
    "automatic-updates",
    "cloud-upload",
    "public-oast",
    "raw-command-arguments",
)


def _authorization(now: datetime, **updates) -> EngagementAuthorization:
    values = {
        "authorization_id": "engagement-29",
        "target_owner": "Laboratory Owner",
        "approving_person": "Human Approver",
        "approved_targets": ("https://lab.example:443/app",),
        "approved_addresses": ("93.184.216.34",),
        "approved_ports": (443,),
        "approved_protocols": ("https",),
        "approved_scan_profiles": ("passive", "standard", "intrusive"),
        "starts_at": now - timedelta(minutes=5),
        "expires_at": now + timedelta(hours=1),
        "private_network_approved": False,
        "prohibited_actions": _PROHIBITED,
        "audit": {
            "recorded_at": now - timedelta(minutes=10),
            "recorded_by": "approver-29",
            "approval_basis": "Controlled local laboratory pilot approval",
        },
    }
    values.update(updates)
    return EngagementAuthorization.issue(**values)


def _public_resolver(_hostname: str) -> tuple[str, ...]:
    return ("93.184.216.34",)


def _scoped_target(now: datetime):
    authorization = _authorization(now)
    target = validate_nuclei_target_scope(
        "https://LAB.example/app",
        authorization=authorization,
        resolver=_public_resolver,
        now=now,
    )
    return authorization, target


def _plan(tmp_path, now: datetime, *, profile="passive", isolation=False):
    authorization, target = _scoped_target(now)
    evidence_root = tmp_path / "approved-evidence"
    evidence_root.mkdir()
    evidence = evidence_root / "run-29"
    evidence.mkdir()
    output = validate_evidence_directory(evidence, approved_root=evidence_root)
    plan = NucleiCommandPlan.create(
        authorization_id=authorization.authorization_id,
        exact_targets=(target,),
        exact_profile=profile,
        template_manifest_hashes=("a" * 64,),
        output_directory=output,
        rate_limit=5,
        concurrency=2,
        expires_at=now + timedelta(minutes=20),
        requires_isolation=isolation,
    )
    return authorization, plan


def _approval(plan: NucleiCommandPlan, now: datetime, **updates) -> NucleiPlanApproval:
    values = {
        "approval_id": "approval-29",
        "authorization_id": plan.authorization_id,
        "command_plan_digest": plan.plan_digest,
        "approved_by": "Human Approver",
        "approved_at": now - timedelta(minutes=1),
        "expires_at": now + timedelta(minutes=10),
    }
    values.update(updates)
    return NucleiPlanApproval(**values)


def _validate_approval(plan, approval, authorization, now):
    return validate_nuclei_plan_approval(
        plan,
        approval,
        authorization=authorization,
        resolver=_public_resolver,
        approved_output_root=plan.output_directory.parent,
        approved_template_manifest_hashes=plan.template_manifest_hashes,
        now=now,
    )


def test_exact_scope_and_approval_produce_disabled_decision(tmp_path):
    now = datetime.now(UTC)
    authorization, plan = _plan(tmp_path, now)
    decision = _validate_approval(plan, _approval(plan, now), authorization, now)

    assert decision.state == "approved_execution_disabled"
    assert decision.execution_enabled is False
    assert plan.model_config["frozen"] is True
    assert "argv" not in type(plan).model_fields
    assert "command" not in type(plan).model_fields


def test_raw_command_fields_and_execution_enablement_are_rejected(tmp_path):
    now = datetime.now(UTC)
    authorization, plan = _plan(tmp_path, now)
    values = plan.model_dump()
    values["argv"] = ("nuclei", "-u", "https://unreviewed.example")
    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        NucleiCommandPlan(**values)
    with pytest.raises(NucleiActivationError, match="globally disabled"):
        validate_nuclei_plan_approval(
            plan,
            _approval(plan, now),
            authorization=authorization,
            resolver=_public_resolver,
            approved_output_root=plan.output_directory.parent,
            approved_template_manifest_hashes=plan.template_manifest_hashes,
            now=now,
            execution_enabled=True,  # type: ignore[arg-type]
        )


def test_expired_authorization_is_rejected():
    now = datetime.now(UTC)
    authorization = _authorization(
        now,
        starts_at=now - timedelta(hours=2),
        expires_at=now - timedelta(hours=1),
        audit={
            "recorded_at": now - timedelta(hours=3),
            "recorded_by": "approver-29",
            "approval_basis": "Controlled local laboratory pilot approval",
        },
    )
    with pytest.raises(NucleiActivationError, match="not active"):
        validate_nuclei_target_scope(
            "https://lab.example/app",
            authorization=authorization,
            resolver=_public_resolver,
            now=now,
        )


@pytest.mark.parametrize(
    "target",
    (
        "https://other.example/app",
        "https://93.184.216.35/app",
        "https://lab.example:444/app",
    ),
)
def test_unauthorized_domain_ip_and_port_are_rejected(target):
    now = datetime.now(UTC)
    with pytest.raises(NucleiActivationError, match="not exactly authorized"):
        validate_nuclei_target_scope(
            target,
            authorization=_authorization(now),
            resolver=_public_resolver,
            now=now,
        )


def test_private_address_requires_explicit_private_approval():
    now = datetime.now(UTC)
    authorization = _authorization(
        now,
        approved_targets=("https://private.lab:443/app",),
        approved_addresses=("10.20.30.40",),
    )
    with pytest.raises(NucleiActivationError, match="private-network approval"):
        validate_nuclei_target_scope(
            "https://private.lab/app",
            authorization=authorization,
            resolver=lambda _host: ("10.20.30.40",),
            now=now,
        )


def test_loopback_and_metadata_addresses_are_always_rejected():
    now = datetime.now(UTC)
    for hostname, address, message in (
        ("127.0.0.1", "127.0.0.1", "loopback"),
        ("metadata.google.internal", "169.254.169.254", "metadata"),
    ):
        authorization = _authorization(
            now,
            approved_targets=(f"https://{hostname}:443/app",),
            approved_addresses=(address,),
            private_network_approved=True,
        )
        with pytest.raises(NucleiActivationError, match=message):
            validate_nuclei_target_scope(
                f"https://{hostname}/app",
                authorization=authorization,
                resolver=lambda _host, value=address: (value,),
                now=now,
            )


def test_dns_rebinding_and_out_of_scope_redirect_fail_closed():
    now = datetime.now(UTC)
    authorization, source = _scoped_target(now)
    with pytest.raises(NucleiActivationError, match="escaped the approved address"):
        validate_nuclei_target_scope(
            source.url,
            authorization=authorization,
            resolver=lambda _host: ("93.184.216.35",),
            now=now,
        )
    with pytest.raises(NucleiActivationError, match="not exactly authorized"):
        validate_nuclei_redirect_scope(
            source,
            "https://redirect.example/app",
            authorization=authorization,
            resolver=_public_resolver,
            now=now,
        )


def _template_manifest(template_path, now, **updates):
    values = {
        "template_id": "reviewed-check",
        "relative_path": "http/reviewed-check.yaml",
        "sha256": hashlib.sha256(template_path.read_bytes()).hexdigest(),
        "template_release": "v10.4.5",
        "risk_class": TemplateRiskClass.PASSIVE,
        "required_approval_level": TemplateApprovalLevel.REVIEWED,
        "enabled": True,
        "reviewed_by": "reviewer-29",
        "reviewed_at": now,
    }
    values.update(updates)
    return NucleiTemplateManifest(
        template_release="v10.4.5",
        entries=(NucleiTemplateManifestEntry(**values),),
    )


def test_reviewed_template_selection_is_content_addressed(tmp_path):
    now = datetime.now(UTC)
    root = tmp_path / "templates"
    path = root / "http" / "reviewed-check.yaml"
    path.parent.mkdir(parents=True)
    path.write_text("id: reviewed-check\n", encoding="utf-8")
    hashes = _template_manifest(path, now).validate_selection(
        ("reviewed-check",),
        template_root=root,
        approval_level=TemplateApprovalLevel.REVIEWED,
    )
    assert len(hashes) == 1
    assert len(hashes[0]) == 64


def test_modified_template_digest_is_rejected(tmp_path):
    now = datetime.now(UTC)
    root = tmp_path / "templates"
    path = root / "http" / "reviewed-check.yaml"
    path.parent.mkdir(parents=True)
    path.write_text("id: reviewed-check\n", encoding="utf-8")
    manifest = _template_manifest(path, now)
    path.write_text("id: modified-check\n", encoding="utf-8")
    with pytest.raises(NucleiActivationError, match="digest"):
        manifest.validate_selection(
            ("reviewed-check",),
            template_root=root,
            approval_level=TemplateApprovalLevel.REVIEWED,
        )


def test_unapproved_and_unreviewed_templates_are_rejected(tmp_path):
    now = datetime.now(UTC)
    root = tmp_path / "templates"
    path = root / "http" / "reviewed-check.yaml"
    path.parent.mkdir(parents=True)
    path.write_text("id: reviewed-check\n", encoding="utf-8")
    manifest = _template_manifest(
        path,
        now,
        reviewed_by=None,
        reviewed_at=None,
    )
    with pytest.raises(NucleiActivationError, match="not listed"):
        manifest.validate_selection(
            ("unknown-check",),
            template_root=root,
            approval_level=TemplateApprovalLevel.REVIEWED,
        )
    with pytest.raises(NucleiActivationError, match="not been reviewed"):
        manifest.validate_selection(
            ("reviewed-check",),
            template_root=root,
            approval_level=TemplateApprovalLevel.REVIEWED,
        )


def test_missing_and_disabled_templates_are_rejected(tmp_path):
    now = datetime.now(UTC)
    root = tmp_path / "templates"
    path = root / "http" / "reviewed-check.yaml"
    path.parent.mkdir(parents=True)
    path.write_text("id: reviewed-check\n", encoding="utf-8")
    missing_manifest = _template_manifest(path, now)
    path.unlink()
    with pytest.raises(NucleiActivationError, match="missing"):
        missing_manifest.validate_selection(
            ("reviewed-check",),
            template_root=root,
            approval_level=TemplateApprovalLevel.REVIEWED,
        )

    path.write_text("id: reviewed-check\n", encoding="utf-8")
    disabled_manifest = _template_manifest(path, now, enabled=False)
    with pytest.raises(NucleiActivationError, match="disabled"):
        disabled_manifest.validate_selection(
            ("reviewed-check",),
            template_root=root,
            approval_level=TemplateApprovalLevel.REVIEWED,
        )


def test_changed_command_plan_invalidates_approval(tmp_path):
    now = datetime.now(UTC)
    authorization, plan = _plan(tmp_path, now)
    approval = _approval(plan, now)
    changed = plan.model_copy(update={"rate_limit": 6})
    with pytest.raises(NucleiActivationError, match="exact command plan"):
        _validate_approval(changed, approval, authorization, now)


def test_expired_approval_is_rejected(tmp_path):
    now = datetime.now(UTC)
    authorization, plan = _plan(tmp_path, now)
    approval = _approval(
        plan,
        now,
        approved_at=now - timedelta(minutes=20),
        expires_at=now - timedelta(minutes=1),
    )
    with pytest.raises(NucleiActivationError, match="approval is not active"):
        _validate_approval(plan, approval, authorization, now)


def test_intrusive_plan_requires_explicit_approval_and_isolation(tmp_path):
    now = datetime.now(UTC)
    authorization, plan = _plan(tmp_path, now, profile="intrusive", isolation=True)
    with pytest.raises(NucleiActivationError, match="explicit human approval"):
        _validate_approval(plan, _approval(plan, now), authorization, now)


def test_unsafe_evidence_path_and_secret_leakage_are_rejected(tmp_path):
    root = tmp_path / "approved"
    root.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    with pytest.raises(NucleiActivationError, match="outside the approved root"):
        validate_evidence_directory(outside, approved_root=root)

    artifact = root / "nuclei.jsonl"
    secret = "unit-test-bearer-value"
    artifact.write_text(f'{{"authorization":"Bearer {secret}"}}\n', encoding="utf-8")
    with pytest.raises(NucleiActivationError, match="redaction verification") as exc_info:
        verify_redacted_evidence(artifact, maximum_bytes=10_000)
    assert secret not in str(exc_info.value)


def test_redacted_evidence_is_accepted_and_content_addressed(tmp_path):
    artifact = tmp_path / "nuclei.jsonl"
    content = '{"template-id":"reviewed-check","authorization":"[REDACTED]"}\n'
    artifact.write_text(content, encoding="utf-8")

    assert (
        verify_redacted_evidence(artifact, maximum_bytes=10_000)
        == hashlib.sha256(content.encode()).hexdigest()
    )


class _RecordingTerminator:
    def __init__(self):
        self.calls = []

    def terminate_process_group(self, process_group_id, *, grace_seconds):
        self.calls.append((process_group_id, grace_seconds))


def test_cancellation_and_timeout_request_process_group_termination():
    terminator = _RecordingTerminator()
    clock = [10.0]
    control = NucleiRunControl(
        timeout_seconds=5,
        terminator=terminator,
        monotonic=lambda: clock[0],
    )
    control.cancel("operator cancellation")
    with pytest.raises(NucleiCancellationError, match="operator cancellation"):
        control.checkpoint(process_group_id=101)
    assert terminator.calls == [(101, 2.0)]

    timeout_terminator = _RecordingTerminator()
    timed = NucleiRunControl(
        timeout_seconds=5,
        terminator=timeout_terminator,
        monotonic=lambda: clock[0],
    )
    clock[0] = 16.0
    with pytest.raises(NucleiTimeoutError, match="timed out"):
        timed.checkpoint(process_group_id=202)
    assert timeout_terminator.calls == [(202, 2.0)]


def test_activation_controls_never_start_network_or_external_process(tmp_path, monkeypatch):
    def forbidden(*_args, **_kwargs):
        raise AssertionError("external operation attempted")

    monkeypatch.setattr("socket.getaddrinfo", forbidden)
    monkeypatch.setattr("subprocess.run", forbidden)
    monkeypatch.setattr("subprocess.Popen", forbidden)
    now = datetime.now(UTC)
    authorization, plan = _plan(tmp_path, now)
    decision = _validate_approval(plan, _approval(plan, now), authorization, now)
    assert decision.execution_enabled is False


def test_repository_configuration_keeps_nuclei_execution_disabled():
    root = Path(__file__).resolve().parents[2]
    runtime = json.loads((root / "config/security_tools/runtime.json").read_text(encoding="utf-8"))
    profiles = json.loads(
        (root / "config/security_tools/nuclei_profiles.json").read_text(encoding="utf-8")
    )
    manifest = NucleiTemplateManifest.model_validate_json(
        (root / "config/security_tools/nuclei_template_manifest.json").read_text(encoding="utf-8")
    )

    assert runtime["execution_enabled"] is False
    assert runtime["nuclei"]["enabled"] is False
    assert runtime["nuclei"]["engine_version"] == profiles["engine_pin"] == "v3.8.0"
    assert profiles["execution_enabled"] is False
    assert profiles["automatic_updates_enabled"] is False
    assert len(manifest.entries) == 1
    entry = manifest.entries[0]
    assert entry.template_id == "vulnhunter-passive-security-headers"
    assert entry.enabled is True
    assert entry.risk_class.value == "passive"
    assert entry.reviewed_by == "vulnhunter-security-review"
