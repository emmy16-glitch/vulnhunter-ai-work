from __future__ import annotations

from pathlib import Path


def replace_once(path: str, old: str, new: str) -> None:
    file_path = Path(path)
    content = file_path.read_text(encoding="utf-8")
    if content.count(old) != 1:
        raise RuntimeError(f"Expected one repair target in {path}, found {content.count(old)}")
    file_path.write_text(content.replace(old, new), encoding="utf-8")


def main() -> None:
    replace_once(
        "vulnhunter/web/conversational_views.py",
        '''def _approval_payload(run: object) -> dict[str, object] | None:
    pending = _pending_for_run(str(run.run_id))
    if pending is None:
        return None
    return {
        "request_id": pending.request_id,
        "summary": pending.summary,
        "risk_summary": pending.risk_summary,
        "plan_digest": str(getattr(run, "plan_digest", "")),
        "target": str(getattr(run, "scope_summary", "")),
        "profile": str(getattr(run, "risk_classification", "passive")),
        "scanner": str(getattr(run, "requested_tool", "nuclei")),
        "expires_at": pending.expires_at.isoformat(),
    }
''',
        '''def _approval_payload(run: object) -> dict[str, object] | None:
    pending = _pending_for_run(str(run.run_id))
    if pending is None:
        return None
    command_plan = getattr(run, "command_plan_summary", {})
    plan = command_plan if isinstance(command_plan, Mapping) else {}
    target = str(getattr(run, "scope_summary", ""))
    try:
        parsed = urlsplit(target)
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
    except ValueError:
        port = None
    template_hashes = plan.get("template_manifest_hashes", ())
    if not isinstance(template_hashes, (list, tuple)):
        template_hashes = ()
    return {
        "request_id": pending.request_id,
        "summary": pending.summary,
        "risk_summary": pending.risk_summary,
        "plan_digest": str(plan.get("plan_digest") or getattr(run, "plan_digest", "") or ""),
        "target": target,
        "port": port,
        "profile": str(
            plan.get("exact_profile")
            or getattr(run, "risk_classification", "passive")
            or "passive"
        ),
        "scanner": str(getattr(run, "requested_tool", "nuclei") or "nuclei"),
        "template_count": len(template_hashes),
        "rate_limit": plan.get("rate_limit"),
        "concurrency": plan.get("concurrency"),
        "expires_at": pending.expires_at.isoformat(),
    }
''',
    )
    replace_once(
        "vulnhunter/web/conversational_views.py",
        '            content="Which authorised assessment profile should I use? Passive is recommended first.",\n',
        '''            content=(
                "Which authorised assessment profile should I use? "
                "Passive is recommended first."
            ),
''',
    )
    replace_once(
        "vulnhunter/web/templates/web/conversation.html",
        '''        <div><dt>Target and port</dt><dd data-approval-target></dd></div>
        <div><dt>Profile</dt><dd data-approval-profile></dd></div>
        <div><dt>Scanner</dt><dd data-approval-scanner></dd></div>
        <div><dt>Templates</dt><dd>Reviewed passive templates only</dd></div>
        <div><dt>Limits</dt><dd>1 request/sec · concurrency 1</dd></div>
''',
        '''        <div><dt>Target</dt><dd data-approval-target></dd></div>
        <div><dt>Port</dt><dd data-approval-port></dd></div>
        <div><dt>Profile</dt><dd data-approval-profile></dd></div>
        <div><dt>Scanner</dt><dd data-approval-scanner></dd></div>
        <div><dt>Templates</dt><dd data-approval-templates></dd></div>
        <div><dt>Limits</dt><dd data-approval-limits></dd></div>
''',
    )
    replace_once(
        "vulnhunter/web/static/web/conversation.js",
        '''    panel.querySelector("[data-approval-target]").textContent = text(approval.target || run.target);
    panel.querySelector("[data-approval-profile]").textContent = prettyState(approval.profile || run.profile);
    panel.querySelector("[data-approval-scanner]").textContent = text(approval.scanner || run.scanner);
    panel.querySelector("[data-approval-digest]").textContent = text(approval.plan_digest || "");
''',
        '''    panel.querySelector("[data-approval-target]").textContent = text(approval.target || run.target);
    panel.querySelector("[data-approval-port]").textContent = text(approval.port || "Not recorded");
    panel.querySelector("[data-approval-profile]").textContent = prettyState(approval.profile || run.profile);
    panel.querySelector("[data-approval-scanner]").textContent = text(approval.scanner || run.scanner);
    const templateCount = Number(approval.template_count || 0);
    panel.querySelector("[data-approval-templates]").textContent = templateCount
      ? `${templateCount} reviewed template${templateCount === 1 ? "" : "s"}`
      : "No reviewed templates selected";
    const rateLimit = Number(approval.rate_limit || 0);
    const concurrency = Number(approval.concurrency || 0);
    panel.querySelector("[data-approval-limits]").textContent =
      rateLimit && concurrency
        ? `${rateLimit} request${rateLimit === 1 ? "" : "s"}/sec · concurrency ${concurrency}`
        : "Limits unavailable";
    panel.querySelector("[data-approval-digest]").textContent = text(approval.plan_digest || "");
''',
    )
    replace_once(
        ".devcontainer/first-run.sh",
        '''  'import os; from django.contrib.auth import get_user_model; from vulnhunter.web.models import WebUserMapping; user=get_user_model().objects.get(username=os.environ["WEB_USERNAME"]); mapping=WebUserMapping.objects.get(user=user); mapping.governance_identity_id=os.environ["GOVERNANCE_ID"]; mapping.product_roles=["campaign-operator"]; mapping.full_clean(); mapping.save(); user.is_staff=True; user.save(update_fields=["is_staff"]); print("Configured", user.username, "as the VulnHunter Security Analyst")'
''',
        '''  'import os; from django.contrib.auth import get_user_model; from vulnhunter.web.models import WebUserMapping; user=get_user_model().objects.get(username=os.environ["WEB_USERNAME"]); mapping,_=WebUserMapping.objects.update_or_create(user=user, defaults={"governance_identity_id":os.environ["GOVERNANCE_ID"],"product_roles":["campaign-operator"]}); mapping.full_clean(); mapping.save(); user.is_staff=True; user.save(update_fields=["is_staff"]); print("Configured", user.username, "as the VulnHunter Security Analyst")'
''',
    )
    replace_once(
        "tests/unit/test_conversational_workspace.py",
        '''    assert artifact == {
        "filename": "evidence.jsonl",
        "type": "jsonl",
        "size": 321,
        "checksum": "a" * 64,
    }


@pytest.mark.django_db
''',
        '''    assert artifact == {
        "filename": "evidence.jsonl",
        "type": "jsonl",
        "size": 321,
        "checksum": "a" * 64,
    }


def test_approval_payload_uses_the_authoritative_signed_plan(monkeypatch):
    pending = SimpleNamespace(
        request_id="approval-test",
        summary="Confirm the exact passive plan.",
        risk_summary="The plan is restricted to reviewed passive templates.",
        expires_at=SimpleNamespace(isoformat=lambda: "2026-07-23T15:00:00+00:00"),
    )
    run = SimpleNamespace(
        run_id="assessment-test",
        scope_summary="http://10.0.0.143:8010/",
        requested_tool="nuclei",
        risk_classification="passive",
        plan_digest="b" * 64,
        command_plan_summary={
            "exact_profile": "passive",
            "template_manifest_hashes": ("a" * 64, "c" * 64),
            "rate_limit": 1,
            "concurrency": 1,
            "plan_digest": "d" * 64,
        },
    )
    monkeypatch.setattr(conversational_views, "_pending_for_run", lambda _run_id: pending)

    payload = conversational_views._approval_payload(run)

    assert payload is not None
    assert payload["target"] == "http://10.0.0.143:8010/"
    assert payload["port"] == 8010
    assert payload["profile"] == "passive"
    assert payload["template_count"] == 2
    assert payload["rate_limit"] == 1
    assert payload["concurrency"] == 1
    assert payload["plan_digest"] == "d" * 64


@pytest.mark.django_db
''',
    )
    replace_once(
        "tests/unit/test_conversational_workspace.py",
        '''    assert "Confirm and continue" in content
    assert "Open approval centre" not in content
''',
        '''    assert "Confirm and continue" in content
    assert "data-approval-port" in content
    assert "data-approval-templates" in content
    assert "data-approval-limits" in content
    assert "Open approval centre" not in content
''',
    )


if __name__ == "__main__":
    main()
