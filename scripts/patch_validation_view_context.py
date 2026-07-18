from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PATH = ROOT / "vulnhunter/web/views.py"
text = PATH.read_text(encoding="utf-8")

old = "from vulnhunter.agent import AgentStore, AgentStoreError\n"
new = (
    "from vulnhunter.adversary_lab.store import "
    "AdversaryLabStore, AdversaryLabStoreError\n"
    "from vulnhunter.agent import AgentStore, AgentStoreError\n"
)
if old not in text:
    raise RuntimeError("views import block changed")
text = text.replace(old, new, 1)

old = """    else:
        can_decide_approval = True
    return _render(
        request,
        "web/agent_run_detail.html","""
new = """    else:
        can_decide_approval = True
    try:
        lab_store = AdversaryLabStore(Path(settings.VULNHUNTER_ADVERSARY_LAB_DATABASE))
        lab_store.initialize()
        lab_runs = lab_store.list_for_assessment(run_id)
    except (OSError, AdversaryLabStoreError):
        lab_runs = ()
    latest_lab = lab_runs[0] if lab_runs else None
    try:
        authorized_actor(request.user, required_actions=("lab.request",))
    except WebPermissionDenied:
        can_request_lab = False
    else:
        can_request_lab = bool(request.user.is_staff or request.user.is_superuser)
    return _render(
        request,
        "web/agent_run_detail.html","""
if old not in text:
    raise RuntimeError("assessment view transition block changed")
text = text.replace(old, new, 1)

old = """            "can_decide_approval": can_decide_approval,
        },
    )"""
new = """            "can_decide_approval": can_decide_approval,
            "lab_runs": lab_runs,
            "latest_lab": latest_lab,
            "can_request_lab": can_request_lab,
        },
    )"""
if old not in text:
    raise RuntimeError("assessment context block changed")
text = text.replace(old, new, 1)
PATH.write_text(text, encoding="utf-8")
