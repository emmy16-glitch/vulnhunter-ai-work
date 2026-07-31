from __future__ import annotations

import pytest


@pytest.mark.django_db
def test_source_hunt_submission_binds_job_graph_and_event_to_selected_workspace(
    client,
    tmp_path,
    settings,
    monkeypatch,
):
    from django.contrib.auth import get_user_model
    from governance_test_support import ADMIN_SECRET, NOW, make_governance_store

    from vulnhunter.governance.service import bootstrap_administrator
    from vulnhunter.source_hunt import SourceHuntJobStore
    from vulnhunter.web.models import ConversationThread, WebUserMapping

    settings.PASSWORD_HASHERS = ["django.contrib.auth.hashers.MD5PasswordHasher"]
    settings.VULNHUNTER_GOVERNANCE_DATABASE = str(tmp_path / "governance.db")
    settings.VULNHUNTER_TASK_GRAPH_ROOT = tmp_path / "graphs"
    settings.VULNHUNTER_GROQ_ENABLED = True
    settings.ALLOWED_HOSTS = ["testserver", "localhost", "127.0.0.1"]
    job_root = tmp_path / "jobs"
    report_root = tmp_path / "reports"
    monkeypatch.setenv("VULNHUNTER_SOURCE_HUNT_ROOTS", str(tmp_path))
    monkeypatch.setenv("VULNHUNTER_SOURCE_HUNT_JOB_ROOT", str(job_root))
    monkeypatch.setenv("VULNHUNTER_SOURCE_HUNT_REPORT_ROOT", str(report_root))

    governance = make_governance_store(tmp_path)
    bootstrap_administrator(
        governance,
        reviewer_id="source-chat-admin",
        display_name="Source Chat Administrator",
        secret=ADMIN_SECRET,
        now=NOW,
    )

    User = get_user_model()
    operator = User.objects.create_user(
        username="source-chat-operator",
        password="password-1234",
    )
    WebUserMapping.objects.create(
        user=operator,
        governance_identity_id="source-chat-admin",
        product_roles=["campaign-operator"],
    )
    thread = ConversationThread.objects.create(owner=operator, title="Review repository")
    repository = tmp_path / "authorised-repository"
    repository.mkdir()
    (repository / "app.py").write_text(
        """\
class App:
    def route(self, _path):
        def decorate(function):
            return function
        return decorate

app = App()

@app.route('/download')
def download(request):
    return open(request.args.get('name')).read()
""",
        encoding="utf-8",
    )

    client.force_login(operator)
    response = client.post(
        f"/source-hunt/?thread={thread.thread_id}",
        {
            "thread_id": str(thread.thread_id),
            "repository_root": str(repository),
            "revision": "a" * 40,
            "visibility": "private",
            "permitted_paths": ".",
            "password": "password-1234",
            "approve_remote_processing": "yes",
            "confirm_no_customer_data": "yes",
            "confirm_retention_reviewed": "yes",
        },
    )

    assert response.status_code == 200
    assert b"Bound to this chat workspace" in response.content
    assert f'name="thread_id" value="{thread.thread_id}"'.encode() in response.content
    assert f"/?thread={thread.thread_id}".encode() in response.content

    jobs = SourceHuntJobStore(job_root).list()
    assert len(jobs) == 1
    job = jobs[0]
    thread.refresh_from_db()
    plan = thread.data["vulnhunter_conversation_source_hunt"]
    assert plan["job_id"] == job.job_id
    assert plan["repository"]["snapshot_sha256"] == job.snapshot.snapshot_sha256
    assert plan["assessment_graph"]["assessment_kind"] == "source"
    assert plan["assessment_graph"]["workspace_id"] == str(thread.thread_id)
    assert plan["assessment_graph"]["chat_stage"] == "queued_for_analysis"
    assert plan["task_graph_id"] == f"{job.job_id}-graph"
    messages = thread.data["vulnhunter_conversation_messages"]
    assert any(
        item.get("metadata", {}).get("source_hunt_event")
        == f"source-hunt:{job.job_id}:queued"
        for item in messages
    )

    status = client.post(
        "/source-hunt/",
        {
            "thread_id": str(thread.thread_id),
            "source_chat_bridge": "yes",
            "message": "What is the Source Hunt status?",
        },
        HTTP_X_VULNHUNTER_THREAD=str(thread.thread_id),
        HTTP_ACCEPT="application/json",
    )

    assert status.status_code == 200
    payload = status.json()
    assert payload["handled"] is True
    assert "is queued" in payload["message"]["content"]
    assert "queued_for_analysis" in payload["message"]["content"]
    assert "redirect_url" not in payload


@pytest.mark.django_db
def test_source_hunt_chat_setup_preserves_protected_reauthentication_boundary(
    client,
    settings,
):
    from django.contrib.auth import get_user_model

    from vulnhunter.web.models import ConversationThread

    settings.PASSWORD_HASHERS = ["django.contrib.auth.hashers.MD5PasswordHasher"]
    settings.ALLOWED_HOSTS = ["testserver", "localhost", "127.0.0.1"]
    User = get_user_model()
    operator = User.objects.create_user(
        username="source-setup-operator",
        password="password-1234",
    )
    thread = ConversationThread.objects.create(owner=operator, title="Start Source Hunt")
    client.force_login(operator)

    with pytest.MonkeyPatch.context() as patch:
        from types import SimpleNamespace
        from unittest.mock import patch as mock_patch

        actor = SimpleNamespace(governance_identity=SimpleNamespace(reviewer_id="source-operator"))
        with mock_patch("vulnhunter.web.source_hunt_views.authorized_actor", return_value=actor):
            response = client.post(
                "/source-hunt/",
                {
                    "thread_id": str(thread.thread_id),
                    "source_chat_bridge": "yes",
                    "message": "Analyze this repository with Source Hunt",
                },
                HTTP_X_VULNHUNTER_THREAD=str(thread.thread_id),
                HTTP_ACCEPT="application/json",
            )
        patch.undo()

    assert response.status_code == 200
    payload = response.json()
    assert payload["handled"] is True
    assert payload["redirect_url"] == f"/source-hunt/?thread={thread.thread_id}"
    assert "password re-authentication" in payload["message"]["content"]
    thread.refresh_from_db()
    assert "vulnhunter_conversation_source_hunt" not in thread.data
