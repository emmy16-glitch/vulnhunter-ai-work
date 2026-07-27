from __future__ import annotations

import pytest


@pytest.mark.django_db
def test_source_hunt_post_queues_without_groq_network_or_key(
    client,
    tmp_path,
    settings,
    monkeypatch,
):
    from django.contrib.auth import get_user_model
    from governance_test_support import ADMIN_SECRET, NOW, make_governance_store

    from vulnhunter.governance.service import bootstrap_administrator
    from vulnhunter.source_hunt import SourceHuntJobStatus, SourceHuntJobStore
    from vulnhunter.web.models import WebUserMapping

    settings.PASSWORD_HASHERS = ["django.contrib.auth.hashers.MD5PasswordHasher"]
    settings.VULNHUNTER_GOVERNANCE_DATABASE = str(tmp_path / "governance.db")
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
        reviewer_id="source-admin",
        display_name="Source Administrator",
        secret=ADMIN_SECRET,
        now=NOW,
    )

    User = get_user_model()
    operator = User.objects.create_user(
        username="source-queue-operator",
        password="password-1234",
    )
    WebUserMapping.objects.create(
        user=operator,
        governance_identity_id="source-admin",
        product_roles=["campaign-operator"],
    )
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
        "/source-hunt/",
        {
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
    assert b"Queued source-job-" in response.content
    assert b"Queue exact snapshot and hunt" in response.content
    jobs = SourceHuntJobStore(job_root).list()
    assert len(jobs) == 1
    assert jobs[0].status == SourceHuntJobStatus.QUEUED
    assert jobs[0].snapshot.revision == "a" * 40
    assert not report_root.exists()
