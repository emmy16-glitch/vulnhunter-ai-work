import pytest
from django.conf import settings
from django.core.exceptions import ImproperlyConfigured

from vulnhunter.web.settings import env_bool, env_csv, env_int, env_secret


def test_environment_helpers_parse_explicit_deployment_values(monkeypatch):
    monkeypatch.setenv("VH_TEST_BOOL", "true")
    monkeypatch.setenv("VH_TEST_CSV", "app.example.test, api.example.test")
    monkeypatch.setenv("VH_TEST_INT", "3600")

    assert env_bool("VH_TEST_BOOL") is True
    assert env_csv("VH_TEST_CSV", "") == ["app.example.test", "api.example.test"]
    assert env_int("VH_TEST_INT", 1, minimum=0, maximum=7200) == 3600


@pytest.mark.parametrize(
    ("name", "value", "call"),
    [
        ("VH_TEST_BOOL", "enabled", lambda: env_bool("VH_TEST_BOOL")),
        (
            "VH_TEST_INT",
            "unbounded",
            lambda: env_int("VH_TEST_INT", 1, minimum=0, maximum=10),
        ),
        ("VH_TEST_INT", "11", lambda: env_int("VH_TEST_INT", 1, minimum=0, maximum=10)),
    ],
)
def test_environment_helpers_reject_malformed_or_out_of_range_values(
    monkeypatch, name, value, call
):
    monkeypatch.setenv(name, value)
    with pytest.raises(ImproperlyConfigured):
        call()


def test_default_agent_store_is_not_required_in_repository_root():
    assert settings.VULNHUNTER_AGENT_DATABASE.endswith(".local/runtime/agent/agent.db")
    assert not settings.VULNHUNTER_AGENT_DATABASE.endswith(
        "vulnhunter-ai-integrated-future/agent.db"
    )


def test_local_model_runtime_has_been_removed():
    assert not hasattr(settings, "VULNHUNTER_OLLAMA_MODEL")
    assert not hasattr(settings, "VULNHUNTER_OLLAMA_CONTEXT_TOKENS")
    assert not hasattr(settings, "VULNHUNTER_OLLAMA_TIMEOUT_SECONDS")


def test_control_store_defaults_are_outside_repository_root_files():
    assert settings.VULNHUNTER_AUTHORIZATION_DATABASE.endswith(
        ".local/runtime/authorization/authorizations.db"
    )
    assert settings.VULNHUNTER_GOVERNANCE_DATABASE.endswith(
        ".local/runtime/governance/governance.db"
    )


def test_groq_is_disabled_by_default_with_production_model_allowlist():
    assert settings.VULNHUNTER_GROQ_ENABLED is False
    assert settings.VULNHUNTER_GROQ_API_BASE == "https://api.groq.com/openai/v1"
    assert settings.VULNHUNTER_GROQ_MODEL == "openai/gpt-oss-120b"
    assert settings.VULNHUNTER_GROQ_FALLBACK_MODEL == "openai/gpt-oss-20b"


def test_secret_file_helper_reads_protected_file_and_rejects_conflicts(tmp_path, monkeypatch):
    secret = tmp_path / "secret"
    secret.write_text("controlled-secret\n", encoding="utf-8")
    secret.chmod(0o400)
    monkeypatch.setenv("VH_SECRET_FILE", str(secret))
    assert env_secret("VH_SECRET", file_name="VH_SECRET_FILE") == "controlled-secret"

    monkeypatch.setenv("VH_SECRET", "direct-secret")
    with pytest.raises(ImproperlyConfigured):
        env_secret("VH_SECRET", file_name="VH_SECRET_FILE")


def test_controlled_lab_defaults_are_bounded_and_local(settings):
    assert settings.VULNHUNTER_ADVERSARY_LAB_MAX_TRIALS == 10
    assert settings.VULNHUNTER_ADVERSARY_LAB_STEP_UP_SECONDS <= 1_800
    assert settings.VULNHUNTER_ADVERSARY_LAB_DATABASE.endswith("adversary-lab/lab.sqlite3")
