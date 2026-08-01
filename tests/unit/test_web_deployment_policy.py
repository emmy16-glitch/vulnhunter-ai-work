from __future__ import annotations

import json
from dataclasses import replace

from vulnhunter.web.deployment_policy import (
    DeploymentConfiguration,
    deployment_policy,
)


def safe_baseline_configuration() -> DeploymentConfiguration:
    return DeploymentConfiguration(
        debug=False,
        secret_key="A9x!production-key-with-strong-random-material-2026",
        allowed_hosts=("127.0.0.1", "localhost"),
        csrf_trusted_origins=(),
        use_https=False,
        session_cookie_secure=False,
        session_cookie_httponly=True,
        csrf_cookie_secure=False,
        csrf_cookie_httponly=True,
        secure_ssl_redirect=False,
        secure_hsts_seconds=0,
        x_frame_options="DENY",
        database_engine="sqlite",
    )


def safe_public_configuration() -> DeploymentConfiguration:
    return replace(
        safe_baseline_configuration(),
        allowed_hosts=("vulnhunter.example.com",),
        csrf_trusted_origins=("https://vulnhunter.example.com",),
        use_https=True,
        session_cookie_secure=True,
        csrf_cookie_secure=True,
        secure_ssl_redirect=True,
        secure_hsts_seconds=3600,
        database_engine="postgresql",
    )


def test_baseline_policy_accepts_private_https_optional_deployment() -> None:
    report = deployment_policy(configuration=safe_baseline_configuration())

    assert report.ready is True
    assert report.mode == "baseline"
    assert set(report.as_payload()["checks"]) == {
        "debug_disabled",
        "secret_key_strong",
        "allowed_hosts_explicit",
        "session_cookie_httponly",
        "csrf_cookie_httponly",
        "clickjacking_protection",
    }


def test_baseline_policy_rejects_debug_weak_secret_and_wildcard_host() -> None:
    report = deployment_policy(
        configuration=replace(
            safe_baseline_configuration(),
            debug=True,
            secret_key="django-insecure-change-me",
            allowed_hosts=("*",),
        )
    )
    checks = report.as_payload()["checks"]

    assert report.ready is False
    assert checks["debug_disabled"] == "failed"
    assert checks["secret_key_strong"] == "failed"
    assert checks["allowed_hosts_explicit"] == "failed"


def test_baseline_policy_rejects_non_httponly_cookies_and_clickjacking_gap() -> None:
    report = deployment_policy(
        configuration=replace(
            safe_baseline_configuration(),
            session_cookie_httponly=False,
            csrf_cookie_httponly=False,
            x_frame_options="SAMEORIGIN",
        )
    )
    checks = report.as_payload()["checks"]

    assert report.ready is False
    assert checks["session_cookie_httponly"] == "failed"
    assert checks["csrf_cookie_httponly"] == "failed"
    assert checks["clickjacking_protection"] == "failed"


def test_public_policy_rejects_local_http_sqlite_configuration() -> None:
    report = deployment_policy(public=True, configuration=safe_baseline_configuration())
    checks = report.as_payload()["checks"]

    assert report.ready is False
    assert report.mode == "public"
    assert checks["https_enabled"] == "failed"
    assert checks["session_cookie_secure"] == "failed"
    assert checks["csrf_cookie_secure"] == "failed"
    assert checks["ssl_redirect_enabled"] == "failed"
    assert checks["hsts_enabled"] == "failed"
    assert checks["public_host_configured"] == "failed"
    assert checks["csrf_trusted_origins_https"] == "failed"
    assert checks["postgresql_database"] == "failed"


def test_public_policy_accepts_https_postgresql_public_configuration() -> None:
    report = deployment_policy(public=True, configuration=safe_public_configuration())

    assert report.ready is True
    assert report.as_payload()["status"] == "ready"
    assert all(value == "ok" for value in report.as_payload()["checks"].values())


def test_public_policy_rejects_private_hosts_and_non_https_origins() -> None:
    report = deployment_policy(
        public=True,
        configuration=replace(
            safe_public_configuration(),
            allowed_hosts=("192.168.1.20",),
            csrf_trusted_origins=("http://192.168.1.20",),
        ),
    )
    checks = report.as_payload()["checks"]

    assert checks["public_host_configured"] == "failed"
    assert checks["csrf_trusted_origins_https"] == "failed"


def test_public_policy_rejects_origins_with_credentials_query_or_fragment() -> None:
    for origin in (
        "https://user:pass@vulnhunter.example.com",
        "https://vulnhunter.example.com?token=secret",
        "https://vulnhunter.example.com#fragment",
    ):
        report = deployment_policy(
            public=True,
            configuration=replace(
                safe_public_configuration(),
                csrf_trusted_origins=(origin,),
            ),
        )
        assert report.as_payload()["checks"]["csrf_trusted_origins_https"] == "failed"


def test_policy_payload_never_exposes_configuration_values() -> None:
    database_value = "postgresql://policy-user:policy-password@database.example.com/vulnhunter"
    configuration = replace(
        safe_public_configuration(),
        secret_key="Never-log-this-production-secret-1234567890!",
        allowed_hosts=("sensitive.example.com",),
        csrf_trusted_origins=("https://sensitive.example.com",),
        database_engine=database_value,
    )
    encoded = json.dumps(
        deployment_policy(public=True, configuration=configuration).as_payload()
    )

    assert configuration.secret_key not in encoded
    assert configuration.allowed_hosts[0] not in encoded
    assert configuration.csrf_trusted_origins[0] not in encoded
    assert database_value not in encoded
