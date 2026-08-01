from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from django.conf import settings

_LOCAL_HOSTS = {"127.0.0.1", "::1", "[::1]", "localhost", "testserver"}
_WEAK_SECRET_MARKERS = {
    "change-me",
    "changeme",
    "development",
    "django-insecure",
    "insecure",
    "password",
    "secret",
}


@dataclass(frozen=True, slots=True)
class DeploymentConfiguration:
    debug: bool
    secret_key: str
    allowed_hosts: tuple[str, ...]
    csrf_trusted_origins: tuple[str, ...]
    use_https: bool
    session_cookie_secure: bool
    session_cookie_httponly: bool
    csrf_cookie_secure: bool
    csrf_cookie_httponly: bool
    secure_ssl_redirect: bool
    secure_hsts_seconds: int
    x_frame_options: str
    database_engine: str

    @classmethod
    def from_django_settings(cls) -> DeploymentConfiguration:
        return cls(
            debug=bool(settings.DEBUG),
            secret_key=str(settings.SECRET_KEY),
            allowed_hosts=tuple(str(item).strip() for item in settings.ALLOWED_HOSTS),
            csrf_trusted_origins=tuple(
                str(item).strip() for item in settings.CSRF_TRUSTED_ORIGINS
            ),
            use_https=bool(settings.USE_HTTPS),
            session_cookie_secure=bool(settings.SESSION_COOKIE_SECURE),
            session_cookie_httponly=bool(settings.SESSION_COOKIE_HTTPONLY),
            csrf_cookie_secure=bool(settings.CSRF_COOKIE_SECURE),
            csrf_cookie_httponly=bool(settings.CSRF_COOKIE_HTTPONLY),
            secure_ssl_redirect=bool(settings.SECURE_SSL_REDIRECT),
            secure_hsts_seconds=int(settings.SECURE_HSTS_SECONDS),
            x_frame_options=str(settings.X_FRAME_OPTIONS),
            database_engine=str(settings.DATABASE_ENGINE),
        )


@dataclass(frozen=True, slots=True)
class DeploymentPolicyReport:
    mode: str
    checks: tuple[tuple[str, bool], ...]

    @property
    def ready(self) -> bool:
        return all(passed for _, passed in self.checks)

    def as_payload(self) -> dict[str, Any]:
        return {
            "mode": self.mode,
            "status": "ready" if self.ready else "unready",
            "checks": {
                name: "ok" if passed else "failed" for name, passed in self.checks
            },
        }


def _secret_is_strong(value: str) -> bool:
    normalized = value.strip().lower()
    if len(value.strip()) < 32:
        return False
    return not any(marker in normalized for marker in _WEAK_SECRET_MARKERS)


def _hosts_are_explicit(hosts: tuple[str, ...]) -> bool:
    return bool(hosts) and all(host and host != "*" for host in hosts)


def _has_public_host(hosts: tuple[str, ...]) -> bool:
    for host in hosts:
        normalized = host.strip().lower().lstrip(".")
        host_without_port = normalized.rsplit(":", 1)[0] if normalized.count(":") == 1 else normalized
        if host_without_port and host_without_port not in _LOCAL_HOSTS:
            return True
    return False


def _origins_are_public_https(origins: tuple[str, ...]) -> bool:
    return bool(origins) and all(origin.lower().startswith("https://") for origin in origins)


def deployment_policy(
    *,
    public: bool = False,
    configuration: DeploymentConfiguration | None = None,
) -> DeploymentPolicyReport:
    config = configuration or DeploymentConfiguration.from_django_settings()
    checks: list[tuple[str, bool]] = [
        ("debug_disabled", not config.debug),
        ("secret_key_strong", _secret_is_strong(config.secret_key)),
        ("allowed_hosts_explicit", _hosts_are_explicit(config.allowed_hosts)),
        ("session_cookie_httponly", config.session_cookie_httponly),
        ("csrf_cookie_httponly", config.csrf_cookie_httponly),
        ("clickjacking_protection", config.x_frame_options.upper() == "DENY"),
    ]
    if public:
        checks.extend(
            [
                ("https_enabled", config.use_https),
                ("session_cookie_secure", config.session_cookie_secure),
                ("csrf_cookie_secure", config.csrf_cookie_secure),
                ("ssl_redirect_enabled", config.secure_ssl_redirect),
                ("hsts_enabled", config.secure_hsts_seconds > 0),
                ("public_host_configured", _has_public_host(config.allowed_hosts)),
                (
                    "csrf_trusted_origins_https",
                    _origins_are_public_https(config.csrf_trusted_origins),
                ),
                ("postgresql_database", config.database_engine == "postgresql"),
            ]
        )
    return DeploymentPolicyReport(
        mode="public" if public else "baseline",
        checks=tuple(checks),
    )
