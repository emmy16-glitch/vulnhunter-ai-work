from __future__ import annotations

import os
import secrets
import sys
from pathlib import Path

from django.core.exceptions import ImproperlyConfigured

BASE_DIR = Path(__file__).resolve().parents[2]
TESTING = any("pytest" in arg for arg in sys.argv) or any(arg == "test" for arg in sys.argv)


def env_bool(name: str, default: bool = False) -> bool:
    value = os.environ.get(name)
    if value is None:
        return default
    normalized = value.strip().lower()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off"}:
        return False
    raise ImproperlyConfigured(f"{name} must be a true or false value.")


def env_csv(name: str, default: str) -> list[str]:
    raw = os.environ.get(name, default)
    return [item.strip() for item in raw.split(",") if item.strip()]


def env_int(name: str, default: int, *, minimum: int, maximum: int) -> int:
    raw = os.environ.get(name, str(default))
    try:
        value = int(raw)
    except ValueError as exc:
        raise ImproperlyConfigured(f"{name} must be an integer.") from exc
    if not minimum <= value <= maximum:
        raise ImproperlyConfigured(f"{name} must be between {minimum} and {maximum}.")
    return value


DEBUG = env_bool("VULNHUNTER_WEB_DEBUG", False)
USE_HTTPS = env_bool("VULNHUNTER_WEB_HTTPS", False)
SECRET_KEY = os.environ.get("VULNHUNTER_WEB_SECRET_KEY")
if not SECRET_KEY:
    if DEBUG or TESTING:
        SECRET_KEY = secrets.token_urlsafe(32)
    else:
        raise ImproperlyConfigured("VULNHUNTER_WEB_SECRET_KEY is required when DEBUG is disabled.")

ALLOWED_HOSTS = env_csv(
    "VULNHUNTER_WEB_ALLOWED_HOSTS",
    "127.0.0.1,localhost",
)
CSRF_TRUSTED_ORIGINS = env_csv("VULNHUNTER_WEB_CSRF_TRUSTED_ORIGINS", "")
TRUST_PROXY = env_bool("VULNHUNTER_WEB_TRUST_PROXY", False)

INSTALLED_APPS = [
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "vulnhunter.web",
]

AUTH_PASSWORD_VALIDATORS = [
    {
        "NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.MinimumLengthValidator",
        "OPTIONS": {"min_length": 12},
    },
    {
        "NAME": "django.contrib.auth.password_validation.CommonPasswordValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.NumericPasswordValidator",
    },
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
    "vulnhunter.web.middleware.ContentSecurityPolicyMiddleware",
]

ROOT_URLCONF = "vulnhunter.web.urls"
WSGI_APPLICATION = "vulnhunter.web.wsgi.application"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.debug",
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ]
        },
    }
]

DATABASE_ENGINE = os.environ.get("VULNHUNTER_WEB_DATABASE_ENGINE", "sqlite").strip().lower()
if DATABASE_ENGINE == "sqlite":
    database_path = Path(
        os.environ.get(
            "VULNHUNTER_WEB_DATABASE",
            str(BASE_DIR / ".local" / "vulnhunter-web.sqlite3"),
        )
    ).expanduser()
    database_path.parent.mkdir(parents=True, exist_ok=True)
    DATABASES = {
        "default": {
            "ENGINE": "django.db.backends.sqlite3",
            "NAME": database_path,
        }
    }
elif DATABASE_ENGINE == "postgresql":
    required_database_values = {
        "NAME": os.environ.get("VULNHUNTER_POSTGRES_DATABASE", "").strip(),
        "USER": os.environ.get("VULNHUNTER_POSTGRES_USER", "").strip(),
        "HOST": os.environ.get("VULNHUNTER_POSTGRES_HOST", "").strip(),
    }
    if not all(required_database_values.values()):
        raise ImproperlyConfigured(
            "PostgreSQL requires VULNHUNTER_POSTGRES_DATABASE, "
            "VULNHUNTER_POSTGRES_USER, and VULNHUNTER_POSTGRES_HOST."
        )
    DATABASES = {
        "default": {
            "ENGINE": "django.db.backends.postgresql",
            **required_database_values,
            "PASSWORD": os.environ.get("VULNHUNTER_POSTGRES_PASSWORD", ""),
            "PORT": env_int("VULNHUNTER_POSTGRES_PORT", 5432, minimum=1, maximum=65_535),
            "CONN_MAX_AGE": env_int(
                "VULNHUNTER_POSTGRES_CONN_MAX_AGE", 60, minimum=0, maximum=3_600
            ),
            "OPTIONS": {"sslmode": os.environ.get("VULNHUNTER_POSTGRES_SSLMODE", "require")},
        }
    }
else:
    raise ImproperlyConfigured("VULNHUNTER_WEB_DATABASE_ENGINE must be sqlite or postgresql.")

LANGUAGE_CODE = "en-us"
TIME_ZONE = "UTC"
USE_I18N = True
USE_TZ = True

STATIC_URL = "/static/"
STATIC_ROOT = Path(
    os.environ.get(
        "VULNHUNTER_WEB_STATIC_ROOT",
        str(BASE_DIR / ".local" / "staticfiles"),
    )
).expanduser()
MEDIA_ROOT = Path(
    os.environ.get("VULNHUNTER_WEB_MEDIA_ROOT", str(BASE_DIR / ".local" / "media"))
).expanduser()

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"
LOGIN_URL = "web-login"
LOGIN_REDIRECT_URL = "web-dashboard"
LOGOUT_REDIRECT_URL = "web-login"

SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = "Lax"
SESSION_COOKIE_SECURE = USE_HTTPS
CSRF_COOKIE_HTTPONLY = True
CSRF_COOKIE_SAMESITE = "Lax"
CSRF_COOKIE_SECURE = USE_HTTPS
SECURE_SSL_REDIRECT = USE_HTTPS
SECURE_HSTS_SECONDS = (
    0
    if not USE_HTTPS
    else env_int(
        "VULNHUNTER_WEB_HSTS_SECONDS",
        3600,
        minimum=0,
        maximum=63_072_000,
    )
)
SECURE_HSTS_INCLUDE_SUBDOMAINS = USE_HTTPS and env_bool(
    "VULNHUNTER_WEB_HSTS_INCLUDE_SUBDOMAINS", False
)
SECURE_HSTS_PRELOAD = False
SECURE_REFERRER_POLICY = "strict-origin-when-cross-origin"
SECURE_CONTENT_TYPE_NOSNIFF = True
SECURE_CROSS_ORIGIN_OPENER_POLICY = "same-origin"
X_FRAME_OPTIONS = "DENY"
USE_X_FORWARDED_HOST = TRUST_PROXY
if TRUST_PROXY:
    # Enable only behind a trusted proxy that strips inbound forwarding headers.
    SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")

LOG_LEVEL = os.environ.get("VULNHUNTER_WEB_LOG_LEVEL", "INFO").strip().upper()
if LOG_LEVEL not in {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}:
    raise ImproperlyConfigured("VULNHUNTER_WEB_LOG_LEVEL is invalid.")
LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "handlers": {"console": {"class": "logging.StreamHandler"}},
    "root": {"handlers": ["console"], "level": LOG_LEVEL},
}

VULNHUNTER_CSP = (
    "default-src 'self'; "
    "script-src 'self'; "
    "style-src 'self'; "
    "img-src 'self' data:; "
    "font-src 'self'; "
    "connect-src 'self'; "
    "base-uri 'self'; "
    "form-action 'self'; "
    "frame-ancestors 'none'"
)

VULNHUNTER_AUTHORIZATION_DATABASE = os.environ.get(
    "VULNHUNTER_AUTHORIZATION_DATABASE",
    str(BASE_DIR / ".local" / "runtime" / "authorization" / "authorizations.db"),
)
VULNHUNTER_GOVERNANCE_DATABASE = os.environ.get(
    "VULNHUNTER_GOVERNANCE_DATABASE",
    str(BASE_DIR / ".local" / "runtime" / "governance" / "governance.db"),
)
VULNHUNTER_AGENT_DATABASE = os.environ.get(
    "VULNHUNTER_AGENT_DATABASE",
    str(BASE_DIR / ".local" / "runtime" / "agent" / "agent.db"),
)
VULNHUNTER_ROLE_REGISTRY_ROOT = os.environ.get(
    "VULNHUNTER_ROLE_REGISTRY_ROOT",
    str(BASE_DIR / "config" / "roles"),
)
VULNHUNTER_RUNTIME_CONFIG = os.environ.get(
    "VULNHUNTER_RUNTIME_CONFIG",
    str(BASE_DIR / "config" / "agent_runtime" / "runtime.json"),
)
VULNHUNTER_PRODUCT_SPEC_ROOT = os.environ.get(
    "VULNHUNTER_PRODUCT_SPEC_ROOT",
    str(BASE_DIR / "config" / "product_interface"),
)
VULNHUNTER_PILOT_PLAN_ROOT = os.environ.get(
    "VULNHUNTER_PILOT_PLAN_ROOT",
    str(BASE_DIR / "config" / "pilot"),
)
VULNHUNTER_AGENT_ACTIVITY_ROOT = os.environ.get(
    "VULNHUNTER_AGENT_ACTIVITY_ROOT",
    str(BASE_DIR / ".local" / "agent-activity"),
)
VULNHUNTER_APPROVAL_DATABASE = os.environ.get(
    "VULNHUNTER_APPROVAL_DATABASE",
    str(BASE_DIR / ".local" / "approvals.sqlite3"),
)
VULNHUNTER_SECURITY_TOOL_CONFIG = os.environ.get(
    "VULNHUNTER_SECURITY_TOOL_CONFIG",
    str(BASE_DIR / "config" / "security_tools" / "runtime.json"),
)
VULNHUNTER_SECURITY_EVIDENCE_ROOT = os.environ.get(
    "VULNHUNTER_SECURITY_EVIDENCE_ROOT",
    str(BASE_DIR / ".local" / "security-evidence"),
)
VULNHUNTER_NUCLEI_PROFILE_CONFIG = os.environ.get(
    "VULNHUNTER_NUCLEI_PROFILE_CONFIG",
    str(BASE_DIR / "config" / "security_tools" / "nuclei_profiles.json"),
)
VULNHUNTER_NUCLEI_TEMPLATE_MANIFEST = os.environ.get(
    "VULNHUNTER_NUCLEI_TEMPLATE_MANIFEST",
    str(BASE_DIR / "config" / "security_tools" / "nuclei_template_manifest.json"),
)
VULNHUNTER_NUCLEI_TEMPLATE_ROOT = os.environ.get(
    "VULNHUNTER_NUCLEI_TEMPLATE_ROOT",
    str(BASE_DIR / ".local" / "nuclei-templates"),
)
VULNHUNTER_NUCLEI_READINESS_REPORT = os.environ.get(
    "VULNHUNTER_NUCLEI_READINESS_REPORT",
    str(BASE_DIR / ".local" / "nuclei-readiness" / "readiness.json"),
)
VULNHUNTER_NUCLEI_PILOT_ENQUEUE_ENABLED = env_bool("VULNHUNTER_NUCLEI_PILOT_ENQUEUE_ENABLED", False)
VULNHUNTER_NUCLEI_WORKER_SIGNING_KEY_FILE = os.environ.get(
    "VULNHUNTER_NUCLEI_WORKER_SIGNING_KEY_FILE",
    str(Path.home() / ".vulnhunter-nuclei-worker-key"),
)
VULNHUNTER_NUCLEI_WORKER_SPOOL_ROOT = os.environ.get(
    "VULNHUNTER_NUCLEI_WORKER_SPOOL_ROOT",
    str(BASE_DIR / ".local" / "nuclei-worker-spool"),
)
VULNHUNTER_NUCLEI_WORKER_POLICY = os.environ.get(
    "VULNHUNTER_NUCLEI_WORKER_POLICY",
    str(BASE_DIR / "config" / "security_tools" / "nuclei_worker_pilot.json"),
)
VULNHUNTER_NUCLEI_EXECUTION_ROOT = os.environ.get(
    "VULNHUNTER_NUCLEI_EXECUTION_ROOT",
    str(BASE_DIR / ".local" / "nuclei-executions"),
)
VULNHUNTER_VERIFICATION_ROOT = os.environ.get(
    "VULNHUNTER_VERIFICATION_ROOT",
    str(BASE_DIR / ".local" / "verification"),
)
VULNHUNTER_SCANNER_COMPATIBILITY_MANIFEST = os.environ.get(
    "VULNHUNTER_SCANNER_COMPATIBILITY_MANIFEST",
    str(BASE_DIR / "config" / "security_tools" / "scanner_compatibility.json"),
)
VULNHUNTER_TASK_GRAPH_ROOT = os.environ.get(
    "VULNHUNTER_TASK_GRAPH_ROOT",
    str(BASE_DIR / ".local" / "task-graphs"),
)

VULNHUNTER_MOBILE_ARTIFACT_ROOT = os.environ.get(
    "VULNHUNTER_MOBILE_ARTIFACT_ROOT",
    str(BASE_DIR / ".local" / "mobile-artifacts"),
)
VULNHUNTER_MOBILE_MAX_APK_BYTES = env_int(
    "VULNHUNTER_MOBILE_MAX_APK_BYTES",
    1_000_000_000,
    minimum=1_024,
    maximum=10_000_000_000,
)

VULNHUNTER_GRAPHIFY_EXECUTABLE = os.environ.get(
    "VULNHUNTER_GRAPHIFY_EXECUTABLE",
    "/mnt/vulnhunter-data/tools/uv/tool-bin/graphify",
)
VULNHUNTER_GRAPHIFY_OUTPUT_ROOT = os.environ.get(
    "VULNHUNTER_GRAPHIFY_OUTPUT_ROOT",
    str(BASE_DIR / "graphify-out"),
)
VULNHUNTER_GRAPHIFY_EXECUTION_ENABLED = env_bool("VULNHUNTER_GRAPHIFY_EXECUTION_ENABLED", False)
VULNHUNTER_GROQ_ENABLED = env_bool("VULNHUNTER_GROQ_ENABLED", False)
VULNHUNTER_GROQ_API_BASE = os.environ.get(
    "VULNHUNTER_GROQ_API_BASE", "https://api.groq.com/openai/v1"
).rstrip("/")
VULNHUNTER_GROQ_API_KEY_FILE = os.environ.get(
    "VULNHUNTER_GROQ_API_KEY_FILE", str(Path.home() / ".groq-api-key")
)
VULNHUNTER_GROQ_MODEL = os.environ.get("VULNHUNTER_GROQ_MODEL", "openai/gpt-oss-120b")
VULNHUNTER_GROQ_FALLBACK_MODEL = os.environ.get(
    "VULNHUNTER_GROQ_FALLBACK_MODEL", "openai/gpt-oss-20b"
)
VULNHUNTER_GROQ_TIMEOUT_SECONDS = env_int(
    "VULNHUNTER_GROQ_TIMEOUT_SECONDS", 90, minimum=5, maximum=300
)
VULNHUNTER_GROQ_MAX_INPUT_BYTES = env_int(
    "VULNHUNTER_GROQ_MAX_INPUT_BYTES", 24_000, minimum=1_024, maximum=200_000
)
VULNHUNTER_GROQ_MAX_OUTPUT_TOKENS = env_int(
    "VULNHUNTER_GROQ_MAX_OUTPUT_TOKENS", 1_200, minimum=32, maximum=8_192
)
