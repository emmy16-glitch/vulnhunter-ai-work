from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SETTINGS = ROOT / "vulnhunter/web/settings.py"
TESTS = ROOT / "tests/unit/test_web_settings.py"


def replace_once(text: str, old: str, new: str) -> str:
    if old not in text:
        raise RuntimeError(f"expected block missing: {old[:80]!r}")
    return text.replace(old, new, 1)


settings = SETTINGS.read_text(encoding="utf-8")
settings = replace_once(
    settings,
    '    return value\n\n\nDEBUG = env_bool("VULNHUNTER_WEB_DEBUG", False)',
    '''    return value


def env_secret(name: str, *, file_name: str) -> str | None:
    """Read one deployment secret from an environment value or mounted file."""

    direct = os.environ.get(name)
    secret_path = os.environ.get(file_name)
    if direct and secret_path:
        raise ImproperlyConfigured(f"{name} and {file_name} must not both be set.")
    if direct:
        return direct
    if not secret_path:
        return None
    path = Path(secret_path).expanduser()
    if path.is_symlink():
        raise ImproperlyConfigured(f"{file_name} must not reference a symbolic link.")
    try:
        metadata = path.stat()
        value = path.read_text(encoding="utf-8").strip()
    except OSError as exc:
        raise ImproperlyConfigured(f"{file_name} could not be read.") from exc
    if metadata.st_mode & 0o022:
        raise ImproperlyConfigured(f"{file_name} must not be group or world writable.")
    if not value:
        raise ImproperlyConfigured(f"{file_name} contains an empty secret.")
    return value


DEBUG = env_bool("VULNHUNTER_WEB_DEBUG", False)''',
)
settings = replace_once(
    settings,
    '''SECRET_KEY = os.environ.get("VULNHUNTER_WEB_SECRET_KEY")
if not SECRET_KEY:
    if DEBUG or TESTING:
        SECRET_KEY = secrets.token_urlsafe(32)
    else:
        raise ImproperlyConfigured("VULNHUNTER_WEB_SECRET_KEY is required when DEBUG is disabled.")''',
    '''SECRET_KEY = env_secret(
    "VULNHUNTER_WEB_SECRET_KEY",
    file_name="VULNHUNTER_WEB_SECRET_KEY_FILE",
)
if not SECRET_KEY:
    if DEBUG or TESTING:
        SECRET_KEY = secrets.token_urlsafe(32)
    else:
        raise ImproperlyConfigured(
            "VULNHUNTER_WEB_SECRET_KEY or VULNHUNTER_WEB_SECRET_KEY_FILE is required "
            "when DEBUG is disabled."
        )''',
)
settings = replace_once(
    settings,
    '            "PASSWORD": os.environ.get("VULNHUNTER_POSTGRES_PASSWORD", ""),',
    '''            "PASSWORD": env_secret(
                "VULNHUNTER_POSTGRES_PASSWORD",
                file_name="VULNHUNTER_POSTGRES_PASSWORD_FILE",
            )
            or "",''',
)
settings = replace_once(
    settings,
    '''VULNHUNTER_TASK_GRAPH_ROOT = os.environ.get(
    "VULNHUNTER_TASK_GRAPH_ROOT",
    str(BASE_DIR / ".local" / "task-graphs"),
)
''',
    '''VULNHUNTER_TASK_GRAPH_ROOT = os.environ.get(
    "VULNHUNTER_TASK_GRAPH_ROOT",
    str(BASE_DIR / ".local" / "task-graphs"),
)
VULNHUNTER_ADVERSARY_LAB_DATABASE = os.environ.get(
    "VULNHUNTER_ADVERSARY_LAB_DATABASE",
    str(BASE_DIR / ".local" / "adversary-lab" / "lab.sqlite3"),
)
VULNHUNTER_ADVERSARY_LAB_WORKSPACE_ROOT = os.environ.get(
    "VULNHUNTER_ADVERSARY_LAB_WORKSPACE_ROOT",
    str(BASE_DIR / ".local" / "adversary-lab" / "workspaces"),
)
VULNHUNTER_ADVERSARY_LAB_EVIDENCE_ROOT = os.environ.get(
    "VULNHUNTER_ADVERSARY_LAB_EVIDENCE_ROOT",
    str(BASE_DIR / ".local" / "adversary-lab" / "evidence"),
)
VULNHUNTER_ADVERSARY_LAB_MAX_TRIALS = env_int(
    "VULNHUNTER_ADVERSARY_LAB_MAX_TRIALS",
    10,
    minimum=1,
    maximum=10,
)
VULNHUNTER_ADVERSARY_LAB_STEP_UP_SECONDS = env_int(
    "VULNHUNTER_ADVERSARY_LAB_STEP_UP_SECONDS",
    600,
    minimum=60,
    maximum=1_800,
)
VULNHUNTER_ADVERSARY_LAB_ENABLED = env_bool(
    "VULNHUNTER_ADVERSARY_LAB_ENABLED",
    DEBUG or TESTING,
)
''',
)
SETTINGS.write_text(settings, encoding="utf-8")

tests = TESTS.read_text(encoding="utf-8")
tests = replace_once(
    tests,
    "from vulnhunter.web.settings import env_bool, env_csv, env_int",
    "from vulnhunter.web.settings import env_bool, env_csv, env_int, env_secret",
)
addition = '''


def test_secret_file_helper_reads_protected_file_and_rejects_conflicts(tmp_path, monkeypatch):
    secret = tmp_path / "secret"
    secret.write_text("controlled-secret\\n", encoding="utf-8")
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
'''
if "test_secret_file_helper_reads_protected_file" not in tests:
    tests = tests.rstrip() + addition + "\n"
TESTS.write_text(tests, encoding="utf-8")
