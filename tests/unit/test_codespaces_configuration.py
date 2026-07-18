from __future__ import annotations

import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DEVCONTAINER = ROOT / ".devcontainer"


def test_codespaces_configuration_is_private_and_phone_ready() -> None:
    config = json.loads((DEVCONTAINER / "devcontainer.json").read_text(encoding="utf-8"))
    dockerfile = (DEVCONTAINER / "Dockerfile").read_text(encoding="utf-8")

    assert config["build"]["dockerfile"] == "Dockerfile"
    assert "mcr.microsoft.com/devcontainers/python:1-3.12-bookworm" in dockerfile
    assert "/etc/apt/sources.list.d/yarn.list" in dockerfile
    assert config["remoteUser"] == "vscode"
    assert config["postCreateCommand"] == "bash .devcontainer/post-create.sh"
    assert 8002 in config["forwardPorts"]
    assert config["portsAttributes"]["8002"]["visibility"] == "private"
    assert config["portsAttributes"]["8002"]["protocol"] == "http"
    assert "ghcr.io/devcontainers/features/sshd:1" in config["features"]


def test_codespaces_shell_scripts_have_valid_bash_syntax() -> None:
    for name in ("post-create.sh", "first-run.sh", "start-preview.sh"):
        path = DEVCONTAINER / name
        result = subprocess.run(
            ["bash", "-n", str(path)],
            capture_output=True,
            check=False,
            text=True,
        )
        assert result.returncode == 0, result.stderr


def test_codespaces_setup_keeps_credentials_out_of_repository() -> None:
    setup = (DEVCONTAINER / "post-create.sh").read_text(encoding="utf-8")
    first_run = (DEVCONTAINER / "first-run.sh").read_text(encoding="utf-8")
    gitignore = (ROOT / ".gitignore").read_text(encoding="utf-8")

    assert ".codespaces/" in gitignore
    assert "VULNHUNTER_WEB_DEBUG=true" in setup
    assert "VULNHUNTER_WEB_SECRET_KEY=" not in setup
    assert "--secret=" not in first_run
    assert "Password:" not in first_run


def test_codespaces_preview_uses_real_project_setup_commands() -> None:
    setup = (DEVCONTAINER / "post-create.sh").read_text(encoding="utf-8")
    launcher = (DEVCONTAINER / "start-preview.sh").read_text(encoding="utf-8")

    assert 'python -m pip install -e ".[dev]"' in setup
    assert "python manage.py migrate --noinput" in setup
    assert "python manage.py vh_init_agent_store" in setup
    assert "python manage.py runserver 0.0.0.0:8002" in launcher
