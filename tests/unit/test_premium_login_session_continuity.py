from pathlib import Path
from unittest.mock import patch

import pytest
from django.contrib.auth import get_user_model
from django.test import Client
from django.urls import reverse

ROOT = Path(__file__).resolve().parents[2]
LOGIN = ROOT / "vulnhunter" / "web" / "templates" / "web" / "login.html"
INTERACTION = ROOT / "vulnhunter" / "web" / "static" / "web" / "premium-interaction.js"


def _text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _user(username: str = "premium-login"):
    return get_user_model().objects.create_user(username=username, password="correct-password")


def test_login_template_uses_canonical_assets_and_preserves_return_destination() -> None:
    template = _text(LOGIN)

    assert "tokens.css" in template
    assert "app.css" in template
    assert "premium-interaction.css" not in template
    assert "premium-interaction.js" in template
    assert 'data-route="login"' in template
    assert 'id="main-content"' in template
    assert "data-login-form" in template
    assert 'name="next"' in template
    assert 'value="{{ next }}"' in template
    assert "data-login-submit" in template
    assert "data-login-error" in template


def test_login_interaction_blocks_duplicate_submit_and_recovers_from_bfcache() -> None:
    javascript = _text(INTERACTION)

    assert 'loginForm?.addEventListener("submit"' in javascript
    assert 'loginSubmit.getAttribute("aria-busy") === "true"' in javascript
    assert "event.preventDefault()" in javascript
    assert 'loginSubmit.setAttribute("aria-busy", "true")' in javascript
    assert "loginSubmit.disabled = true" in javascript
    assert 'loginSubmitLabel.textContent = "Signing in…"' in javascript
    assert "restoreLoginSubmit()" in javascript
    assert 'window.addEventListener("pageshow"' in javascript
    assert "loginSubmit.disabled = false" in javascript
    assert 'loginSubmit.removeAttribute("aria-busy")' in javascript


def test_login_interaction_does_not_authenticate_or_choose_redirects() -> None:
    javascript = _text(INTERACTION)
    login_section = javascript.split("const loginForm", maxsplit=1)[1].split(
        'document.addEventListener("click"', maxsplit=1
    )[0]

    for forbidden in (
        "fetch(",
        "XMLHttpRequest",
        "window.location",
        "location.assign",
        "location.replace",
        "document.cookie",
        "localStorage",
    ):
        assert forbidden not in login_section


@pytest.mark.django_db
def test_login_get_renders_safe_requested_destination() -> None:
    client = Client()
    login_url = reverse("web-login")

    response = client.get(login_url, {"next": "/health/"})

    assert response.status_code == 200
    content = response.content.decode("utf-8")
    assert 'name="next"' in content
    assert 'value="/health/"' in content


@pytest.mark.django_db
def test_successful_reauthentication_returns_to_safe_requested_destination() -> None:
    _user()
    client = Client()

    response = client.post(
        reverse("web-login"),
        {
            "username": "premium-login",
            "password": "correct-password",
            "next": "/health/",
        },
    )

    assert response.status_code == 302
    assert response.headers["Location"] == "/health/"
    assert str(client.session.get("_auth_user_id"))


@pytest.mark.django_db
def test_unsafe_return_destination_falls_back_to_role_aware_default() -> None:
    _user("unsafe-next")
    client = Client()

    with (
        patch("vulnhunter.web.unified_assessment_views._can", return_value=False),
        patch("vulnhunter.web.unified_assessment_views._pending_approvals", return_value=()),
    ):
        response = client.post(
            reverse("web-login"),
            {
                "username": "unsafe-next",
                "password": "correct-password",
                "next": "https://evil.example/steal-session",
            },
        )

    assert response.status_code == 302
    assert response.headers["Location"] == reverse("web-dashboard")
    assert "evil.example" not in response.headers["Location"]


@pytest.mark.django_db
def test_invalid_login_preserves_username_but_never_password() -> None:
    _user("invalid-login")
    client = Client()
    secret = "DO-NOT-ECHO-LOGIN-SECRET"

    response = client.post(
        reverse("web-login"),
        {
            "username": "invalid-login",
            "password": secret,
            "next": "/health/",
        },
    )

    assert response.status_code == 200
    content = response.content.decode("utf-8")
    assert "invalid-login" in content
    assert secret not in content
    assert "data-login-error" in content
    assert 'value="/health/"' in content


@pytest.mark.django_db
def test_login_rejects_missing_csrf_without_authenticating() -> None:
    _user("csrf-login")
    client = Client(enforce_csrf_checks=True)

    response = client.post(
        reverse("web-login"),
        {"username": "csrf-login", "password": "correct-password"},
    )

    assert response.status_code == 403
    assert client.session.get("_auth_user_id") is None


@pytest.mark.django_db
def test_successful_login_rotates_existing_anonymous_session() -> None:
    _user("rotate-login")
    client = Client()
    session = client.session
    session["preauth-marker"] = "preserve"
    session.save()
    previous_session_key = session.session_key

    response = client.post(
        reverse("web-login"),
        {
            "username": "rotate-login",
            "password": "correct-password",
            "next": "/health/",
        },
    )

    assert response.status_code == 302
    assert client.session.session_key
    assert client.session.session_key != previous_session_key
    assert client.session.get("preauth-marker") == "preserve"
