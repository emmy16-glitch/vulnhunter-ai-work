"""Tests for VulnHunter's central secret-redaction service."""

from vulnhunter.security import (
    REDACTED,
    is_sensitive_key,
    redact_headers,
    redact_mapping,
    redact_text,
    redact_url,
)


def test_detects_common_sensitive_key_variations() -> None:
    assert is_sensitive_key("Authorization")
    assert is_sensitive_key("X-API-Key")
    assert is_sensitive_key("access_token")
    assert is_sensitive_key("client-secret")
    assert is_sensitive_key("session_id")
    assert is_sensitive_key("database_password")


def test_does_not_mark_ordinary_keys_as_sensitive() -> None:
    assert not is_sensitive_key("content-type")
    assert not is_sensitive_key("user-agent")
    assert not is_sensitive_key("response_length")


def test_redacts_sensitive_headers_and_preserves_safe_headers() -> None:
    headers = {
        "Authorization": "Bearer secret-access-token",
        "Cookie": "sessionid=private-session",
        "Content-Type": "application/json",
        "User-Agent": "VulnHunter-Lab/0.1",
    }

    result = redact_headers(headers)

    assert result["Authorization"] == REDACTED
    assert result["Cookie"] == REDACTED
    assert result["Content-Type"] == "application/json"
    assert result["User-Agent"] == "VulnHunter-Lab/0.1"


def test_redact_mapping_does_not_mutate_original_data() -> None:
    original = {
        "username": "student",
        "password": "not-for-storage",
        "metadata": {
            "access_token": "nested-secret",
            "status": "active",
        },
    }

    result = redact_mapping(original)

    assert original["password"] == "not-for-storage"
    assert original["metadata"]["access_token"] == "nested-secret"

    assert result["password"] == REDACTED
    assert result["metadata"]["access_token"] == REDACTED
    assert result["metadata"]["status"] == "active"


def test_redacts_bearer_token_from_free_text() -> None:
    result = redact_text("Request failed with Authorization: Bearer abc.def.ghi")

    assert "abc.def.ghi" not in result
    assert "Bearer [REDACTED]" in result


def test_redacts_secret_assignments_from_free_text() -> None:
    result = redact_text("password=hunter2 api_key:super-secret session_id=abc123")

    assert "hunter2" not in result
    assert "super-secret" not in result
    assert "abc123" not in result
    assert result.count(REDACTED) == 3


def test_redacts_email_and_payment_card_like_values() -> None:
    result = redact_text("Contact person@example.com with card 4111 1111 1111 1111")

    assert "person@example.com" not in result
    assert "4111 1111 1111 1111" not in result
    assert "[REDACTED_EMAIL]" in result
    assert "[REDACTED_PAYMENT_DATA]" in result


def test_redacts_sensitive_url_query_values() -> None:
    result = redact_url("http://127.0.0.1:8000/profile?access_token=private-token&mode=summary")

    assert "private-token" not in result
    assert "access_token=%5BREDACTED%5D" in result
    assert "mode=summary" in result


def test_redacts_embedded_url_credentials() -> None:
    result = redact_url("http://admin:password@127.0.0.1:8000/private")

    assert "admin" not in result
    assert "password" not in result
    assert "[REDACTED]" in result
    assert "127.0.0.1:8000/private" in result


def test_redacts_nested_collections() -> None:
    original = {
        "events": [
            {
                "message": "access_token=secret-one",
                "status": "failed",
            },
            {
                "message": "ordinary message",
                "status": "complete",
            },
        ]
    }

    result = redact_mapping(original)

    assert "secret-one" not in result["events"][0]["message"]
    assert result["events"][0]["status"] == "failed"
    assert result["events"][1]["message"] == "ordinary message"
