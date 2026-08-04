from pathlib import Path

BRIDGE = Path("vulnhunter/web/static/web/conversation-mobile-bridge.js")


def _source() -> str:
    return BRIDGE.read_text(encoding="utf-8")


def test_mobile_retry_control_uses_authoritative_projection_contract() -> None:
    source = _source()

    assert "retry?.available !== true" in source
    assert 'actions.includes("request_retry")' in source
    assert 'const scope = String(retry.scope || "")' in source
    assert 'body.append("retry_scope", scope)' in source
    assert 'body.append("idempotency_key", idempotencyKey)' in source


def test_mobile_retry_control_preserves_idempotency_key_after_unknown_failure() -> None:
    source = _source()

    clear_call = "clearRetryIdempotencyKey(assessmentId, scope);"
    success_check = "if (!response.ok) throw new Error"
    error_handler = "} catch (error) {"

    assert source.index(success_check) < source.index(clear_call)
    assert source.index(clear_call) < source.index(error_handler)
    assert "button.disabled = false;" in source[source.index(error_handler) :]


def test_mobile_retry_control_restores_server_owned_state_after_reconnect() -> None:
    source = _source()

    assert 'method: "GET"' in source
    assert 'cache: "no-store"' in source
    assert "window.setTimeout(refreshRetryProjection, 0);" in source
    assert 'emit("vh:mobile-projection", payload);' in source
    assert "if (!retryCard())" in source


def test_mobile_retry_control_keeps_csrf_and_session_boundaries() -> None:
    source = _source()

    assert 'credentials: "same-origin"' in source
    assert '"X-CSRFToken": csrfToken()' in source
    assert 'retryUrl = "/workspace/mobile-retry/"' in source
