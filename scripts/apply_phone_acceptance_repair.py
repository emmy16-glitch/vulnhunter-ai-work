from __future__ import annotations

import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def write(path: str, content: str) -> None:
    (ROOT / path).write_text(content, encoding="utf-8")


def replace_once(path: str, old: str, new: str) -> None:
    content = read(path)
    if old not in content:
        if new in content:
            return
        raise RuntimeError(f"marker missing from {path}: {old[:160]!r}")
    write(path, content.replace(old, new, 1))


def regex_once(path: str, pattern: str, replacement: str, *, flags: int = 0) -> None:
    content = read(path)
    updated, count = re.subn(pattern, replacement, content, count=1, flags=flags)
    if count != 1:
        raise RuntimeError(f"pattern matched {count} times in {path}: {pattern[:160]!r}")
    write(path, updated)


def patch_groq_provider() -> None:
    path = "vulnhunter/providers/groq.py"
    replace_once(
        path,
        "    ProviderHealth,\n    ProviderInvocation,\n",
        "    ProviderCapability,\n    ProviderHealth,\n    ProviderInvocation,\n",
    )
    replace_once(
        path,
        "class _StructuredModelOutput(BaseModel):\n"
        "    model_config = ConfigDict(frozen=True, extra=\"forbid\")\n\n"
        "    output_kind: ProviderOutputKind\n"
        "    content: str = Field(min_length=1, max_length=40_000)\n",
        "class _StructuredModelOutput(BaseModel):\n"
        "    model_config = ConfigDict(frozen=True, extra=\"forbid\")\n\n"
        "    output_kind: ProviderOutputKind\n"
        "    content: str = Field(min_length=1, max_length=40_000)\n\n\n"
        "class _ConversationModelOutput(BaseModel):\n"
        "    model_config = ConfigDict(frozen=True, extra=\"forbid\")\n\n"
        "    message: str = Field(min_length=1, max_length=40_000)\n"
        "    recommended_profile: str | None = Field(default=None, max_length=64)\n",
    )
    replace_once(
        path,
        "            structured = _StructuredModelOutput.model_validate_json(response_text)\n",
        "            structured = self._decode_structured_output(invocation, response_text)\n",
    )
    marker = "    def _model_inventory(self) -> frozenset[str]:\n"
    helper = '''    @staticmethod
    def _decode_structured_output(
        invocation: ProviderInvocation,
        response_text: str,
    ) -> _StructuredModelOutput:
        """Accept the governed envelope and one conversation-only compatibility shape.

        The provider-level contract remains authoritative. The compatibility path exists
        only because JSON-object models can follow the conversation prompt's inner schema
        directly instead of encoding that object as the outer ``content`` string.
        """

        try:
            return _StructuredModelOutput.model_validate_json(response_text)
        except ValidationError:
            if invocation.capability != ProviderCapability.CONVERSATION:
                raise
            conversation = _ConversationModelOutput.model_validate_json(response_text)
            content = json.dumps(
                {
                    "message": conversation.message,
                    "recommended_profile": conversation.recommended_profile,
                },
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            )
            return _StructuredModelOutput(
                output_kind=ProviderOutputKind.CANDIDATE_ANALYSIS,
                content=content,
            )

'''
    replace_once(path, marker, helper + marker)


def patch_conversation_service() -> None:
    path = "vulnhunter/web/conversation_service.py"
    replace_once(path, "import json\nimport re\n", "import json\nimport os\nimport re\n")
    old = (
        '        "sets final "\n'
        '        "severity, or publishes results. Do not reveal hidden chain-of-thought; provide "\n'
        '        "conclusions "\n'
        '        "and concise supporting rationale. Return JSON with keys message and recommended_profile. "\n'
        '        "message must contain the complete user-facing answer. recommended_profile must be one "\n'
        '        "available profile or null. "\n'
    )
    new = (
        '        "sets final "\n'
        '        "severity, or publishes results. Do not reveal hidden chain-of-thought; provide "\n'
        '        "conclusions and concise supporting rationale. The provider wrapper requires exactly one "\n'
        '        "outer JSON object with output_kind and content. Set output_kind to CANDIDATE_ANALYSIS. "\n'
        '        "Set content to a JSON-encoded string containing message and recommended_profile. message "\n'
        '        "must contain the complete user-facing answer. recommended_profile must be one available "\n'
        '        "profile or null. Do not return message and recommended_profile as the outer object. "\n'
    )
    replace_once(path, old, new)
    old_status = '''    configured = groq_configured or hf_configured
    providers = []
    if groq_configured:
        providers.append("Groq")
    if hf_configured:
        providers.append("Hugging Face")
    return {
        "enabled": groq_enabled or hf_enabled,
        "configured": configured,
        "label": f"{' + '.join(providers)} ready" if providers else "AI provider setup required",
        "model": settings.VULNHUNTER_GROQ_MODEL
        if groq_configured
        else settings.VULNHUNTER_HUGGINGFACE_MODEL,
        "providers": providers,
    }
'''
    new_status = '''    configured = groq_configured or hf_configured
    runtime_verified = os.environ.get("VULNHUNTER_GROQ_RUNTIME_VERIFIED", "").strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }
    providers = []
    if groq_configured:
        providers.append("Groq")
    if hf_configured:
        providers.append("Hugging Face")
    live_verified = bool(groq_configured and runtime_verified)
    if live_verified:
        label = "Groq live conversation ready"
    elif groq_configured:
        label = "Groq configured; restart to verify live conversation"
    elif providers:
        label = f"{' + '.join(providers)} configured"
    else:
        label = "AI provider setup required"
    return {
        "enabled": groq_enabled or hf_enabled,
        "configured": configured,
        "live_verified": live_verified,
        "label": label,
        "model": settings.VULNHUNTER_GROQ_MODEL
        if groq_configured
        else settings.VULNHUNTER_HUGGINGFACE_MODEL,
        "providers": providers,
    }
'''
    replace_once(path, old_status, new_status)


def patch_verify_command() -> None:
    path = "vulnhunter/web/management/commands/vh_verify_groq.py"
    replace_once(
        path,
        '        parser.add_argument("--timeout", type=int, default=settings.VULNHUNTER_GROQ_TIMEOUT_SECONDS)\n',
        '        parser.add_argument("--timeout", type=int, default=settings.VULNHUNTER_GROQ_TIMEOUT_SECONDS)\n'
        '        parser.add_argument(\n'
        '            "--conversation-smoke",\n'
        '            action="store_true",\n'
        '            help="Also verify the exact conversational interpretation path used by the web UI.",\n'
        '        )\n',
    )
    old = '''        if "VULNHUNTER_GROQ_READY" not in response.content:
            raise CommandError("Groq response passed schema validation but missed the marker")
        self.stdout.write(
            self.style.SUCCESS(
                "Groq verified: "
                f"model={response.model} output_kind={response.output_kind.value} "
                f"trusted={response.trusted}."
            )
        )
'''
    new = '''        if "VULNHUNTER_GROQ_READY" not in response.content:
            raise CommandError("Groq response passed schema validation but missed the marker")

        conversation_ready = False
        if options["conversation_smoke"]:
            from vulnhunter.web.conversation_service import interpret_request

            marker = "VULNHUNTER_CHAT_READY"
            interpreted = interpret_request(
                (
                    "Answer this harmless readiness request. Your complete user-facing message must "
                    f"include the exact marker {marker}."
                ),
                available_profiles=("passive",),
                reasoning_effort="low",
                provider_preference="groq",
            )
            if interpreted.provider != "groq" or marker not in (interpreted.assistant_copy or ""):
                raise CommandError(
                    "Groq conversation smoke test failed safely: "
                    f"provider={interpreted.provider} detail={interpreted.provider_detail}"
                )
            conversation_ready = True

        suffix = " conversation=ready" if conversation_ready else ""
        self.stdout.write(
            self.style.SUCCESS(
                "Groq verified: "
                f"model={response.model} output_kind={response.output_kind.value} "
                f"trusted={response.trusted}.{suffix}"
            )
        )
'''
    replace_once(path, old, new)


def patch_codespace_runtime() -> None:
    start = ".devcontainer/start-vulnhunter.sh"
    replace_once(
        start,
        'if [[ -f "$ROOT/.codespaces/vulnhunter-user.env" ]]; then\n'
        '  source "$ROOT/.codespaces/vulnhunter-user.env"\n'
        'fi\n\n'
        ': "${VULNHUNTER_USER_ID:?Run bash .devcontainer/first-run.sh first.}"\n',
        'if [[ -f "$ROOT/.codespaces/vulnhunter-user.env" ]]; then\n'
        '  source "$ROOT/.codespaces/vulnhunter-user.env"\n'
        'fi\n\n'
        'WEB_SECRET_KEY_FILE="${VULNHUNTER_WEB_SECRET_KEY_FILE:-$ROOT/.codespaces/web-secret.key}"\n'
        'if [[ ! -s "$WEB_SECRET_KEY_FILE" ]]; then\n'
        '  umask 077\n'
        '  python -c \'import secrets,sys; sys.stdout.write(secrets.token_urlsafe(64))\' > "$WEB_SECRET_KEY_FILE"\n'
        'fi\n'
        'chmod 600 "$WEB_SECRET_KEY_FILE"\n'
        'export VULNHUNTER_WEB_SECRET_KEY_FILE="$WEB_SECRET_KEY_FILE"\n\n'
        ': "${VULNHUNTER_USER_ID:?Run bash .devcontainer/first-run.sh first.}"\n',
    )
    replace_once(
        start,
        'GROQ_STATE="deterministic fallback"\nHUGGINGFACE_STATE="disabled"\n',
        'GROQ_STATE="deterministic fallback"\nexport VULNHUNTER_GROQ_RUNTIME_VERIFIED=false\nHUGGINGFACE_STATE="disabled"\n',
    )
    replace_once(
        start,
        '  if python manage.py vh_verify_groq >"$LOG_ROOT/groq-verification.log" 2>&1; then\n'
        '    GROQ_STATE="live inference verified"\n',
        '  if python manage.py vh_verify_groq --conversation-smoke >"$LOG_ROOT/groq-verification.log" 2>&1; then\n'
        '    export VULNHUNTER_GROQ_RUNTIME_VERIFIED=true\n'
        '    GROQ_STATE="live conversation verified"\n',
    )

    post = ".devcontainer/post-create.sh"
    replace_once(
        post,
        'GROQ_KEY="$STATE_DIR/groq-api-key"\nmkdir -p "$RUNTIME_DIR"\n',
        'GROQ_KEY="$STATE_DIR/groq-api-key"\nWEB_SECRET_KEY="$STATE_DIR/web-secret.key"\nmkdir -p "$RUNTIME_DIR"\n',
    )
    replace_once(
        post,
        'chmod 700 "$STATE_DIR" "$RUNTIME_DIR"\n\n',
        'chmod 700 "$STATE_DIR" "$RUNTIME_DIR"\n\n'
        'if [[ ! -s "$WEB_SECRET_KEY" ]]; then\n'
        '  umask 077\n'
        '  python -c \'import secrets,sys; sys.stdout.write(secrets.token_urlsafe(64))\' > "$WEB_SECRET_KEY"\n'
        'fi\n'
        'chmod 600 "$WEB_SECRET_KEY"\n\n',
    )
    replace_once(
        post,
        'export VULNHUNTER_WEB_CSRF_TRUSTED_ORIGINS="https://*.app.github.dev,https://localhost:8002"\n',
        'export VULNHUNTER_WEB_CSRF_TRUSTED_ORIGINS="https://*.app.github.dev,https://localhost:8002"\n'
        'export VULNHUNTER_WEB_SECRET_KEY_FILE="$WEB_SECRET_KEY"\n',
    )


def patch_upload_coordinator() -> None:
    path = "vulnhunter/web/static/web/conversation-upload-coordinator.js"
    replace_once(
        path,
        '''  const csrfToken = () => {
    const match = document.cookie.match(/(?:^|;\\s*)csrftoken=([^;]+)/);
    return match ? decodeURIComponent(match[1]) : "";
  };
''',
        '''  const csrfToken = () => {
    const match = document.cookie.match(/(?:^|;\\s*)csrftoken=([^;]+)/);
    if (match) return decodeURIComponent(match[1]);
    return document.querySelector("input[name='csrfmiddlewaretoken']")?.value || "";
  };
''',
    )
    marker = '''  const request = async (url, options, threadId) => {
'''
    helper = '''  const refreshSessionProtection = async () => {
    const response = await fetch(window.location.href, {
      method: "GET",
      credentials: "same-origin",
      cache: "no-store",
    });
    if (response.redirected || response.url.includes("/login/")) {
      const error = new Error("Your session expired. Refresh the page and sign in again.");
      error.status = 401;
      throw error;
    }
    const html = await response.text();
    const parsed = new DOMParser().parseFromString(html, "text/html");
    const fresh = parsed.querySelector("input[name='csrfmiddlewaretoken']")?.value || "";
    if (!fresh) {
      const error = new Error("Session protection could not be refreshed. Reload the page.");
      error.status = 403;
      throw error;
    }
    document.querySelectorAll("input[name='csrfmiddlewaretoken']").forEach((input) => {
      input.value = fresh;
    });
    return fresh;
  };

  const request = async (url, options, threadId, retried = false) => {
'''
    replace_once(path, marker, helper)
    replace_once(
        path,
        '''    const payload = await readJson(response);
    if (!response.ok) {
''',
        '''    const payload = await readJson(response);
    if (response.status === 403 && !retried) {
      await refreshSessionProtection();
      return request(url, options, threadId, true);
    }
    if (!response.ok) {
''',
    )
    marker = '''  const cancel = async (localId) => {
'''
    retry = '''  const retry = async (localId) => {
    const record = await getRecord(localId);
    if (!record) return;
    if (!(record.file instanceof Blob) || record.file.size !== record.size) {
      record.state = "failed";
      record.error = "The browser no longer has the selected APK bytes. Choose the file again.";
      await putRecord(record);
      return;
    }
    record.state = "queued";
    record.error = "";
    record.retryAt = 0;
    await putRecord(record);
    schedule();
  };

  const cancel = async (localId) => {
'''
    replace_once(path, marker, retry)
    replace_once(
        path,
        '''      if (!["completed", "cancelled"].includes(record.state)) {
        const cancel = document.createElement("button");
''',
        '''      if (record.state === "failed") {
        const retryButton = document.createElement("button");
        retryButton.type = "button";
        retryButton.textContent = "Retry";
        retryButton.addEventListener("click", () => window.VulnHunterUploads.retry(record.localId));
        actions.append(retryButton);
      }
      if (!["completed", "cancelled"].includes(record.state)) {
        const cancel = document.createElement("button");
''',
    )
    replace_once(
        path,
        '  window.VulnHunterUploads = { enqueue, cancel, list: listRecords, resume: schedule };\n',
        '  window.VulnHunterUploads = { enqueue, retry, cancel, list: listRecords, resume: schedule };\n',
    )


def patch_conversation_client() -> None:
    path = "vulnhunter/web/static/web/conversation.js"
    replace_once(
        path,
        '  const csrfToken = form?.querySelector("input[name=\'csrfmiddlewaretoken\']")?.value || "";\n',
        '''  const csrfToken = () => {
    const cookie = document.cookie.match(/(?:^|;\\s*)csrftoken=([^;]+)/);
    if (cookie) return decodeURIComponent(cookie[1]);
    return form?.querySelector("input[name='csrfmiddlewaretoken']")?.value || "";
  };
''',
    )
    replace_once(
        path,
        '''      const provider = text(metadata.provider || "deterministic");
      const model = text(metadata.model || "");
      badge.textContent = `${prettyState(metadata.reasoning_effort)} reasoning · ${prettyState(provider)}${model ? ` · ${model}` : ""}`;
      body.append(badge);
''',
        '''      const provider = text(metadata.provider || "deterministic");
      const model = text(metadata.model || "");
      const detail = text(metadata.provider_detail || "");
      const degraded = provider === "deterministic" && /groq/i.test(detail);
      if (degraded) badge.classList.add("is-degraded");
      badge.textContent = degraded
        ? `${prettyState(metadata.reasoning_effort)} reasoning · Groq unavailable · deterministic fallback`
        : `${prettyState(metadata.reasoning_effort)} reasoning · ${prettyState(provider)}${model ? ` · ${model}` : ""}`;
      if (detail) badge.title = detail;
      body.append(badge);
''',
    )
    old_post = '''  const postForm = async (url, values) => {
    const payload = new FormData();
    Object.entries(values).forEach(([key, value]) => payload.append(key, text(value)));
    const response = await fetch(url, {
      method: "POST",
      body: payload,
      credentials: "same-origin",
      headers: { "X-CSRFToken": csrfToken, Accept: "application/json" },
    });
    let data = {};
    try {
      data = await response.json();
    } catch (_error) {
      data = { detail: "The server returned an unreadable response." };
    }
    if (!response.ok) throw new Error(data.detail || data.message?.content || "The request could not be completed.");
    return data;
  };
'''
    new_post = '''  const refreshSessionProtection = async () => {
    const response = await fetch(window.location.href, {
      method: "GET",
      credentials: "same-origin",
      cache: "no-store",
    });
    if (response.redirected || response.url.includes("/login/")) {
      throw new Error("Your session expired. Refresh the page and sign in again.");
    }
    const html = await response.text();
    const parsed = new DOMParser().parseFromString(html, "text/html");
    const fresh = parsed.querySelector("input[name='csrfmiddlewaretoken']")?.value || "";
    if (!fresh) throw new Error("Session protection could not be refreshed. Reload the page.");
    form.querySelectorAll("input[name='csrfmiddlewaretoken']").forEach((element) => {
      element.value = fresh;
    });
  };

  const postForm = async (url, values, retried = false) => {
    const payload = new FormData();
    Object.entries(values).forEach(([key, value]) => payload.append(key, text(value)));
    const response = await fetch(url, {
      method: "POST",
      body: payload,
      credentials: "same-origin",
      headers: { "X-CSRFToken": csrfToken(), Accept: "application/json" },
    });
    let data = {};
    try {
      data = await response.json();
    } catch (_error) {
      data = { detail: "The server returned an unreadable response." };
    }
    if (response.status === 403 && !retried) {
      await refreshSessionProtection();
      return postForm(url, values, true);
    }
    if (!response.ok) throw new Error(data.detail || data.message?.content || "The request could not be completed.");
    return data;
  };
'''
    replace_once(path, old_post, new_post)
    replace_once(
        path,
        '    setBusy(true, "Understanding your request and checking authorised scope…");\n',
        '''    const selectedEffort = reasoningSelect?.value || initial.reasoning_effort || "medium";
    const busyCopy =
      selectedEffort === "high"
        ? "Asking Groq to analyse deeply and checking governed context…"
        : selectedEffort === "low"
          ? "Asking Groq for a direct answer…"
          : "Asking Groq to reason through the request…";
    setBusy(true, busyCopy);
''',
    )


def patch_templates_and_styles() -> None:
    template = "vulnhunter/web/templates/web/conversation.html"
    content = read(template)
    content = content.replace("20260725-consolidate1", "20260727-phone-acceptance1")
    content = content.replace("20260727-workspaces1", "20260727-phone-acceptance1")
    old = '''        <div class="vh-chat-composer-meta">
          <span><b data-reasoning-copy>{{ conversation.reasoning_effort|title }}</b> reasoning · Website and APK assessments start here · Enter to send</span>
        </div>
'''
    new = '''        <div class="vh-chat-composer-meta">
          <span><b data-reasoning-copy>{{ conversation.reasoning_effort|title }}</b> reasoning · Website and APK assessments start here · Enter to send</span>
          <span class="vh-provider-runtime{% if groq.live_verified %} is-ready{% elif groq.configured %} is-warning{% else %} is-offline{% endif %}" data-provider-runtime title="{{ groq.label }}">
            {% if groq.live_verified %}Groq live{% elif groq.configured %}Groq needs verified restart{% else %}Groq unavailable{% endif %}
          </span>
        </div>
'''
    if old not in content:
        raise RuntimeError("composer metadata marker missing")
    write(template, content.replace(old, new, 1))

    base = "vulnhunter/web/templates/web/base.html"
    content = read(base)
    content = content.replace("background-uploads.css' %}?v=20260727-workspaces1", "background-uploads.css' %}?v=20260727-phone-acceptance1")
    content = content.replace("conversation-upload-coordinator.js' %}?v=20260727-workspaces1", "conversation-upload-coordinator.js' %}?v=20260727-phone-acceptance1")
    write(base, content)

    css = "vulnhunter/web/static/web/workspace-final-fixes.css"
    content = read(css)
    addition = '''

/* Phone acceptance: make reasoning/provider state readable and prevent overlap. */
.vh-message-reasoning {
  display: inline-flex;
  align-items: center;
  max-width: 100%;
  margin-top: .55rem;
  padding: .28rem .48rem;
  border: 1px solid rgba(108, 124, 255, .22);
  border-radius: 999px;
  color: var(--vh-final-muted);
  background: rgba(108, 124, 255, .07);
  font-size: .68rem;
  line-height: 1.25;
}

.vh-message-reasoning.is-degraded {
  border-color: rgba(232, 162, 61, .38);
  color: #f5c77f;
  background: rgba(232, 162, 61, .09);
}

.vh-provider-runtime {
  display: inline-flex;
  align-items: center;
  gap: .35rem;
  white-space: nowrap;
}

.vh-provider-runtime::before {
  width: .45rem;
  height: .45rem;
  border-radius: 50%;
  background: var(--vh-final-blocked);
  content: "";
}

.vh-provider-runtime.is-ready::before { background: var(--vh-final-authorized); }
.vh-provider-runtime.is-warning::before { background: var(--vh-final-pending); }

@media (max-width: 767px) {
  .vh-conversation-body .vh-chat-input-shell {
    display: grid;
    grid-template-columns: 44px minmax(0, 1fr) minmax(5.8rem, auto) 44px;
    align-items: end;
    gap: .42rem;
    padding: .48rem;
  }

  .vh-conversation-body .vh-chat-input-shell textarea {
    width: 100%;
    min-width: 0;
  }

  .vh-conversation-body .vh-reasoning-control,
  .vh-conversation-body .vh-reasoning-control select {
    min-width: 0;
    width: 100%;
  }

  .vh-conversation-body .vh-chat-composer-meta {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: .55rem;
    padding-inline: .2rem;
    font-size: .68rem;
  }

  .vh-conversation-body .vh-chat-composer-meta > span:first-child {
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
}

@media (max-width: 420px) {
  .vh-conversation-body .vh-chat-input-shell {
    grid-template-columns: 42px minmax(0, 1fr) 5.8rem 42px;
  }
}
'''
    if "Phone acceptance: make reasoning/provider state readable" not in content:
        write(css, content.rstrip() + addition + "\n")

    upload_css = "vulnhunter/web/static/web/background-uploads.css"
    content = read(upload_css)
    content = content.replace(
        '@media (max-width: 700px) { .vh-background-upload-dock { right: .65rem; bottom: .65rem; width: calc(100vw - 1.3rem); } }',
        '''@media (max-width: 700px) {
  .vh-background-upload-dock {
    right: .65rem;
    bottom: 8.25rem;
    width: calc(100vw - 1.3rem);
    max-height: min(38dvh, 22rem);
    overflow-y: auto;
  }
  .vh-background-upload { grid-template-columns: minmax(0, 1fr); }
  .vh-background-upload > div:last-child { justify-content: flex-end; }
}''',
    )
    write(upload_css, content)


def add_tests() -> None:
    test = '''from __future__ import annotations

import hashlib
import json
from pathlib import Path

import httpx

from vulnhunter.providers import (
    GroqProvider,
    ProviderCapability,
    ProviderInvocation,
    ProviderKind,
    ProviderOutputKind,
)


def test_conversation_direct_json_shape_is_wrapped_safely():
    def handler(request):
        return httpx.Response(
            200,
            json={
                "choices": [
                    {
                        "message": {
                            "content": json.dumps(
                                {
                                    "message": "A useful live answer.",
                                    "recommended_profile": "passive",
                                }
                            )
                        }
                    }
                ],
                "system_fingerprint": "phone-acceptance",
            },
        )

    content = "safe conversation"
    invocation = ProviderInvocation(
        invocation_id="phone-chat",
        request_id="phone-chat",
        provider=ProviderKind.GROQ_ADVISORY,
        model="openai/gpt-oss-120b",
        capability=ProviderCapability.CONVERSATION,
        input_sha256=hashlib.sha256(content.encode()).hexdigest(),
        maximum_output_tokens=128,
    )
    response = GroqProvider(
        api_key="gsk_test",
        transport=httpx.MockTransport(handler),
    ).invoke(invocation, content)

    assert response.output_kind == ProviderOutputKind.CANDIDATE_ANALYSIS
    assert json.loads(response.content) == {
        "message": "A useful live answer.",
        "recommended_profile": "passive",
    }
    assert response.trusted is False


def test_non_conversation_capability_keeps_strict_outer_schema():
    def handler(request):
        return httpx.Response(
            200,
            json={"choices": [{"message": {"content": '{"message":"not allowed"}'}}]},
        )

    content = "classification"
    invocation = ProviderInvocation(
        invocation_id="strict",
        request_id="strict",
        provider=ProviderKind.GROQ_ADVISORY,
        model="openai/gpt-oss-120b",
        capability=ProviderCapability.CLASSIFICATION,
        input_sha256=hashlib.sha256(content.encode()).hexdigest(),
        maximum_output_tokens=128,
    )
    response = GroqProvider(
        api_key="gsk_test",
        transport=httpx.MockTransport(handler),
    ).invoke(invocation, content)
    assert response.output_kind == ProviderOutputKind.ABSTAIN


def test_phone_runtime_contracts_are_wired():
    root = Path(__file__).resolve().parents[2]
    start = (root / ".devcontainer/start-vulnhunter.sh").read_text()
    post_create = (root / ".devcontainer/post-create.sh").read_text()
    upload = (root / "vulnhunter/web/static/web/conversation-upload-coordinator.js").read_text()
    conversation = (root / "vulnhunter/web/static/web/conversation.js").read_text()
    template = (root / "vulnhunter/web/templates/web/conversation.html").read_text()
    upload_css = (root / "vulnhunter/web/static/web/background-uploads.css").read_text()

    assert "vh_verify_groq --conversation-smoke" in start
    assert "VULNHUNTER_GROQ_RUNTIME_VERIFIED=true" in start
    assert "VULNHUNTER_WEB_SECRET_KEY_FILE" in start
    assert "WEB_SECRET_KEY" in post_create
    assert "input[name='csrfmiddlewaretoken']" in upload
    assert "refreshSessionProtection" in upload
    assert "VulnHunterUploads = { enqueue, retry, cancel" in upload
    assert "Groq unavailable · deterministic fallback" in conversation
    assert "data-provider-runtime" in template
    assert "bottom: 8.25rem" in upload_css
'''
    write("tests/unit/test_phone_acceptance_repairs.py", test)


def main() -> None:
    patch_groq_provider()
    patch_conversation_service()
    patch_verify_command()
    patch_codespace_runtime()
    patch_upload_coordinator()
    patch_conversation_client()
    patch_templates_and_styles()
    add_tests()


if __name__ == "__main__":
    main()
