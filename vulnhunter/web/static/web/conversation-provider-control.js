(() => {
  "use strict";

  if (typeof document === "undefined" || typeof window === "undefined") return;

  const workspace = document.querySelector("[data-conversation-workspace]");
  const dataElement = document.getElementById("vh-conversation-data");
  const form = document.querySelector("[data-conversation-form]");
  const reasoningSelect = document.querySelector("[data-reasoning-effort]");
  const runtime = document.querySelector("[data-provider-runtime]");
  const thinking = document.querySelector("[data-conversation-thinking]");
  const thinkingCopy = document.querySelector("[data-thinking-copy]");
  const feed = document.querySelector("[data-conversation-feed]");
  const composerMeta = document.querySelector(".vh-chat-composer-meta");
  if (!workspace || !dataElement || !form || !runtime || !thinking || !thinkingCopy || !composerMeta) {
    return;
  }

  let initial;
  try {
    initial = JSON.parse(dataElement.textContent || "{}");
  } catch (_error) {
    return;
  }

  const configuredProviders = new Set(
    Array.isArray(initial.groq?.providers) ? initial.groq.providers.map((item) => String(item)) : [],
  );
  const state = {
    preference: ["auto", "groq", "huggingface"].includes(initial.provider_preference)
      ? initial.provider_preference
      : "auto",
    active: false,
    startedAt: 0,
    stage: 0,
    timer: null,
    lastProvider: "",
    lastModel: "",
  };

  const providerLabel = (value) => {
    if (value === "groq") return "Groq";
    if (value === "huggingface") return "Hugging Face";
    const ordered = ["Groq", "Hugging Face"].filter((item) => configuredProviders.has(item));
    return ordered.length ? `Auto · ${ordered.join(" → ")}` : "Auto · local fallback available";
  };

  const providerAvailability = (value) => {
    if (value === "groq") return configuredProviders.has("Groq");
    if (value === "huggingface") return configuredProviders.has("Hugging Face");
    return configuredProviders.size > 0;
  };

  const csrfToken = () => {
    const field = form.querySelector("input[name='csrfmiddlewaretoken']");
    if (field?.value) return field.value;
    const cookie = document.cookie.match(/(?:^|;\s*)csrftoken=([^;]+)/);
    return cookie ? decodeURIComponent(cookie[1]) : "";
  };

  const control = document.createElement("label");
  control.className = "vh-provider-control";
  control.setAttribute("title", "Choose which configured advisory provider should answer this workspace");
  control.innerHTML = `
    <span>AI</span>
    <select data-provider-preference aria-label="AI provider">
      <option value="auto">Auto</option>
      <option value="groq">Groq</option>
      <option value="huggingface">Hugging Face</option>
    </select>
    <small data-provider-preference-status></small>
  `;
  const select = control.querySelector("[data-provider-preference]");
  const preferenceStatus = control.querySelector("[data-provider-preference-status]");
  select.value = state.preference;
  const providerContainer = runtime.parentElement;
  if (!providerContainer || !providerContainer.contains(runtime)) return;
  providerContainer.insertBefore(control, runtime);

  const progress = document.createElement("div");
  progress.className = "vh-llm-progress";
  progress.dataset.progressMode = "validated-stages";
  progress.hidden = true;
  progress.setAttribute("role", "status");
  progress.setAttribute("aria-live", "polite");
  progress.innerHTML = `
    <div class="vh-llm-progress-head">
      <strong data-llm-progress-copy>Preparing request…</strong>
      <span data-llm-progress-elapsed>0s</span>
    </div>
    <div class="vh-llm-progress-track" aria-hidden="true">
      <i class="vh-llm-progress-step"></i>
      <i class="vh-llm-progress-step"></i>
      <i class="vh-llm-progress-step"></i>
      <i class="vh-llm-progress-step"></i>
    </div>
  `;
  thinking.insertAdjacentElement("afterend", progress);
  const progressCopy = progress.querySelector("[data-llm-progress-copy]");
  const progressElapsed = progress.querySelector("[data-llm-progress-elapsed]");
  const progressSteps = [...progress.querySelectorAll(".vh-llm-progress-step")];

  const renderPreference = () => {
    const available = providerAvailability(state.preference);
    const label = providerLabel(state.preference);
    preferenceStatus.textContent = available ? "configured" : "not configured";
    preferenceStatus.title = available
      ? `${label} will be requested for the next ordinary chat answer.`
      : `${label} is not configured; VulnHunter will fail safely to deterministic guidance.`;
    runtime.dataset.providerPreferenceActive = state.preference;
    if (!state.lastProvider) {
      runtime.textContent = label;
      runtime.title = available
        ? `${label} selected. The final response badge records the provider and model that actually answered.`
        : `${label} selected but unavailable. Deterministic guidance remains available.`;
      runtime.classList.remove("is-ready");
      runtime.classList.toggle("is-warning", available);
      runtime.classList.toggle("is-offline", !available);
    }
  };

  const persistPreference = async (nextValue) => {
    const previousValue = state.preference;
    state.preference = nextValue;
    renderPreference();
    select.disabled = true;
    const payload = new FormData();
    payload.set("reasoning_effort", reasoningSelect?.value || initial.reasoning_effort || "medium");
    payload.set("provider_preference", nextValue);
    if (initial.thread_id) payload.set("thread_id", initial.thread_id);
    try {
      const response = await window.fetch(initial.reasoning_url, {
        method: "POST",
        body: payload,
        credentials: "same-origin",
        headers: { "X-CSRFToken": csrfToken(), Accept: "application/json" },
      });
      const body = await response.json();
      if (!response.ok) throw new Error(body.detail || "The provider preference could not be saved.");
      state.preference = body.provider_preference || nextValue;
      select.value = state.preference;
      initial.provider_preference = state.preference;
      renderPreference();
    } catch (error) {
      state.preference = previousValue;
      select.value = previousValue;
      renderPreference();
      window.alert(error instanceof Error ? error.message : "The provider preference could not be saved.");
    } finally {
      select.disabled = false;
      document.querySelector("[data-conversation-input]")?.focus();
    }
  };

  select.addEventListener("change", () => persistPreference(select.value));

  const nativeFetch = window.fetch.bind(window);
  window.fetch = (input, options = {}) => {
    try {
      const requestUrl = new URL(
        typeof input === "string" ? input : input instanceof Request ? input.url : String(input),
        window.location.href,
      );
      const messageUrl = new URL(initial.message_url, window.location.href);
      const method = String(options.method || (input instanceof Request ? input.method : "GET")).toUpperCase();
      if (
        method === "POST" &&
        requestUrl.pathname === messageUrl.pathname &&
        options.body instanceof FormData
      ) {
        options.body.set("provider_preference", state.preference);
        if (initial.thread_id && !options.body.has("thread_id")) {
          options.body.set("thread_id", initial.thread_id);
        }
      }
    } catch (_error) {
      // Leave unrelated requests untouched.
    }
    return nativeFetch(input, options);
  };

  const currentStage = (elapsed) => {
    if (elapsed < 1) return 0;
    if (elapsed < 3) return 1;
    if (elapsed < 7) return 2;
    return 3;
  };

  const stageCopy = (stage, elapsed) => {
    const selected = providerLabel(state.preference);
    if (stage === 0) return "Preparing safe workspace context…";
    if (stage === 1) return `Contacting ${selected}…`;
    if (stage === 2) return "Waiting for a validated model response…";
    if (elapsed >= 15) return "Still validating the response safely…";
    return "Checking and formatting the final answer…";
  };

  const renderProgress = () => {
    if (!state.active) return;
    const elapsed = Math.max(0, (Date.now() - state.startedAt) / 1000);
    state.stage = currentStage(elapsed);
    const copy = stageCopy(state.stage, elapsed);
    progress.hidden = false;
    progressCopy.textContent = copy;
    progressElapsed.textContent = `${Math.floor(elapsed)}s`;
    progressSteps.forEach((step, index) => {
      step.classList.toggle("is-complete", index < state.stage);
      step.classList.toggle("is-active", index === state.stage);
    });
    if (thinkingCopy.textContent !== copy) thinkingCopy.textContent = copy;
  };

  const startProgress = () => {
    if (state.active) return;
    state.active = true;
    state.startedAt = Date.now();
    state.stage = 0;
    if (state.timer) window.clearInterval(state.timer);
    renderProgress();
    state.timer = window.setInterval(renderProgress, 400);
  };

  const stopProgress = () => {
    state.active = false;
    if (state.timer) window.clearInterval(state.timer);
    state.timer = null;
    progress.hidden = true;
    progressSteps.forEach((step) => step.classList.remove("is-complete", "is-active"));
  };

  document.addEventListener(
    "submit",
    (event) => {
      if (event.target !== form || form.dataset.specialistBusy === "true") return;
      const input = form.querySelector("[data-conversation-input]");
      if (!input?.value.trim()) return;
      startProgress();
    },
    true,
  );

  new MutationObserver(() => {
    if (thinking.hidden) stopProgress();
    else if (!state.active) startProgress();
  }).observe(thinking, { attributes: true, attributeFilter: ["hidden"] });

  new MutationObserver(() => {
    if (state.active) renderProgress();
  }).observe(thinkingCopy, { childList: true, characterData: true, subtree: true });

  const updateActualProvider = () => {
    if (!feed) return;
    const badges = [...feed.querySelectorAll(".vh-message-reasoning")];
    const badge = badges.at(-1);
    if (!badge || badge.dataset.providerRuntimeRecorded === "true") return;
    badge.dataset.providerRuntimeRecorded = "true";
    const copy = String(badge.textContent || "");
    const modelMatch = copy.match(/(?:Groq|Hugging Face)\s*·\s*(.+)$/i);
    if (/Hugging Face/i.test(copy)) state.lastProvider = "Hugging Face";
    else if (/\bGroq\b/i.test(copy)) state.lastProvider = "Groq";
    else if (/fallback|unavailable/i.test(copy)) state.lastProvider = "Deterministic fallback";
    else return;
    state.lastModel = modelMatch ? modelMatch[1].trim() : "";
    runtime.textContent =
      state.lastProvider === "Deterministic fallback"
        ? "AI unavailable · local fallback"
        : `${state.lastProvider} answered`;
    runtime.title = state.lastModel
      ? `Last answer: ${state.lastProvider} · ${state.lastModel}. Preference: ${providerLabel(state.preference)}.`
      : `Last answer: ${state.lastProvider}. Preference: ${providerLabel(state.preference)}.`;
    runtime.classList.toggle("is-ready", state.lastProvider !== "Deterministic fallback");
    runtime.classList.toggle("is-warning", state.lastProvider === "Deterministic fallback");
    runtime.classList.remove("is-offline");
  };

  if (feed) {
    updateActualProvider();
    new MutationObserver(updateActualProvider).observe(feed, { childList: true, subtree: true });
  }

  renderPreference();
})();