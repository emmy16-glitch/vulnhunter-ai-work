(() => {
  "use strict";

  if (typeof document === "undefined" || typeof window === "undefined") return;

  const workspace = document.querySelector("[data-conversation-workspace]");
  const dataElement = document.getElementById("vh-conversation-data");
  const form = document.querySelector("[data-conversation-form]");
  const runtime = document.querySelector("[data-provider-runtime]");
  const thinking = document.querySelector("[data-conversation-thinking]");
  const composerMeta = document.querySelector(".vh-chat-composer-meta");
  if (!workspace || !dataElement || !form || !runtime || !thinking || !composerMeta) return;

  let initial;
  try {
    initial = JSON.parse(dataElement.textContent || "{}");
  } catch (_error) {
    return;
  }

  const state = {
    active: false,
    startedAt: 0,
    stage: 1,
    timer: null,
  };

  // Provider routing is intentionally automatic and infrastructure status is private.
  runtime.hidden = true;
  runtime.setAttribute("aria-hidden", "true");
  runtime.textContent = "Automatic routing";
  runtime.removeAttribute("title");
  runtime.dataset.providerPreferenceActive = "auto";
  runtime.classList.remove("is-ready", "is-warning", "is-offline");

  // The base thinking node remains the state signal used by the conversation client,
  // but the validated progress component below is the only visible working indicator.
  // This prevents duplicate "thinking" panels from stacking on small screens.
  thinking.classList.add("is-progress-delegated");
  thinking.setAttribute("aria-hidden", "true");

  // Remove any legacy provider selector if an older cached script inserted one.
  composerMeta.querySelectorAll(".vh-provider-control").forEach((node) => node.remove());

  const progress = document.createElement("div");
  progress.className = "vh-llm-progress";
  progress.dataset.progressMode = "validated-stages";
  progress.hidden = true;
  progress.setAttribute("role", "status");
  progress.setAttribute("aria-live", "polite");
  progress.innerHTML = `
    <div class="vh-llm-progress-head">
      <strong data-llm-progress-copy>Reasoning over the request…</strong>
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

  // Keep the request contract compatible with the server while making provider choice
  // invisible. The server-side router owns all provider selection and fallback decisions.
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
        options.body.set("provider_preference", "auto");
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
    if (elapsed < 3) return 1;
    if (elapsed < 7) return 2;
    return 3;
  };

  const stageCopy = (stage, elapsed) => {
    if (stage === 1) return "Reasoning over the request…";
    if (stage === 2) return "Validating the response…";
    if (elapsed >= 15) return "Still working through the request…";
    return "Formatting the final answer…";
  };

  const renderProgress = () => {
    if (!state.active) return;
    const elapsed = Math.max(0, (Date.now() - state.startedAt) / 1000);
    state.stage = currentStage(elapsed);
    progress.hidden = false;
    progressCopy.textContent = stageCopy(state.stage, elapsed);
    progressElapsed.textContent = `${Math.floor(elapsed)}s`;
    progressSteps.forEach((step, index) => {
      step.classList.toggle("is-complete", index < state.stage);
      step.classList.toggle("is-active", index === state.stage);
    });
  };

  const startProgress = () => {
    if (state.active) return;
    state.active = true;
    state.startedAt = Date.now();
    state.stage = 1;
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

  // Deliberately do not observe or rewrite the thinking copy. The command-center layer
  // owns visible status wording, which prevents competing MutationObservers from looping.
})();
