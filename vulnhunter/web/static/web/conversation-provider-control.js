(() => {
  "use strict";

  if (typeof document === "undefined" || typeof window === "undefined") return;

  const workspace = document.querySelector("[data-conversation-workspace]");
  const dataElement = document.getElementById("vh-conversation-data");
  const form = document.querySelector("[data-conversation-form]");
  const runtime = document.querySelector("[data-provider-runtime]");
  const thinking = document.querySelector("[data-conversation-thinking]");
  if (!workspace || !dataElement || !form || !runtime || !thinking) return;

  let initial;
  try {
    initial = JSON.parse(dataElement.textContent || "{}");
  } catch (_error) {
    return;
  }

  const state = { active: false };

  // Provider selection and failover are backend concerns. Keep infrastructure
  // identity private while preserving the automatic-routing request contract.
  runtime.hidden = true;
  runtime.setAttribute("aria-hidden", "true");
  runtime.textContent = "Automatic routing";
  runtime.removeAttribute("title");
  runtime.dataset.providerPreferenceActive = "auto";
  runtime.classList.remove("is-ready", "is-warning", "is-offline");

  // The base thinking node is a request-state signal. Delegate its visible
  // representation to one truthful request-status component instead of
  // inventing client-side validation, formatting, percentages or timed stages
  // that are not supplied by the backend.
  thinking.classList.add("is-progress-delegated");
  thinking.setAttribute("aria-hidden", "true");

  const progress = document.createElement("div");
  progress.className = "vh-llm-progress";
  // Keep the established selector contract while naming the actual source of
  // truth separately. This is one active-request state, not a staged meter.
  progress.dataset.progressMode = "validated-stages";
  progress.dataset.progressSource = "request-state";
  progress.hidden = true;
  progress.setAttribute("role", "status");
  progress.setAttribute("aria-live", "polite");
  progress.innerHTML = `
    <div class="vh-llm-progress-head">
      <strong data-llm-progress-copy>Reasoning over the request</strong>
    </div>
  `;
  thinking.insertAdjacentElement("afterend", progress);
  const progressCopy = progress.querySelector("[data-llm-progress-copy]");

  const nativeFetch = window.fetch.bind(window);
  window.fetch = (input, options = {}) => {
    try {
      const requestUrl = new URL(
        typeof input === "string" ? input : input instanceof Request ? input.url : String(input),
        window.location.href,
      );
      const messageUrl = new URL(initial.message_url, window.location.href);
      const method = String(
        options.method || (input instanceof Request ? input.method : "GET"),
      ).toUpperCase();
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

  const startProgress = () => {
    if (state.active) return;
    state.active = true;
    progressCopy.textContent = "Reasoning over the request";
    progress.hidden = false;
  };

  const stopProgress = () => {
    state.active = false;
    progress.hidden = true;
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
})();