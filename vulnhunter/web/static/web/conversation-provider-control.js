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

  const state = {
    active: false,
    startedAt: 0,
    timer: null,
  };

  // Provider selection and failover are backend concerns. Keep infrastructure
  // identity private while preserving the automatic-routing request contract.
  runtime.hidden = true;
  runtime.setAttribute("aria-hidden", "true");
  runtime.textContent = "Automatic routing";
  runtime.removeAttribute("title");
  runtime.dataset.providerPreferenceActive = "auto";
  runtime.classList.remove("is-ready", "is-warning", "is-offline");

  // The base thinking node is a request-state signal. Delegate its visible
  // representation to one component. The legacy progress-mode token is kept
  // for compatibility with existing clients/tests, but no fabricated
  // validation/formatting stages or percentages are generated in the browser.
  thinking.classList.add("is-progress-delegated");
  thinking.setAttribute("aria-hidden", "true");
  document.querySelectorAll(".vh-provider-control").forEach((node) => node.remove());

  const progress = document.createElement("div");
  progress.className = "vh-llm-progress";
  progress.dataset.progressMode = "validated-stages";
  progress.dataset.progressSource = "request-state";
  progress.hidden = true;
  progress.setAttribute("role", "status");
  progress.setAttribute("aria-live", "polite");
  progress.innerHTML = `
    <div class="vh-llm-progress-head">
      <strong data-llm-progress-copy>Reasoning over the request…</strong>
      <span data-llm-progress-elapsed>0s</span>
    </div>
  `;
  thinking.insertAdjacentElement("afterend", progress);
  const progressCopy = progress.querySelector("[data-llm-progress-copy]");
  const progressElapsed = progress.querySelector("[data-llm-progress-elapsed]");

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

  const renderProgress = () => {
    if (!state.active) return;
    const elapsed = Math.max(0, (Date.now() - state.startedAt) / 1000);
    progress.hidden = false;
    progressCopy.textContent =
      elapsed >= 15 ? "Still working through the request…" : "Reasoning over the request…";
    progressElapsed.textContent = `${Math.floor(elapsed)}s`;
  };

  const startProgress = () => {
    if (state.active) return;
    state.active = true;
    state.startedAt = Date.now();
    if (state.timer) window.clearInterval(state.timer);
    renderProgress();
    state.timer = window.setInterval(renderProgress, 1000);
  };

  const stopProgress = () => {
    state.active = false;
    if (state.timer) window.clearInterval(state.timer);
    state.timer = null;
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