(() => {
  "use strict";

  if (typeof document === "undefined" || typeof window === "undefined") return;

  const workspace = document.querySelector("[data-conversation-workspace]");
  const dataElement = document.getElementById("vh-conversation-data");
  const form = document.querySelector("[data-conversation-form]");
  const runtime = document.querySelector("[data-provider-runtime]");
  if (!workspace || !dataElement || !form || !runtime) return;

  let initial;
  try {
    initial = JSON.parse(dataElement.textContent || "{}");
  } catch (_error) {
    return;
  }

  // Provider routing and health are backend concerns. Keep the infrastructure
  // status hidden from ordinary users and do not create a second activity system.
  runtime.hidden = true;
  runtime.setAttribute("aria-hidden", "true");
  runtime.textContent = "Automatic routing";
  runtime.removeAttribute("title");
  runtime.dataset.providerPreferenceActive = "auto";
  runtime.classList.remove("is-ready", "is-warning", "is-offline");

  // Keep the request contract compatible with the server while making provider
  // selection invisible. The server-side router owns all fallback decisions.
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
})();
