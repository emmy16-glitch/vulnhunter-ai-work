(() => {
  "use strict";

  if (typeof window === "undefined" || typeof window.fetch !== "function") return;
  if (window.__vhUploadRecoveryInstalled === true) return;
  window.__vhUploadRecoveryInstalled = true;

  const originalFetch = window.fetch.bind(window);
  const chunkPath = /^(.*\/workspace\/uploads\/[^/]+)\/chunk\/?$/;

  const requestUrl = (input) => {
    if (typeof input === "string") return input;
    if (input && typeof input.url === "string") return input.url;
    return "";
  };

  const submittedOffset = (init) => {
    const body = init?.body;
    if (!body || typeof body.get !== "function") return null;
    const value = Number(body.get("offset"));
    return Number.isFinite(value) && value >= 0 ? value : null;
  };

  const threadHeader = (init) => {
    const headers = init?.headers;
    if (!headers) return "";
    if (typeof headers.get === "function") return headers.get("X-VulnHunter-Thread") || "";
    return headers["X-VulnHunter-Thread"] || headers["x-vulnhunter-thread"] || "";
  };

  const recoveryResponse = async (url, init, offset) => {
    const parsed = new URL(url, window.location?.href || "http://localhost/");
    const match = parsed.pathname.match(chunkPath);
    if (!match) return null;
    parsed.pathname = `${match[1]}/status/`;
    parsed.search = "";
    parsed.hash = "";
    const headers = { Accept: "application/json" };
    const threadId = threadHeader(init);
    if (threadId) headers["X-VulnHunter-Thread"] = threadId;
    const status = await originalFetch(parsed.toString(), {
      method: "GET",
      credentials: init?.credentials || "same-origin",
      headers,
    });
    if (!status.ok) return null;
    let body;
    try {
      body = await status.clone().json();
    } catch (_error) {
      return null;
    }
    const completed = body?.upload?.complete === true;
    const received = Number(body?.upload?.received_bytes ?? body?.received_bytes);
    if (completed && Number.isFinite(received) && received >= offset) return status;
    if (Number.isFinite(received) && received > offset) return status;
    if (Number.isFinite(received) && received === offset) return "retry";
    return null;
  };

  window.fetch = async (input, init = undefined) => {
    const url = requestUrl(input);
    const method = String(init?.method || "GET").toUpperCase();
    const offset = submittedOffset(init);
    if (method !== "POST" || offset === null || !chunkPath.test(new URL(url, window.location?.href || "http://localhost/").pathname)) {
      return originalFetch(input, init);
    }
    try {
      return await originalFetch(input, init);
    } catch (firstError) {
      let recovered;
      try {
        recovered = await recoveryResponse(url, init, offset);
      } catch (_statusError) {
        throw firstError;
      }
      if (recovered && recovered !== "retry") return recovered;
      if (recovered === "retry") return originalFetch(input, init);
      throw firstError;
    }
  };
})();
