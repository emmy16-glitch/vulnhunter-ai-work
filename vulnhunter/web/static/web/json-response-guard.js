(() => {
  "use strict";

  const originalFetch = window.fetch.bind(window);

  const headerValue = (headers, name) => {
    if (!headers) return "";
    if (headers instanceof Headers) return headers.get(name) || "";
    if (Array.isArray(headers)) {
      const match = headers.find(([key]) => String(key).toLowerCase() === name.toLowerCase());
      return match ? String(match[1] || "") : "";
    }
    const key = Object.keys(headers).find((item) => item.toLowerCase() === name.toLowerCase());
    return key ? String(headers[key] || "") : "";
  };

  const expectsJson = (input, init) => {
    const initAccept = headerValue(init?.headers, "Accept");
    if (initAccept.includes("application/json")) return true;
    if (input instanceof Request) {
      return (input.headers.get("Accept") || "").includes("application/json");
    }
    return false;
  };

  const safeDetail = (response, body) => {
    if (response.redirected || response.url.includes("/login/")) {
      return "Your session expired. Refresh the page and sign in again.";
    }
    if (response.status === 413) {
      return "The APK is larger than the current upload limit. Choose a smaller APK or increase the configured limit.";
    }
    if (response.status === 403) {
      return "The request was rejected by session protection. Refresh the page and try again.";
    }
    if (response.status === 404) {
      return "The requested workspace endpoint is unavailable. Refresh the page after updating the server.";
    }
    if (response.status >= 500) {
      return `VulnHunter could not complete this request (server ${response.status}). The failure was logged on the server.`;
    }
    const title = body.match(/<title[^>]*>([^<]+)<\/title>/i)?.[1]?.trim();
    if (title && !title.toLowerCase().includes("django")) return title;
    return `The request failed with HTTP ${response.status || 502}.`;
  };

  window.fetch = async (input, init = undefined) => {
    const response = await originalFetch(input, init);
    if (!expectsJson(input, init)) return response;

    const contentType = response.headers.get("Content-Type") || "";
    if (contentType.includes("application/json")) return response;

    let body = "";
    try {
      body = await response.clone().text();
    } catch (_error) {
      body = "";
    }

    const status = response.ok ? 502 : response.status || 502;
    return new Response(JSON.stringify({ detail: safeDetail(response, body) }), {
      status,
      statusText: response.statusText || "Invalid JSON response",
      headers: {
        "Content-Type": "application/json; charset=utf-8",
        "Cache-Control": "no-store",
      },
    });
  };
})();
