(() => {
  "use strict";

  const workspace = document.querySelector("[data-conversation-workspace]");
  const form = workspace?.querySelector("[data-conversation-form]");
  if (!workspace || !form) return;
  const threadId = String(workspace.dataset.threadId || form.dataset.threadId || "");
  const originalFetch = window.fetch.bind(window);
  const csrfToken = form.querySelector("input[name='csrfmiddlewaretoken']")?.value || "";

  const withThread = (input, init = {}) => {
    const request = input instanceof Request ? input : null;
    const rawUrl = request?.url || String(input || "");
    const url = new URL(rawUrl, window.location.origin);
    if (url.origin !== window.location.origin || !url.pathname.startsWith("/workspace/")) {
      return [input, init];
    }
    const method = String(init.method || request?.method || "GET").toUpperCase();
    const headers = new Headers(init.headers || request?.headers || {});
    headers.set("X-VulnHunter-Thread", threadId);
    let body = init.body;
    if (body instanceof FormData && !body.has("thread_id")) body.append("thread_id", threadId);
    if (method === "GET") url.searchParams.set("thread", threadId);
    return [url.toString(), { ...init, method, body, headers }];
  };

  window.fetch = (input, init = {}) => {
    const [nextInput, nextInit] = withThread(input, init);
    return originalFetch(nextInput, nextInit);
  };

  const renderProgress = (record) => {
    if (record.threadId !== threadId) return;
    const tray = workspace.querySelector("[data-attachment-tray]");
    if (!tray) return;
    const total = Math.max(1, Number(record.size) || 1);
    const offset = Math.max(0, Number(record.offset) || 0);
    const percent = Math.floor((offset / total) * 100);
    tray.hidden = false;
    tray.innerHTML = "";
    const card = document.createElement("div");
    card.className = `vh-apk-uploading is-${record.state}`;
    const marker = document.createElement("span");
    const copy = document.createElement("div");
    const title = document.createElement("strong");
    const detail = document.createElement("small");
    const progress = document.createElement("progress");
    title.textContent = record.state === "completed" ? `${record.name} uploaded` : `Uploading ${record.name}`;
    detail.textContent = record.error || `${percent}% · This continues while you browse other pages.`;
    progress.max = total;
    progress.value = offset;
    copy.append(title, detail, progress);
    card.append(marker, copy);
    tray.append(card);
  };

  const fileInput = workspace.querySelector("[data-conversation-file]");
  fileInput?.addEventListener(
    "change",
    async (event) => {
      const file = fileInput.files?.[0];
      if (!file) return;
      event.stopImmediatePropagation();
      try {
        const record = await window.VulnHunterUploads.enqueue(file, {
          threadId,
          startUrl: form.dataset.uploadStartUrl,
          workspaceUrl: `${window.location.pathname}?thread=${encodeURIComponent(threadId)}`,
        });
        renderProgress(record);
      } catch (error) {
        const tray = workspace.querySelector("[data-attachment-tray]");
        if (tray) {
          tray.hidden = false;
          tray.textContent = error.message || "The APK upload could not start.";
        }
      } finally {
        fileInput.value = "";
      }
    },
    true,
  );

  for (const name of ["vh:upload-enqueued", "vh:upload-progress", "vh:upload-paused", "vh:upload-error", "vh:upload-complete"]) {
    document.addEventListener(name, (event) => {
      const record = event.detail || {};
      renderProgress(record);
      if (
        name === "vh:upload-complete" &&
        record.threadId === threadId &&
        document.visibilityState === "visible" &&
        !workspace.querySelector("[data-conversation-input]")?.value.trim()
      ) {
        window.setTimeout(() => window.location.assign(record.workspaceUrl), 500);
      }
    });
  }

  window.VulnHunterUploads?.list().then((records) => {
    const selected = records
      .filter((item) => item.threadId === threadId && item.state !== "cancelled")
      .sort((a, b) => Number(b.updatedAt || 0) - Number(a.updatedAt || 0))[0];
    if (selected) renderProgress(selected);
  });

  const createButton = workspace.querySelector("[data-thread-create]");
  createButton?.addEventListener(
    "click",
    async (event) => {
      event.preventDefault();
      event.stopImmediatePropagation();
      createButton.disabled = true;
      try {
        const payload = new FormData();
        payload.append("thread_id", threadId);
        const response = await fetch(form.dataset.threadCreateUrl, {
          method: "POST",
          body: payload,
          headers: { "X-CSRFToken": csrfToken, Accept: "application/json" },
          credentials: "same-origin",
        });
        const data = await response.json();
        if (!response.ok) throw new Error(data.detail || "A new workspace could not be created.");
        window.location.assign(data.thread.url);
      } catch (error) {
        createButton.disabled = false;
        createButton.title = error.message;
      }
    },
    true,
  );
})();
