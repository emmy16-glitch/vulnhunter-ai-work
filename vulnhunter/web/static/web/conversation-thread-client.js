(() => {
  "use strict";

  const workspace = document.querySelector("[data-conversation-workspace]");
  const form = workspace?.querySelector("[data-conversation-form]");
  if (!workspace || !form) return;
  const threadId = String(workspace.dataset.threadId || form.dataset.threadId || "");
  const originalFetch = window.fetch.bind(window);
  const csrfToken = form.querySelector("input[name='csrfmiddlewaretoken']")?.value || "";
  const fileInput = workspace.querySelector("[data-conversation-file]");

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

  const formatBytes = (value) => {
    const bytes = Math.max(0, Number(value) || 0);
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  };

  const uploadPresentation = (record) => {
    const total = Math.max(1, Number(record.size) || 1);
    const offset = Math.min(total, Math.max(0, Number(record.offset) || 0));
    const percent = Math.floor((offset / total) * 100);
    const name = String(record.name || "Android application.apk");
    const bytes = `${formatBytes(offset)} of ${formatBytes(total)}`;
    const state = String(record.state || "queued");
    if (state === "uploading") {
      return {
        title: `Uploading ${name}`,
        detail: `${percent}% · ${bytes}`,
        measurable: true,
      };
    }
    if (state === "retrying") {
      return {
        title: `Upload paused for ${name}`,
        detail: record.error
          ? `${record.error} ${bytes} preserved; retrying safely.`
          : `Connection interrupted · ${bytes} preserved; retrying safely.`,
        measurable: true,
      };
    }
    if (state === "processing") {
      return {
        title: `${name} uploaded`,
        detail: "Upload bytes complete · validating the artifact and binding the assessment.",
        measurable: false,
      };
    }
    if (state === "completed") {
      return {
        title: `${name} ready`,
        detail: "Artifact validated · the server confirmed the assessment result for this upload.",
        measurable: false,
      };
    }
    if (state === "failed") {
      return {
        title: `${name} needs attention`,
        detail: record.error || "The upload stopped before the artifact was ready.",
        measurable: false,
      };
    }
    return {
      title: `${name} queued`,
      detail: `${formatBytes(total)} selected · waiting for the upload worker.`,
      measurable: true,
    };
  };

  const clearProgress = () => {
    const tray = workspace.querySelector("[data-attachment-tray]");
    if (!tray) return;
    tray.replaceChildren();
    tray.hidden = true;
  };

  const renderProgress = (record) => {
    if (record.threadId !== threadId) return;
    const tray = workspace.querySelector("[data-attachment-tray]");
    if (!tray) return;
    const total = Math.max(1, Number(record.size) || 1);
    const offset = Math.min(total, Math.max(0, Number(record.offset) || 0));
    const presentation = uploadPresentation(record);
    tray.hidden = false;
    tray.replaceChildren();
    const card = document.createElement("div");
    card.className = `vh-apk-uploading is-${record.state}`;
    card.dataset.uploadState = String(record.state || "queued");
    card.setAttribute("role", "status");
    const marker = document.createElement("span");
    marker.setAttribute("aria-hidden", "true");
    const copy = document.createElement("div");
    const title = document.createElement("strong");
    const detail = document.createElement("small");
    title.textContent = presentation.title;
    detail.textContent = presentation.detail;
    copy.append(title, detail);
    if (presentation.measurable) {
      const progress = document.createElement("progress");
      progress.max = total;
      progress.value = offset;
      progress.setAttribute("aria-label", `Uploaded ${formatBytes(offset)} of ${formatBytes(total)}`);
      copy.append(progress);
    }
    const actions = document.createElement("div");
    actions.className = "vh-upload-actions";
    if (record.state === "failed") {
      const needsFile = /choose the file again/i.test(String(record.error || ""));
      const action = document.createElement("button");
      action.type = "button";
      action.textContent = needsFile ? "Choose file again" : "Retry upload";
      action.addEventListener("click", () => {
        if (needsFile) fileInput?.click();
        else window.VulnHunterUploads?.retry(record.localId);
      });
      actions.append(action);
    }
    if (["queued", "uploading", "retrying"].includes(record.state)) {
      const cancel = document.createElement("button");
      cancel.type = "button";
      cancel.textContent = "Cancel upload";
      cancel.addEventListener("click", () => window.VulnHunterUploads?.cancel(record.localId));
      actions.append(cancel);
    }
    if (actions.childElementCount) copy.append(actions);
    card.append(marker, copy);
    tray.append(card);
  };

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

  for (const name of [
    "vh:upload-enqueued",
    "vh:upload-progress",
    "vh:upload-paused",
    "vh:upload-error",
    "vh:upload-complete",
  ]) {
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
  document.addEventListener("vh:upload-cancelled", (event) => {
    if (event.detail?.threadId === threadId) clearProgress();
  });

  window.VulnHunterUploads?.list().then((records) => {
    const selected = records
      .filter((item) => item.threadId === threadId && item.state !== "cancelled")
      .sort((a, b) => Number(b.updatedAt || 0) - Number(a.updatedAt || 0))[0];
    if (selected) renderProgress(selected);
  });

  const persistedStageProgress = /^\s*(\d+)\s+of\s+(\d+)\s+persisted stages complete\s*$/i;

  const syncTaskStageProgress = (track) => {
    if (!(track instanceof HTMLElement)) return;
    const label = track.querySelector(".vh-run-stage-current small")?.textContent || "";
    const meter = track.querySelector(".vh-run-progress-meter");
    const fill = meter?.querySelector("span");
    if (!(meter instanceof HTMLElement) || !(fill instanceof HTMLElement)) return;
    const match = label.match(persistedStageProgress);
    if (!match) {
      meter.hidden = true;
      meter.removeAttribute("role");
      meter.removeAttribute("aria-valuenow");
      meter.removeAttribute("aria-valuemax");
      meter.removeAttribute("aria-label");
      delete meter.dataset.progressMeasurement;
      fill.style.removeProperty("width");
      return;
    }
    const completed = Number(match[1]);
    const total = Number(match[2]);
    if (!Number.isInteger(completed) || !Number.isInteger(total) || total <= 0 || completed < 0 || completed > total) {
      meter.hidden = true;
      return;
    }
    meter.hidden = false;
    meter.dataset.progressMeasurement = "stage";
    meter.setAttribute("role", "progressbar");
    meter.setAttribute("aria-valuenow", String(completed));
    meter.setAttribute("aria-valuemax", String(total));
    meter.setAttribute("aria-label", `${completed} of ${total} persisted stages complete`);
    fill.style.width = `${(completed / total) * 100}%`;
  };

  const taskProgressObserver = new MutationObserver((mutations) => {
    const tracks = new Set();
    for (const mutation of mutations) {
      const target = mutation.target instanceof Element ? mutation.target : mutation.target.parentElement;
      const track = target?.closest?.("[data-run-stages]");
      if (track) tracks.add(track);
      for (const node of mutation.addedNodes) {
        if (!(node instanceof Element)) continue;
        if (node.matches("[data-run-stages]")) tracks.add(node);
        node.querySelectorAll?.("[data-run-stages]").forEach((item) => tracks.add(item));
      }
    }
    tracks.forEach(syncTaskStageProgress);
  });
  taskProgressObserver.observe(workspace, { childList: true, subtree: true, characterData: true });
  workspace.querySelectorAll("[data-run-stages]").forEach(syncTaskStageProgress);

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
