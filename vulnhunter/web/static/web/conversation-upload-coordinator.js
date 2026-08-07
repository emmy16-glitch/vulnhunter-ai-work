(() => {
  "use strict";

  const DB_NAME = "vulnhunter-background-uploads";
  const STORE_NAME = "uploads";
  const DB_VERSION = 1;
  const MAX_CONCURRENT = 2;
  const running = new Set();
  let schedulerTimer = null;

  const text = (value) => (value === null || value === undefined ? "" : String(value));
  const csrfToken = () => {
    const match = document.cookie.match(/(?:^|;\s*)csrftoken=([^;]+)/);
    if (match) return decodeURIComponent(match[1]);
    return document.querySelector("input[name='csrfmiddlewaretoken']")?.value || "";
  };
  const absoluteUrl = (value) => new URL(value, window.location.origin).toString();
  const sameOrigin = (value) => new URL(value, window.location.origin).origin === window.location.origin;
  const formatBytes = (value) => {
    const bytes = Math.max(0, Number(value) || 0);
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  };

  const openDatabase = () =>
    new Promise((resolve, reject) => {
      const request = indexedDB.open(DB_NAME, DB_VERSION);
      request.onupgradeneeded = () => {
        const database = request.result;
        if (!database.objectStoreNames.contains(STORE_NAME)) {
          const store = database.createObjectStore(STORE_NAME, { keyPath: "localId" });
          store.createIndex("state", "state", { unique: false });
          store.createIndex("threadId", "threadId", { unique: false });
        }
      };
      request.onsuccess = () => resolve(request.result);
      request.onerror = () => reject(request.error || new Error("Upload storage is unavailable."));
    });

  const transaction = async (mode, callback) => {
    const database = await openDatabase();
    return new Promise((resolve, reject) => {
      const tx = database.transaction(STORE_NAME, mode);
      const store = tx.objectStore(STORE_NAME);
      let result;
      try {
        result = callback(store);
      } catch (error) {
        database.close();
        reject(error);
        return;
      }
      tx.oncomplete = () => {
        database.close();
        resolve(result);
      };
      tx.onerror = () => {
        database.close();
        reject(tx.error || new Error("Upload storage transaction failed."));
      };
      tx.onabort = tx.onerror;
    });
  };

  const requestResult = (request) =>
    new Promise((resolve, reject) => {
      request.onsuccess = () => resolve(request.result);
      request.onerror = () => reject(request.error || new Error("Upload storage request failed."));
    });

  const getRecord = async (localId) => {
    const database = await openDatabase();
    try {
      const tx = database.transaction(STORE_NAME, "readonly");
      return await requestResult(tx.objectStore(STORE_NAME).get(localId));
    } finally {
      database.close();
    }
  };

  const listRecords = async () => {
    const database = await openDatabase();
    try {
      const tx = database.transaction(STORE_NAME, "readonly");
      return (await requestResult(tx.objectStore(STORE_NAME).getAll())) || [];
    } finally {
      database.close();
    }
  };

  const putRecord = async (record) => {
    record.updatedAt = Date.now();
    const database = await openDatabase();
    try {
      const tx = database.transaction(STORE_NAME, "readwrite");
      await requestResult(tx.objectStore(STORE_NAME).put(record));
      await new Promise((resolve, reject) => {
        tx.oncomplete = resolve;
        tx.onerror = () => reject(tx.error || new Error("Upload state could not be saved."));
        tx.onabort = tx.onerror;
      });
    } finally {
      database.close();
    }
    emit("vh:upload-progress", record);
    renderDock();
    return record;
  };

  const deleteRecord = async (localId) => {
    const database = await openDatabase();
    try {
      const tx = database.transaction(STORE_NAME, "readwrite");
      await requestResult(tx.objectStore(STORE_NAME).delete(localId));
    } finally {
      database.close();
    }
    renderDock();
  };

  const emit = (name, detail) => {
    document.dispatchEvent(new CustomEvent(name, { detail }));
    try {
      const channel = new BroadcastChannel("vulnhunter-uploads");
      channel.postMessage({ name, detail: { ...detail, file: undefined } });
      channel.close();
    } catch (_error) {
      // BroadcastChannel is optional; IndexedDB remains authoritative.
    }
  };

  const readJson = async (response) => {
    try {
      return await response.json();
    } catch (_error) {
      return { detail: "The server returned an unreadable upload response." };
    }
  };

  const refreshSessionProtection = async () => {
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
    const headers = new Headers(options.headers || {});
    headers.set("Accept", "application/json");
    if (threadId) headers.set("X-VulnHunter-Thread", threadId);
    const token = csrfToken();
    if (token && String(options.method || "GET").toUpperCase() !== "GET") {
      headers.set("X-CSRFToken", token);
    }
    const response = await fetch(url, {
      ...options,
      headers,
      credentials: "same-origin",
      cache: "no-store",
    });
    const payload = await readJson(response);
    if (response.status === 403 && !retried) {
      await refreshSessionProtection();
      return request(url, options, threadId, true);
    }
    if (!response.ok) {
      const error = new Error(payload.detail || "The upload request failed.");
      error.status = response.status;
      throw error;
    }
    return payload;
  };

  const startServerUpload = async (record) => {
    const body = new FormData();
    body.append("filename", record.name);
    body.append("size_bytes", String(record.size));
    body.append("thread_id", record.threadId);
    const payload = await request(record.startUrl, { method: "POST", body }, record.threadId);
    record.uploadId = text(payload.upload_id);
    record.chunkUrl = absoluteUrl(payload.chunk_url);
    record.statusUrl = absoluteUrl(payload.status_url);
    record.cancelUrl = absoluteUrl(payload.cancel_url);
    record.chunkBytes = Math.max(1024 * 1024, Number(payload.chunk_bytes) || 8 * 1024 * 1024);
    record.offset = Number(payload.received_bytes) || 0;
    record.state = "uploading";
    record.error = "";
    await putRecord(record);
  };

  const completeFromServerPayload = async (record, payload) => {
    const upload = payload?.upload || payload;
    const offset = Number(upload?.received_bytes);
    const hasFinalResult = Boolean(payload?.attachment || payload?.auto_started || payload?.mobile_plan);
    if (upload?.complete !== true || !hasFinalResult || offset !== record.size) return false;
    record.state = "completed";
    record.completedAt = Date.now();
    record.offset = record.size;
    record.error = "";
    record.retryAt = 0;
    await putRecord(record);
    emit("vh:upload-complete", record);
    return true;
  };

  const reconcileOffset = async (record) => {
    if (!record.uploadId || !record.statusUrl) return false;
    try {
      const payload = await request(record.statusUrl, { method: "GET" }, record.threadId);
      if (await completeFromServerPayload(record, payload)) return true;
      const offset = Number(payload.received_bytes ?? payload.upload?.received_bytes);
      if (!Number.isFinite(offset) || offset < 0 || offset > record.size) {
        throw new Error("The server returned an invalid resumable upload offset.");
      }
      record.offset = offset;
      await putRecord(record);
      return false;
    } catch (error) {
      if (error.status !== 404) throw error;
      record.uploadId = "";
      record.chunkUrl = "";
      record.statusUrl = "";
      record.cancelUrl = "";
      record.offset = 0;
      await putRecord(record);
      return false;
    }
  };

  const uploadChunks = async (record) => {
    while (record.offset < record.size) {
      const end = Math.min(record.size, record.offset + record.chunkBytes);
      const body = new FormData();
      body.append("offset", String(record.offset));
      body.append("thread_id", record.threadId);
      body.append("chunk", record.file.slice(record.offset, end), `${record.name}.part`);
      const payload = await request(record.chunkUrl, { method: "POST", body }, record.threadId);
      if (await completeFromServerPayload(record, payload)) return;
      const nextOffset = Number(payload.received_bytes ?? payload.upload?.received_bytes);
      if (!Number.isFinite(nextOffset) || nextOffset <= record.offset || nextOffset > record.size) {
        throw new Error("The server returned an invalid APK upload offset.");
      }
      record.offset = nextOffset;
      record.state = record.offset === record.size ? "processing" : "uploading";
      record.error = "";
      await putRecord(record);
    }
  };

  const processRecord = async (localId) => {
    const execute = async () => {
      let record = await getRecord(localId);
      if (!record || ["completed", "cancelled", "failed"].includes(record.state)) return;
      if (!(record.file instanceof Blob) || record.file.size !== record.size) {
        record.state = "failed";
        record.error = "The browser no longer has the selected APK bytes. Choose the file again.";
        await putRecord(record);
        emit("vh:upload-error", record);
        return;
      }
      try {
        record.state = "uploading";
        record.error = "";
        await putRecord(record);
        if (await reconcileOffset(record)) return;
        if (!record.uploadId) await startServerUpload(record);
        await uploadChunks(record);
      } catch (error) {
        record = (await getRecord(localId)) || record;
        const permanent = [400, 401, 403, 413].includes(Number(error.status || 0));
        record.state = permanent ? "failed" : "retrying";
        record.error = text(error.message || "The upload was interrupted.");
        record.retryAt = Date.now() + (permanent ? 0 : 3000);
        await putRecord(record);
        emit(permanent ? "vh:upload-error" : "vh:upload-paused", record);
      }
    };

    if (navigator.locks?.request) {
      await navigator.locks.request(`vulnhunter-upload-${localId}`, { ifAvailable: true }, async (lock) => {
        if (lock) await execute();
      });
    } else {
      await execute();
    }
  };

  const schedule = async () => {
    if (schedulerTimer) window.clearTimeout(schedulerTimer);
    const records = await listRecords().catch(() => []);
    const candidates = records.filter(
      (item) =>
        ["queued", "uploading", "processing", "retrying"].includes(item.state) &&
        (!item.retryAt || item.retryAt <= Date.now()),
    );
    for (const record of candidates) {
      if (running.size >= MAX_CONCURRENT) break;
      if (running.has(record.localId)) continue;
      running.add(record.localId);
      processRecord(record.localId)
        .catch(() => undefined)
        .finally(() => {
          running.delete(record.localId);
          schedule();
        });
    }
    schedulerTimer = window.setTimeout(schedule, candidates.length ? 1500 : 4000);
  };

  const ensureDock = () => {
    let dock = document.querySelector("[data-background-upload-dock]");
    if (dock) return dock;
    dock = document.createElement("aside");
    dock.className = "vh-background-upload-dock";
    dock.dataset.backgroundUploadDock = "";
    dock.setAttribute("aria-live", "polite");
    dock.hidden = true;
    document.body.append(dock);
    return dock;
  };

  const renderDock = async () => {
    if (!document.body) return;
    const dock = ensureDock();
    const records = (await listRecords().catch(() => []))
      .filter((item) => item.state !== "cancelled")
      .sort((a, b) => Number(b.updatedAt || 0) - Number(a.updatedAt || 0))
      .slice(0, 4);
    dock.replaceChildren();
    dock.hidden = records.length === 0;
    records.forEach((record) => {
      const row = document.createElement("article");
      row.className = `vh-background-upload is-${record.state}`;
      const body = document.createElement("div");
      const title = document.createElement("strong");
      title.textContent = record.name;
      const detail = document.createElement("small");
      const percent = Math.floor((Math.max(0, Number(record.offset) || 0) / Math.max(1, record.size)) * 100);
      const labels = {
        queued: "Queued",
        uploading: `Uploading · ${percent}%`,
        processing: "Validating and starting analysis",
        retrying: "Connection interrupted · retrying",
        completed: "Upload complete · analysis started",
        failed: "Upload needs attention",
      };
      detail.textContent = `${labels[record.state] || record.state} · ${formatBytes(record.offset)} of ${formatBytes(record.size)}`;
      if (record.error) detail.title = record.error;
      const progress = document.createElement("progress");
      progress.max = Math.max(1, record.size);
      progress.value = Math.max(0, Number(record.offset) || 0);
      body.append(title, detail, progress);
      const actions = document.createElement("div");
      if (record.workspaceUrl) {
        const open = document.createElement("a");
        open.href = record.workspaceUrl;
        open.textContent = "Open";
        actions.append(open);
      }
      if (record.state === "failed") {
        const retryButton = document.createElement("button");
        retryButton.type = "button";
        retryButton.textContent = "Retry";
        retryButton.addEventListener("click", () => window.VulnHunterUploads.retry(record.localId));
        actions.append(retryButton);
      }
      if (!["completed", "cancelled"].includes(record.state)) {
        const cancel = document.createElement("button");
        cancel.type = "button";
        cancel.textContent = "Cancel";
        cancel.addEventListener("click", () => window.VulnHunterUploads.cancel(record.localId));
        actions.append(cancel);
      } else {
        const dismiss = document.createElement("button");
        dismiss.type = "button";
        dismiss.textContent = "Dismiss";
        dismiss.addEventListener("click", () => deleteRecord(record.localId));
        actions.append(dismiss);
      }
      row.append(body, actions);
      dock.append(row);
    });
  };

  const enqueue = async (file, options) => {
    if (!(file instanceof Blob) || !file.size) throw new Error("Choose a non-empty APK file.");
    if (!text(file.name).toLowerCase().endsWith(".apk")) {
      throw new Error("Choose a file with the .apk extension.");
    }
    if (!options?.threadId || !options?.startUrl || !sameOrigin(options.startUrl)) {
      throw new Error("This workspace cannot start a background APK upload.");
    }
    if (navigator.storage?.persist) await navigator.storage.persist().catch(() => false);
    const localId = crypto.randomUUID();
    const record = {
      localId,
      threadId: text(options.threadId),
      workspaceUrl: text(options.workspaceUrl),
      startUrl: absoluteUrl(options.startUrl),
      uploadId: "",
      chunkUrl: "",
      statusUrl: "",
      cancelUrl: "",
      chunkBytes: 8 * 1024 * 1024,
      file,
      name: text(file.name || "application.apk"),
      type: text(file.type || "application/vnd.android.package-archive"),
      size: file.size,
      offset: 0,
      state: "queued",
      error: "",
      createdAt: Date.now(),
      updatedAt: Date.now(),
    };
    await putRecord(record);
    emit("vh:upload-enqueued", record);
    schedule();
    return record;
  };

  const retry = async (localId) => {
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
    const record = await getRecord(localId);
    if (!record) return;
    if (record.cancelUrl) {
      const body = new FormData();
      body.append("thread_id", record.threadId);
      await request(record.cancelUrl, { method: "POST", body }, record.threadId).catch(() => undefined);
    }
    record.state = "cancelled";
    record.error = "";
    await putRecord(record);
    await deleteRecord(localId);
    emit("vh:upload-cancelled", record);
  };

  window.VulnHunterUploads = { enqueue, retry, cancel, list: listRecords, resume: schedule };
  document.addEventListener("DOMContentLoaded", () => {
    renderDock();
    schedule();
  });
  window.addEventListener("online", schedule);
  try {
    const channel = new BroadcastChannel("vulnhunter-uploads");
    channel.addEventListener("message", () => renderDock());
  } catch (_error) {
    // Optional cross-tab notifications.
  }
})();