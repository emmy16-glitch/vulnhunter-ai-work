(() => {
  "use strict";

  const workspace = document.querySelector("[data-conversation-workspace]");
  const dataElement = document.getElementById("vh-conversation-data");
  const panel = workspace?.querySelector("[data-analysis-activity]");
  const tree = panel?.querySelector("[data-analysis-activity-tree]");
  const statusLabel = panel?.querySelector("[data-analysis-activity-status]");
  const connectionLabel = panel?.querySelector("[data-analysis-activity-connection]");
  if (!workspace || !dataElement || !panel || !tree || !statusLabel || !connectionLabel) return;

  let initial = {};
  try {
    initial = JSON.parse(dataElement.textContent || "{}");
  } catch (_error) {
    return;
  }

  let socket = null;
  let reconnectTimer = null;
  let reconnectDelay = 1000;
  let currentRunId = "";
  let cursor = 0;
  let activeRun = null;
  let stopped = false;

  const text = (value) => (value === null || value === undefined ? "" : String(value));
  const pretty = (value) =>
    text(value || "unknown")
      .replaceAll("_", " ")
      .replace(/\b\w/g, (letter) => letter.toUpperCase());
  const statusMarker = (value) =>
    ({ queued: "○", running: "●", completed: "✓", blocked: "⊘", failed: "!" })[value] || "•";

  const setConnection = (message) => {
    connectionLabel.textContent = message;
    connectionLabel.hidden = !message;
  };

  const setPanelState = (run, status = null) => {
    activeRun = run || null;
    panel.hidden = !activeRun;
    if (!activeRun) {
      statusLabel.textContent = "Waiting for a task";
      tree.replaceChildren();
      setConnection("");
      return;
    }
    const activityStatus = text(status || activeRun.activity_tree?.status || activeRun.state || "running");
    statusLabel.textContent = pretty(activityStatus);
    panel.open = !activeRun.terminal && ["running", "queued"].includes(activityStatus);
  };

  const renderLeaf = (node, level) => {
    const item = document.createElement("div");
    item.className = `vh-analysis-activity-leaf is-${text(node.status || "running")}`;
    item.setAttribute("role", "treeitem");
    item.setAttribute("aria-level", String(level));
    item.dataset.activityId = text(node.activity_id);

    const marker = document.createElement("span");
    marker.className = "vh-analysis-activity-marker";
    marker.setAttribute("aria-hidden", "true");
    marker.textContent = statusMarker(text(node.status));

    const body = document.createElement("span");
    body.className = "vh-analysis-activity-node-copy";
    const label = document.createElement("strong");
    label.textContent = text(node.label || "Recorded operational activity");
    const summary = document.createElement("small");
    summary.textContent = text(node.summary || "");
    body.append(label, summary);

    const meta = document.createElement("span");
    meta.className = "vh-analysis-activity-node-meta";
    meta.textContent = pretty(node.status || "running");
    if (node.tool_id) meta.textContent += ` · ${text(node.tool_id)}`;

    item.append(marker, body, meta);
    return item;
  };

  const renderNode = (node, level = 1) => {
    const children = Array.isArray(node?.children) ? node.children : [];
    if (!children.length) return renderLeaf(node || {}, level);

    const details = document.createElement("details");
    details.className = `vh-analysis-activity-node is-${text(node.status || "running")}`;
    details.setAttribute("role", "treeitem");
    details.setAttribute("aria-level", String(level));
    details.dataset.activityId = text(node.activity_id);
    details.open = text(node.status) === "running" || text(node.status) === "failed" || text(node.status) === "blocked";

    const summary = document.createElement("summary");
    const marker = document.createElement("span");
    marker.className = "vh-analysis-activity-marker";
    marker.setAttribute("aria-hidden", "true");
    marker.textContent = statusMarker(text(node.status));
    const copy = document.createElement("span");
    copy.className = "vh-analysis-activity-node-copy";
    const label = document.createElement("strong");
    label.textContent = text(node.label || "Recorded activity");
    const detail = document.createElement("small");
    detail.textContent = text(node.summary || "");
    copy.append(label, detail);
    const count = document.createElement("span");
    count.className = "vh-analysis-activity-node-meta";
    const completed = Number(node.completed_count || 0);
    const total = Number(node.total_count || children.length);
    count.textContent = `${completed}/${total} · ${pretty(node.status || "running")}`;
    summary.append(marker, copy, count);

    const childList = document.createElement("div");
    childList.className = "vh-analysis-activity-children";
    childList.setAttribute("role", "group");
    children.forEach((child) => childList.append(renderNode(child, level + 1)));
    details.append(summary, childList);
    return details;
  };

  const renderTree = (activityTree) => {
    tree.replaceChildren();
    const nodes = Array.isArray(activityTree?.nodes) ? activityTree.nodes : [];
    if (!nodes.length) {
      const empty = document.createElement("p");
      empty.className = "vh-analysis-activity-empty";
      empty.textContent = "No persisted operational activity is available yet.";
      tree.append(empty);
      return;
    }
    nodes.forEach((node) => tree.append(renderNode(node)));
  };

  const closeSocket = () => {
    if (socket) {
      socket.onclose = null;
      socket.close();
      socket = null;
    }
  };

  const scheduleReconnect = () => {
    if (reconnectTimer || stopped || !activeRun || activeRun.terminal) return;
    setConnection("Live activity reconnecting; saved activity remains available.");
    reconnectTimer = window.setTimeout(() => {
      reconnectTimer = null;
      connect(activeRun);
    }, reconnectDelay);
    reconnectDelay = Math.min(10_000, reconnectDelay * 2);
  };

  const ticket = async (runId) => {
    const url = text(initial.realtime_ticket_url);
    if (!url) throw new Error("Realtime activity is not configured.");
    const csrf = workspace.querySelector("input[name='csrfmiddlewaretoken']")?.value || "";
    const response = await fetch(url, {
      method: "POST",
      credentials: "include",
      headers: { "Content-Type": "application/json", "X-CSRFToken": csrf },
      body: JSON.stringify({ assessment_id: runId }),
    });
    if (!response.ok) throw new Error("Realtime activity ticket was unavailable.");
    const payload = await response.json();
    if (!payload.ticket) throw new Error("Realtime activity ticket was empty.");
    return payload.ticket;
  };

  const connect = async (run) => {
    const runId = text(run?.run_id);
    if (!runId || stopped || run?.terminal) return;
    if (currentRunId !== runId) cursor = 0;
    currentRunId = runId;
    activeRun = run;
    setPanelState(run);
    closeSocket();
    if (!initial.realtime_websocket_enabled) {
      setConnection("Persisted activity is updating through the development stream.");
      return;
    }
    try {
      setConnection("Connecting to persisted activity…");
      const signedTicket = await ticket(runId);
      const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
      socket = new WebSocket(`${protocol}//${window.location.host}/ws/api/v1/assessments/${encodeURIComponent(runId)}/events/`);
      socket.addEventListener("open", () => {
        reconnectDelay = 1000;
        socket?.send(JSON.stringify({ ticket: signedTicket, after_sequence: cursor }));
      });
      socket.addEventListener("message", (message) => {
        try {
          const payload = JSON.parse(message.data || "{}");
          if (payload.type !== "assessment.snapshot") return;
          if (text(payload.assessment_id) !== currentRunId) return;
          cursor = Math.max(cursor, Number(payload.last_sequence || 0));
          renderTree(payload.activity_tree || {});
          setPanelState({ ...activeRun, ...payload, activity_tree: payload.activity_tree || activeRun?.activity_tree }, payload.activity_tree?.status || payload.run_state);
          setConnection(payload.terminal ? "Persisted activity complete." : "Live activity connected.");
          if (payload.terminal) {
            stopped = true;
            closeSocket();
          }
        } catch (_error) {
          setConnection("A live activity update could not be read safely.");
        }
      });
      socket.addEventListener("error", () => setConnection("Live activity is temporarily unavailable."));
      socket.addEventListener("close", () => {
        socket = null;
        scheduleReconnect();
      });
    } catch (_error) {
      setConnection("Live activity is unavailable; saved activity remains available.");
      scheduleReconnect();
    }
  };

  const receiveRun = (run) => {
    stopped = false;
    const nextRun = run && typeof run === "object" ? run : null;
    if (!nextRun) {
      stopped = true;
      closeSocket();
      setPanelState(null);
      return;
    }
    const sameTask = currentRunId && currentRunId === text(nextRun.run_id);
    if (sameTask) {
      cursor = Math.max(cursor, Number(nextRun.last_sequence || 0));
    }
    setPanelState(nextRun);
    renderTree(nextRun.activity_tree || {});
    if (!nextRun.terminal) connect(nextRun);
  };

  window.addEventListener("vulnhunter:run-update", (event) => receiveRun(event.detail?.run || null));
  window.addEventListener("pagehide", () => {
    stopped = true;
    if (reconnectTimer) window.clearTimeout(reconnectTimer);
    closeSocket();
  });
  receiveRun(initial.active_run || null);
})();
