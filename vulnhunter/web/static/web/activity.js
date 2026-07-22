(() => {
  "use strict";

  const terminalStates = new Set([
    "completed",
    "failed",
    "stopped",
    "cancelled",
    "blocked",
    "timed_out",
  ]);

  function createTextElement(tagName, className, text) {
    const element = document.createElement(tagName);
    if (className) {
      element.className = className;
    }
    element.textContent = text ?? "";
    return element;
  }

  function metadataNode(metadata) {
    const entries = Object.entries(metadata || {});
    if (!entries.length) {
      return null;
    }
    const details = document.createElement("details");
    const summary = document.createElement("summary");
    summary.textContent = "Safe metadata";
    const list = document.createElement("ul");
    list.className = "vh-rows";
    for (const [key, value] of entries) {
      const item = document.createElement("li");
      const strong = document.createElement("strong");
      strong.textContent = String(key);
      const code = document.createElement("code");
      code.textContent = typeof value === "string" ? value : JSON.stringify(value);
      item.append(strong, document.createTextNode(" "), code);
      list.append(item);
    }
    details.append(summary, list);
    return details;
  }

  function eventNode(event) {
    const item = document.createElement("li");
    item.className = "vh-activity-event";
    item.dataset.sequence = String(event.sequence);
    item.dataset.eventId = String(event.event_id);

    const marker = document.createElement("div");
    marker.className = "vh-activity-marker";
    marker.setAttribute("aria-hidden", "true");

    const content = document.createElement("div");
    content.className = "vh-activity-content";
    const time = createTextElement("time", "", event.timestamp);
    time.dateTime = String(event.timestamp);
    const title = createTextElement(
      "div",
      "vh-activity-title",
      String(event.event_type).replaceAll("_", " ")
    );
    const summary = createTextElement("p", "", event.summary);
    const meta = document.createElement("div");
    meta.className = "vh-activity-meta";
    meta.append(
      createTextElement("span", "", `State: ${String(event.run_state).replaceAll("_", " ")}`)
    );
    if (event.audit_reference) {
      meta.append(createTextElement("span", "", `Audit: ${String(event.audit_reference)}`));
    }
    content.append(time, title, summary, meta);
    const details = metadataNode(event.metadata);
    if (details) {
      content.append(details);
    }
    item.append(marker, content);
    return item;
  }

  function formatDuration(rawSeconds) {
    const elapsedSeconds = Math.max(0, Number(rawSeconds) || 0);
    const hours = String(Math.floor(elapsedSeconds / 3600)).padStart(2, "0");
    const minutes = String(Math.floor((elapsedSeconds % 3600) / 60)).padStart(2, "0");
    const seconds = String(Math.floor(elapsedSeconds % 60)).padStart(2, "0");
    return `${hours}:${minutes}:${seconds}`;
  }

  function progressFor(payload) {
    if (payload.run_state === "completed") return 100;
    const workflowProgress = {
      authorization_required: 12,
      scope_validated: 28,
      readiness_checked: 38,
      plan_generated: 48,
      awaiting_approval: 52,
      approved: 60,
      queued: 68,
      running: 74,
      executing: 78,
      evaluating: 88,
      completed: 100,
      failed: 100,
      timed_out: 100,
      cancelled: 100,
      execution_blocked: 60,
      readiness_blocked: 35,
      denied: 52,
    };
    if (payload.workflow_state in workflowProgress) return workflowProgress[payload.workflow_state];
    if (["completed", "succeeded", "tool_executed"].includes(payload.execution_state)) {
      return 100;
    }
    if (["running", "queued"].includes(payload.execution_state)) return 78;
    if (payload.approval_state === "pending") return 52;
    return 35;
  }

  function updateAssessmentChrome(payload) {
    document.querySelectorAll("[data-run-clock]").forEach((clock) => {
      clock.textContent = formatDuration(payload.elapsed_seconds);
    });

    const runState = document.querySelector(".vh-context-run .vh-live-text > span");
    if (runState && payload.run_state) {
      runState.textContent = String(payload.run_state).replaceAll("_", " ");
    }

    const progress = progressFor(payload);
    const progressValue = document.querySelector(".vh-inspector-heading .vh-tabular");
    const progressBar = document.querySelector(".vh-progress");
    const progressFill = progressBar?.querySelector("i");
    if (progressValue) progressValue.textContent = `${progress}%`;
    if (progressBar) progressBar.setAttribute("aria-valuenow", String(progress));
    if (progressFill) progressFill.style.width = `${progress}%`;

    const approvalValue = document.querySelector(".vh-inspector-grid section:first-child strong");
    if (approvalValue && payload.approval_state) {
      approvalValue.textContent = String(payload.approval_state).replaceAll("_", " ");
      approvalValue.classList.toggle("vh-text-warning", payload.approval_state === "pending");
      approvalValue.classList.toggle("vh-text-safe", payload.approval_state !== "pending");
    }

    const toolStageState = document.querySelector(".vh-stage-tool .vh-stage-state");
    if (toolStageState && (payload.workflow_state || payload.execution_state)) {
      toolStageState.textContent = String(
        payload.workflow_state || payload.execution_state
      ).replaceAll("_", " ");
    }

    document.querySelectorAll("[data-global-connection-state]").forEach((element) => {
      element.textContent = "EventSource connected to backend state";
    });

    const oracleState = document.querySelector(".vh-oracle-state strong");
    if (oracleState) {
      oracleState.textContent = payload.evaluation_result || "Awaiting evidence";
    }
  }

  function streamEndpoint(endpoint, afterSequence) {
    const normalized = `${endpoint.replace(/\/?$/, "/")}stream/`;
    const url = new URL(normalized, window.location.href);
    url.searchParams.set("after_sequence", String(afterSequence));
    return url;
  }

  function initialize(root) {
    const endpoint = root.dataset.endpoint;
    const eventList = root.querySelector(".vh-activity-events");
    const emptyState = root.querySelector(".vh-activity-empty");
    const connectionState = root.querySelector("[data-connection-state]");
    const stateLabel = root.querySelector(".vh-activity-state");
    const autoScrollButton = root.querySelector('[data-action="toggle-autoscroll"]');
    const newEventsButton = root.querySelector('[data-action="show-new-events"]');
    let afterSequence = Number(root.dataset.afterSequence || 0);
    let autoScroll = true;
    let stopped = root.dataset.terminal === "true";
    let source = null;
    const seen = new Set(
      [...eventList.querySelectorAll("[data-event-id]")].map((node) => node.dataset.eventId)
    );

    function setConnection(message) {
      connectionState.textContent = message;
      connectionState.hidden = !message;
    }

    function revealLatest() {
      eventList.lastElementChild?.scrollIntoView({ block: "nearest" });
      newEventsButton.hidden = true;
    }

    function appendEvents(events) {
      let appended = 0;
      for (const event of events) {
        if (seen.has(String(event.event_id))) {
          continue;
        }
        seen.add(String(event.event_id));
        eventList.append(eventNode(event));
        afterSequence = Math.max(afterSequence, Number(event.sequence));
        appended += 1;
      }
      emptyState.hidden = eventList.children.length > 0;
      if (appended && autoScroll) {
        revealLatest();
      } else if (appended) {
        newEventsButton.hidden = false;
      }
    }

    function connect() {
      if (stopped || !endpoint) return;
      if (!("EventSource" in window)) {
        setConnection("Live activity requires browser support for server-sent events.");
        return;
      }

      setConnection("Connecting to live activity…");
      source = new EventSource(streamEndpoint(endpoint, afterSequence), { withCredentials: true });
      source.addEventListener("activity", (message) => {
        try {
          const payload = JSON.parse(message.data);
          appendEvents(Array.isArray(payload.events) ? payload.events : []);
          afterSequence = Math.max(afterSequence, Number(payload.last_sequence || 0));
          stateLabel.textContent = payload.run_state || "No activity";
          updateAssessmentChrome(payload);
          stopped = Boolean(payload.terminal) || terminalStates.has(payload.run_state);
          if (stopped) {
            source?.close();
            setConnection(`Run ${String(payload.run_state || "stopped")} and live updates ended.`);
          } else {
            setConnection("");
          }
        } catch (error) {
          setConnection("A live activity update could not be read safely.");
        }
      });
      source.onerror = () => {
        if (!stopped) {
          setConnection("Live activity reconnecting…");
        }
      };
    }

    autoScrollButton?.addEventListener("click", () => {
      autoScroll = !autoScroll;
      autoScrollButton.setAttribute("aria-pressed", String(!autoScroll));
      autoScrollButton.textContent = autoScroll ? "Pause live view" : "Resume live view";
      if (autoScroll) {
        revealLatest();
      }
    });
    newEventsButton?.addEventListener("click", revealLatest);
    window.addEventListener("pagehide", () => source?.close());
    connect();
  }

  document.querySelectorAll(".vh-activity-timeline").forEach((root) => initialize(root));
})();
