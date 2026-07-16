(() => {
  "use strict";

  const terminalStates = new Set(["completed", "failed", "stopped", "cancelled", "blocked"]);

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
    const title = createTextElement("div", "vh-activity-title", String(event.event_type).replaceAll("_", " "));
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
    let timer = null;
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

    async function poll() {
      if (stopped || !endpoint) {
        return;
      }
      setConnection("Loading activity…");
      try {
        const url = new URL(endpoint, window.location.href);
        url.searchParams.set("after_sequence", String(afterSequence));
        const response = await fetch(url, {
          credentials: "same-origin",
          headers: { Accept: "application/json" },
        });
        if (!response.ok) {
          throw new Error(`HTTP ${response.status}`);
        }
        const payload = await response.json();
        appendEvents(Array.isArray(payload.events) ? payload.events : []);
        stateLabel.textContent = payload.run_state || "No activity";
        stopped = Boolean(payload.terminal) || terminalStates.has(payload.run_state);
        if (stopped) {
          setConnection(`Run ${String(payload.run_state || "stopped")} and polling stopped.`);
        } else {
          setConnection("");
        }
      } catch (error) {
        setConnection("Disconnected temporarily. Retrying safely.");
      } finally {
        if (!stopped) {
          timer = window.setTimeout(poll, Number(root.dataset.pollIntervalMs || 1500));
        }
      }
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
    window.addEventListener("pagehide", () => {
      if (timer !== null) {
        window.clearTimeout(timer);
      }
    });
    poll();
  }

  document.querySelectorAll(".vh-activity-timeline").forEach((root) => initialize(root));
})();
