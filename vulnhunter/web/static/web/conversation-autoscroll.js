(() => {
  "use strict";

  const feed = document.querySelector("[data-conversation-feed]");
  if (!feed) return;

  let scheduled = false;
  const scrollToLatest = () => {
    if (scheduled) return;
    scheduled = true;
    window.requestAnimationFrame(() => {
      feed.scrollTop = feed.scrollHeight;
      scheduled = false;
    });
  };

  const observer = new MutationObserver(scrollToLatest);
  observer.observe(feed, {
    childList: true,
    subtree: true,
    characterData: true,
  });
  scrollToLatest();

  const dataElement = document.getElementById("vh-conversation-data");
  const messageTemplate = document.getElementById("vh-message-template");
  if (!dataElement || !messageTemplate) return;

  let initial;
  try {
    initial = JSON.parse(dataElement.textContent || "{}");
  } catch (_error) {
    return;
  }

  const run = initial.active_run;
  const groqReady = Boolean(initial.groq?.configured);
  const intelligenceEnabled = groqReady && Boolean(run?.run_id);
  if (!intelligenceEnabled) return;

  const advisoryEvent = (candidateRun) => {
    const events = Array.isArray(candidateRun?.events) ? candidateRun.events : [];
    return events.findLast?.(
      (event) =>
        event?.event_type === "evaluation_completed" &&
        event?.metadata?.advisory_only === true
    ) || events.slice().reverse().find(
      (event) =>
        event?.event_type === "evaluation_completed" &&
        event?.metadata?.advisory_only === true
    );
  };

  const renderAdvisoryResult = (event) => {
    if (!event || feed.querySelector("[data-advisory-result]")) return;
    const metadata = event.metadata && typeof event.metadata === "object" ? event.metadata : {};
    const conclusion = String(metadata.conclusion || metadata.status || "advisory review");
    const summary = String(metadata.summary || event.summary || "Advisory analysis completed.");
    const modelList = Array.isArray(metadata.models) ? metadata.models.join(" and ") : "GPT-OSS";

    const fragment = messageTemplate.content.cloneNode(true);
    const article = fragment.querySelector(".vh-chat-message");
    const avatar = fragment.querySelector(".vh-message-avatar");
    const copy = fragment.querySelector(".vh-message-copy");
    const actions = fragment.querySelector(".vh-message-actions");
    article.classList.add("is-assistant", "is-status");
    article.dataset.advisoryResult = "true";
    avatar.textContent = "VH";
    copy.textContent = `Advisory reasoning (${modelList}) concluded ${conclusion}: ${summary}`;
    actions?.remove();
    feed.append(fragment);

    const track = document.querySelector("[data-run-stages]");
    if (track && !track.querySelector("[data-intelligence-stage]")) {
      const item = document.createElement("div");
      item.className = "vh-run-stage is-complete";
      item.dataset.intelligenceStage = "true";
      const marker = document.createElement("span");
      marker.textContent = "✓";
      const body = document.createElement("span");
      const strong = document.createElement("strong");
      const small = document.createElement("small");
      strong.textContent = "Advisory reasoning";
      small.textContent = metadata.status === "abstained" ? "Abstained safely" : "Completed";
      body.append(strong, small);
      item.append(marker, body);
      const completeStage = track.lastElementChild;
      track.insertBefore(item, completeStage || null);
    }
    scrollToLatest();
  };

  const existing = advisoryEvent(run);
  if (existing) {
    renderAdvisoryResult(existing);
    return;
  }

  const statusTemplate = String(initial.status_url_template || "");
  if (!statusTemplate) return;
  const deadline = Date.now() + 180_000;
  let stopped = false;

  const poll = async () => {
    if (stopped || Date.now() >= deadline) return;
    const url = statusTemplate.replace("RUN_ID", encodeURIComponent(String(run.run_id)));
    try {
      const response = await fetch(url, {
        credentials: "same-origin",
        headers: { Accept: "application/json" },
      });
      const data = await response.json();
      if (response.ok) {
        const result = advisoryEvent(data.run);
        if (result) {
          stopped = true;
          renderAdvisoryResult(result);
          return;
        }
        const findings = Array.isArray(data.run?.findings) ? data.run.findings : [];
        if (data.run?.terminal && findings.length === 0) return;
      }
    } catch (_error) {
      // The main assessment remains usable; advisory polling is optional.
    }
    window.setTimeout(poll, 2000);
  };

  window.setTimeout(poll, 1500);
})();
