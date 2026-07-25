(() => {
  "use strict";

  const feed = document.querySelector("[data-conversation-feed]");
  if (!feed) return;

  const independentlyApproved = (message) => {
    const copy = message.querySelector(".vh-message-copy")?.textContent || "";
    return (
      copy.includes("Public targets cannot be authorized from the conversation") ||
      copy.includes("independent authorization approver")
    );
  };

  const reconcile = () => {
    feed.querySelectorAll(".vh-chat-message.is-authorization_required").forEach((message) => {
      if (!independentlyApproved(message)) return;
      const actions = message.querySelector(".vh-message-actions");
      if (!actions) return;
      actions.querySelectorAll("button").forEach((button) => {
        const label = (button.textContent || "").trim().toLowerCase();
        if (label.includes("authorize") || label.includes("evidence")) button.remove();
      });
      if (!actions.querySelector("[data-independent-approval-note]")) {
        const note = document.createElement("small");
        note.dataset.independentApprovalNote = "true";
        note.textContent =
          "Use Authorizations with a separate authorised approver before returning to this workspace.";
        actions.append(note);
      }
    });
  };

  const observer = new MutationObserver(reconcile);
  observer.observe(feed, { childList: true, subtree: true });
  reconcile();
})();
