(() => {
  "use strict";

  const current = document.currentScript?.src;
  if (current && !document.querySelector("link[data-jump-latest-styles]")) {
    const styleUrl = new URL(current, window.location.href);
    styleUrl.pathname = styleUrl.pathname.replace(
      /conversation-autoscroll\.js$/,
      "conversation-jump-latest.css",
    );
    styleUrl.search = "?v=20260801-jump-latest1";
    const link = document.createElement("link");
    link.rel = "stylesheet";
    link.href = styleUrl.toString();
    link.dataset.jumpLatestStyles = "true";
    document.head.append(link);
  }

  const feed = document.querySelector("[data-conversation-feed]");
  const composer = document.querySelector("[data-conversation-form]");
  if (!feed || !composer) return;

  const bottomThreshold = 96;
  let followingLatest = true;
  let scheduled = false;
  let programmatic = false;
  let unreadMessages = 0;
  let knownMessageCount = feed.querySelectorAll(".vh-chat-message").length;

  const jump = document.createElement("button");
  jump.type = "button";
  jump.className = "vh-jump-latest";
  jump.dataset.jumpLatest = "true";
  jump.hidden = true;
  jump.setAttribute("aria-live", "polite");
  jump.setAttribute("aria-label", "Jump to the latest conversation message");
  composer.append(jump);

  const distanceFromBottom = () =>
    Math.max(0, feed.scrollHeight - feed.scrollTop - feed.clientHeight);

  const renderJump = () => {
    const show = !followingLatest && distanceFromBottom() > bottomThreshold;
    jump.hidden = !show;
    jump.dataset.unread = unreadMessages > 0 ? "true" : "false";
    jump.textContent = unreadMessages > 0 ? `↓ ${unreadMessages} new` : "↓ Latest";
    jump.title = unreadMessages > 0
      ? `${unreadMessages} new conversation message${unreadMessages === 1 ? "" : "s"}`
      : "Jump to the latest conversation message";
  };

  const publishState = () => {
    feed.dataset.followLatest = followingLatest ? "true" : "false";
    renderJump();
  };

  const syncFromPosition = () => {
    if (programmatic) return;
    followingLatest = distanceFromBottom() <= bottomThreshold;
    if (followingLatest) unreadMessages = 0;
    publishState();
  };

  const scrollToLatest = ({ behavior = "smooth", force = false } = {}) => {
    if (!force && !followingLatest) return false;
    if (scheduled) return true;
    scheduled = true;
    programmatic = true;
    window.requestAnimationFrame(() => {
      feed.scrollTo({ top: feed.scrollHeight, behavior });
      scheduled = false;
      window.setTimeout(() => {
        programmatic = false;
        followingLatest = distanceFromBottom() <= bottomThreshold;
        if (followingLatest) unreadMessages = 0;
        publishState();
      }, behavior === "smooth" ? 280 : 0);
    });
    return true;
  };

  const pauseFollowing = () => {
    if (distanceFromBottom() > bottomThreshold) {
      followingLatest = false;
      publishState();
    }
  };

  const resume = (behavior = "smooth") => {
    followingLatest = true;
    unreadMessages = 0;
    publishState();
    scrollToLatest({ behavior, force: true });
  };

  jump.addEventListener("click", () => resume("smooth"));
  feed.addEventListener("scroll", syncFromPosition, { passive: true });
  feed.addEventListener("wheel", pauseFollowing, { passive: true });
  feed.addEventListener("touchstart", pauseFollowing, { passive: true });
  feed.addEventListener("pointerdown", pauseFollowing, { passive: true });

  const observer = new MutationObserver(() => {
    const nextMessageCount = feed.querySelectorAll(".vh-chat-message").length;
    const addedMessages = Math.max(0, nextMessageCount - knownMessageCount);
    knownMessageCount = nextMessageCount;
    if (!followingLatest && addedMessages > 0) unreadMessages += addedMessages;
    scrollToLatest({ behavior: "auto" });
    publishState();
  });
  observer.observe(feed, {
    childList: true,
    subtree: true,
    characterData: true,
  });

  window.VulnHunterConversationScroll = {
    isFollowingLatest: () => followingLatest,
    unreadCount: () => unreadMessages,
    resume,
    scrollToLatest,
  };

  publishState();
  scrollToLatest({ behavior: "auto", force: true });
})();
