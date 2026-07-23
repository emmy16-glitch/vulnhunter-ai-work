(() => {
  "use strict";

  const feed = document.querySelector("[data-conversation-feed]");
  if (!feed) return;

  const bottomThreshold = 96;
  let followingLatest = true;
  let scheduled = false;
  let programmatic = false;

  const distanceFromBottom = () =>
    Math.max(0, feed.scrollHeight - feed.scrollTop - feed.clientHeight);

  const publishState = () => {
    feed.dataset.followLatest = followingLatest ? "true" : "false";
  };

  const syncFromPosition = () => {
    if (programmatic) return;
    followingLatest = distanceFromBottom() <= bottomThreshold;
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

  feed.addEventListener("scroll", syncFromPosition, { passive: true });
  feed.addEventListener("wheel", pauseFollowing, { passive: true });
  feed.addEventListener("touchstart", pauseFollowing, { passive: true });
  feed.addEventListener("pointerdown", pauseFollowing, { passive: true });

  const observer = new MutationObserver(() => {
    scrollToLatest({ behavior: "auto" });
  });
  observer.observe(feed, {
    childList: true,
    subtree: true,
    characterData: true,
  });

  window.VulnHunterConversationScroll = {
    isFollowingLatest: () => followingLatest,
    resume: (behavior = "smooth") => {
      followingLatest = true;
      publishState();
      scrollToLatest({ behavior, force: true });
    },
    scrollToLatest,
  };

  publishState();
  scrollToLatest({ behavior: "auto", force: true });
})();
