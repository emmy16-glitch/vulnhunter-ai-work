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
})();
