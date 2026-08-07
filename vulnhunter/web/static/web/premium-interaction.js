(() => {
  const root = document.documentElement;
  const query = window.matchMedia("(prefers-reduced-motion: reduce)");

  const applyMotionPreference = () => {
    const motion = query.matches ? "reduced" : "full";
    if (root.dataset.motion === motion) return;
    root.dataset.motion = motion;
    window.dispatchEvent(
      new CustomEvent("vh:motion-preference-change", {
        detail: Object.freeze({ motion }),
      }),
    );
  };

  applyMotionPreference();
  query.addEventListener("change", applyMotionPreference);
})();
