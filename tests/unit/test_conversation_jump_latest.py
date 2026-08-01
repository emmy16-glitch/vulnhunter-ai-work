from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "vulnhunter/web/static/web/conversation-autoscroll.js"
STYLES = ROOT / "vulnhunter/web/static/web/conversation-jump-latest.css"


def test_jump_latest_extends_existing_follow_state() -> None:
    script = SCRIPT.read_text(encoding="utf-8")

    assert "followingLatest" in script
    assert "distanceFromBottom()" in script
    assert 'feed.dataset.followLatest = followingLatest ? "true" : "false"' in script
    assert 'jump.dataset.jumpLatest = "true"' in script
    assert 'jump.addEventListener("click", () => resume("smooth"))' in script
    assert "window.VulnHunterConversationScroll" in script


def test_jump_latest_counts_message_elements_not_rich_dom_mutations() -> None:
    script = SCRIPT.read_text(encoding="utf-8")

    assert 'feed.querySelectorAll(".vh-chat-message").length' in script
    assert "nextMessageCount - knownMessageCount" in script
    assert "unreadMessages += addedMessages" in script
    assert 'childList: true' in script
    assert 'subtree: true' in script
    assert "unreadCount: () => unreadMessages" in script


def test_jump_latest_does_not_force_scroll_while_user_is_reading() -> None:
    script = SCRIPT.read_text(encoding="utf-8")

    assert "if (!force && !followingLatest) return false" in script
    assert "if (followingLatest) unreadMessages = 0" in script
    expected_copy = (
        'jump.textContent = unreadMessages > 0 ? `↓ ${unreadMessages} new` : "↓ Latest"'
    )
    assert expected_copy in script


def test_jump_latest_waits_for_a_stable_physical_bottom() -> None:
    script = SCRIPT.read_text(encoding="utf-8")

    assert "const maximumSettleFrames = 90" in script
    assert "const requiredStableFrames = 8" in script
    assert "const smoothScrollGraceFrames = 12" in script
    assert "settleProgrammaticScroll = (frame = 0, stableFrames = 0)" in script
    assert "feed.scrollTop = feed.scrollHeight" in script
    assert "nextStableFrames >= requiredStableFrames" in script
    assert "const finalArrival = distanceFromBottom() <= bottomThreshold" in script
    assert 'scrollToLatest({ behavior: "auto", force: true })' in script
    resume = script[script.index("const resume"): script.index("jump.addEventListener")]
    assert "followingLatest = true" not in resume
    assert 'scrollToLatest({ behavior, force: true })' in resume


def test_jump_latest_uses_self_hosted_composer_anchored_styles() -> None:
    script = SCRIPT.read_text(encoding="utf-8")
    styles = STYLES.read_text(encoding="utf-8")

    assert 'document.createElement("style")' not in script
    assert 'document.createElement("link")' in script
    assert "conversation-jump-latest.css" in script
    assert "composer.append(jump)" in script
    assert ".vh-jump-latest" in styles
    assert "top: -2.75rem" in styles
    assert "@media (max-width: 640px)" in styles
