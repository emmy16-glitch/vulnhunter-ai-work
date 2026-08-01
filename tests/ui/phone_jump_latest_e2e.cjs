const fs = require("fs");
const { chromium } = require("playwright");

const baseUrl = process.env.VULNHUNTER_UI_BASE_URL || "http://127.0.0.1:8767";
const manifestPath = process.env.VULNHUNTER_UI_MANIFEST;
if (!manifestPath) throw new Error("VULNHUNTER_UI_MANIFEST is required");
const manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8"));
const persona = manifest.personas.admin;
const viewports = [
  { width: 390, height: 844 },
  { width: 360, height: 800 },
];

async function login(page) {
  await page.goto(`${baseUrl}/login/`, { waitUntil: "domcontentloaded" });
  await page.getByLabel("Username").fill(persona.username);
  await page.getByLabel("Password").fill(persona.password);
  await Promise.all([
    page.waitForURL((url) => new URL(url).pathname !== "/login/"),
    page.getByRole("button", { name: /sign in securely/i }).click(),
  ]);
}

(async () => {
  const browser = await chromium.launch({ headless: true });
  try {
    for (const viewport of viewports) {
      const context = await browser.newContext({ viewport, colorScheme: "dark" });
      const page = await context.newPage();
      await login(page);
      await page.goto(`${baseUrl}/`, { waitUntil: "domcontentloaded" });

      const feed = page.locator("[data-conversation-feed]");
      const jump = page.locator("[data-jump-latest]");
      await feed.waitFor({ state: "visible" });
      await jump.waitFor({ state: "attached" });
      if (!(await jump.isHidden())) {
        throw new Error("Jump to latest should be hidden while following the newest message");
      }

      await page.evaluate(() => {
        const feedElement = document.querySelector("[data-conversation-feed]");
        const template = document.getElementById("vh-message-template");
        if (!feedElement || !template) throw new Error("Conversation fixtures are unavailable");
        for (let index = 0; index < 24; index += 1) {
          const fragment = template.content.cloneNode(true);
          const article = fragment.querySelector(".vh-chat-message");
          const avatar = fragment.querySelector(".vh-message-avatar");
          const copy = fragment.querySelector(".vh-message-copy");
          const actions = fragment.querySelector(".vh-message-actions");
          article.classList.add(index % 2 === 0 ? "is-user" : "is-assistant");
          article.dataset.syntheticScrollMessage = String(index);
          avatar.textContent = index % 2 === 0 ? "YO" : "VH";
          copy.textContent = `Synthetic conversation message ${index + 1}. `.repeat(8);
          actions?.remove();
          feedElement.append(fragment);
        }
        feedElement.scrollTo({ top: feedElement.scrollHeight, behavior: "auto" });
      });
      await page.waitForTimeout(100);

      await feed.dispatchEvent("pointerdown", {
        pointerType: "touch",
        isPrimary: true,
        bubbles: true,
      });
      await page.evaluate(() => {
        const feedElement = document.querySelector("[data-conversation-feed]");
        feedElement.scrollTo({ top: 0, behavior: "auto" });
        feedElement.dispatchEvent(new Event("scroll"));
      });
      await jump.waitFor({ state: "visible" });
      const initialLabel = (await jump.textContent())?.trim();
      if (initialLabel !== "↓ Latest") {
        throw new Error(`Unexpected paused-following label: ${initialLabel}`);
      }

      const geometry = await jump.evaluate((element) => {
        const rect = element.getBoundingClientRect();
        return {
          left: rect.left,
          right: rect.right,
          top: rect.top,
          bottom: rect.bottom,
          width: rect.width,
          height: rect.height,
          innerWidth: window.innerWidth,
          innerHeight: window.innerHeight,
          stylesLoaded: Boolean(document.querySelector("link[data-jump-latest-styles]")),
        };
      });
      if (
        !geometry.stylesLoaded ||
        geometry.width <= 0 ||
        geometry.height < 38 ||
        geometry.left < -1 ||
        geometry.right > geometry.innerWidth + 1 ||
        geometry.top < -1 ||
        geometry.bottom > geometry.innerHeight + 1
      ) {
        throw new Error(`Jump to latest leaves the phone viewport: ${JSON.stringify(geometry)}`);
      }

      await page.evaluate(() => {
        const feedElement = document.querySelector("[data-conversation-feed]");
        const template = document.getElementById("vh-message-template");
        const fragment = template.content.cloneNode(true);
        const article = fragment.querySelector(".vh-chat-message");
        const avatar = fragment.querySelector(".vh-message-avatar");
        const copy = fragment.querySelector(".vh-message-copy");
        const actions = fragment.querySelector(".vh-message-actions");
        article.classList.add("is-assistant");
        article.dataset.syntheticUnreadMessage = "true";
        avatar.textContent = "VH";
        copy.textContent = "A newly arrived assistant message while the reader is reviewing earlier content.";
        actions?.remove();
        feedElement.append(fragment);
      });

      for (let attempt = 0; attempt < 40; attempt += 1) {
        if (((await jump.textContent()) || "").trim() === "↓ 1 new") break;
        await page.waitForTimeout(50);
      }
      const unreadLabel = ((await jump.textContent()) || "").trim();
      if (unreadLabel !== "↓ 1 new") {
        throw new Error(`New message count was not shown: ${unreadLabel}`);
      }
      const scrollState = await page.evaluate(() => ({
        following: window.VulnHunterConversationScroll?.isFollowingLatest(),
        unread: window.VulnHunterConversationScroll?.unreadCount(),
      }));
      if (scrollState.following !== false || scrollState.unread !== 1) {
        throw new Error(`Paused conversation state is incorrect: ${JSON.stringify(scrollState)}`);
      }

      await jump.click();
      for (let attempt = 0; attempt < 60 && !(await jump.isHidden()); attempt += 1) {
        await page.waitForTimeout(50);
      }
      if (!(await jump.isHidden())) {
        throw new Error("Jump to latest did not hide after resuming the newest message");
      }
      const resumed = await page.evaluate(() => {
        const feedElement = document.querySelector("[data-conversation-feed]");
        return {
          following: window.VulnHunterConversationScroll?.isFollowingLatest(),
          unread: window.VulnHunterConversationScroll?.unreadCount(),
          distance: Math.max(
            0,
            feedElement.scrollHeight - feedElement.scrollTop - feedElement.clientHeight,
          ),
        };
      });
      if (resumed.following !== true || resumed.unread !== 0 || resumed.distance > 96) {
        throw new Error(`Jump to latest did not resume correctly: ${JSON.stringify(resumed)}`);
      }

      await context.close();
    }
    console.log("Phone jump-to-latest and unread-message acceptance passed.");
  } finally {
    await browser.close();
  }
})().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
