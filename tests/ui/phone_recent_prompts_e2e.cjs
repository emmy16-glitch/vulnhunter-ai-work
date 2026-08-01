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

      const form = page.locator("[data-conversation-form]");
      const input = page.locator("[data-conversation-input]");
      const trigger = page.locator("[data-composer-tools-trigger]");
      const clear = page.locator("[data-composer-clear]");
      const menu = page.locator("[data-composer-prompt-menu]");
      const recentSection = page.locator("[data-recent-prompts]");
      await form.waitFor({ state: "visible" });
      await trigger.waitFor({ state: "visible" });
      await recentSection.waitFor({ state: "attached" });
      for (let attempt = 0; attempt < 100 && !(await trigger.isEnabled()); attempt += 1) {
        await page.waitForTimeout(50);
      }
      if (!(await trigger.isEnabled())) {
        throw new Error("Prompt tools did not become available after their stylesheet loaded");
      }

      const prompts = [
        "Oldest prompt that should be dropped",
        "Review the authorised source repository for authentication issues",
        "Explain the confirmed findings in plain language",
        "Summarise the current remediation status",
        "Prepare the attached APK for static analysis",
        "Most recent reusable prompt for this phone test",
        "Most recent reusable prompt for this phone test",
      ];
      await page.evaluate((values) => {
        const feed = document.querySelector("[data-conversation-feed]");
        const template = document.getElementById("vh-message-template");
        if (!feed || !template) throw new Error("Conversation fixtures are unavailable");
        values.forEach((value, index) => {
          const fragment = template.content.cloneNode(true);
          const article = fragment.querySelector(".vh-chat-message");
          const avatar = fragment.querySelector(".vh-message-avatar");
          const copy = fragment.querySelector(".vh-message-copy");
          const actions = fragment.querySelector(".vh-message-actions");
          article.classList.add("is-user");
          article.dataset.syntheticRecentPrompt = String(index);
          avatar.textContent = "YO";
          copy.textContent = value;
          actions?.remove();
          feed.append(fragment);
        });
      }, prompts);

      for (let attempt = 0; attempt < 40; attempt += 1) {
        if ((await recentSection.locator(".vh-composer-recent-option").count()) === 5) break;
        await page.waitForTimeout(50);
      }
      const recentOptions = recentSection.locator(".vh-composer-recent-option");
      if ((await recentOptions.count()) !== 5) {
        throw new Error(`Expected five deduplicated recent prompts, found ${await recentOptions.count()}`);
      }
      if (!(await recentSection.isHidden()) || !(await menu.isHidden())) {
        throw new Error("Recent prompts should remain hidden until the prompt menu is opened");
      }
      const recentCopies = await recentOptions.allTextContents();
      if (!recentCopies[0].includes("Most recent reusable prompt for this phone test")) {
        throw new Error(`The latest recent prompt was not first: ${recentCopies[0]}`);
      }
      if (recentCopies.some((copy) => copy.includes("Oldest prompt that should be dropped"))) {
        throw new Error("The recent prompt list exceeded its five-item limit");
      }
      if (
        recentCopies.filter((copy) => copy.includes("Most recent reusable prompt for this phone test"))
          .length !== 1
      ) {
        throw new Error("Duplicate recent prompts were not collapsed");
      }

      const userMessageCount = await page.locator(".vh-chat-message.is-user").count();
      const runCardCount = await page.locator("[data-run-card]").count();
      let postCount = 0;
      page.on("request", (request) => {
        if (request.method() === "POST") postCount += 1;
      });

      await trigger.click();
      await menu.waitFor({ state: "visible" });
      await recentSection.waitFor({ state: "visible" });
      const geometry = await menu.evaluate((element) => {
        const menuRect = element.getBoundingClientRect();
        const list = element.querySelector(".vh-composer-prompt-list");
        const first = element.querySelector(".vh-composer-recent-option");
        const listRect = list?.getBoundingClientRect();
        const firstRect = first?.getBoundingClientRect();
        const composerStyles = document.querySelector("link[data-composer-tools-styles]");
        const recentStyles = document.querySelector("link[data-recent-prompts-styles]");
        const listStyle = list ? getComputedStyle(list) : null;
        return {
          menu: {
            left: menuRect.left,
            right: menuRect.right,
            top: menuRect.top,
            bottom: menuRect.bottom,
            width: menuRect.width,
            height: menuRect.height,
          },
          list: listRect
            ? {
                left: listRect.left,
                right: listRect.right,
                top: listRect.top,
                bottom: listRect.bottom,
                clientHeight: list.clientHeight,
                scrollHeight: list.scrollHeight,
                overflowY: listStyle?.overflowY,
              }
            : null,
          first: firstRect
            ? {
                left: firstRect.left,
                right: firstRect.right,
                top: firstRect.top,
                bottom: firstRect.bottom,
              }
            : null,
          innerWidth: window.innerWidth,
          innerHeight: window.innerHeight,
          composerStylesLoaded: Boolean(composerStyles?.sheet),
          recentStylesLoaded: Boolean(recentStyles?.sheet),
          stylesReady: window.VulnHunterComposerTools?.stylesReady?.(),
        };
      });
      const menuInsideViewport =
        geometry.menu.width > 0 &&
        geometry.menu.height > 0 &&
        geometry.menu.left >= -1 &&
        geometry.menu.right <= geometry.innerWidth + 1 &&
        geometry.menu.top >= -1 &&
        geometry.menu.bottom <= geometry.innerHeight + 1;
      const listInsideMenu =
        geometry.list &&
        geometry.list.left >= geometry.menu.left - 1 &&
        geometry.list.right <= geometry.menu.right + 1 &&
        geometry.list.top >= geometry.menu.top - 1 &&
        geometry.list.bottom <= geometry.menu.bottom + 1;
      const firstOptionVisible =
        geometry.first &&
        geometry.list &&
        geometry.first.top >= geometry.list.top - 1 &&
        geometry.first.bottom <= geometry.list.bottom + 1;
      const listScrollable =
        geometry.list &&
        ["auto", "scroll"].includes(geometry.list.overflowY) &&
        geometry.list.scrollHeight >= geometry.list.clientHeight;
      if (
        !geometry.composerStylesLoaded ||
        !geometry.recentStylesLoaded ||
        geometry.stylesReady !== true ||
        !menuInsideViewport ||
        !listInsideMenu ||
        !firstOptionVisible ||
        !listScrollable
      ) {
        throw new Error(`Recent prompt menu is unusable on phone: ${JSON.stringify(geometry)}`);
      }

      await recentOptions.last().evaluate((element) =>
        element.scrollIntoView({ block: "nearest", behavior: "auto" }),
      );
      const lastVisible = await recentOptions.last().evaluate((element) => {
        const list = element.closest(".vh-composer-prompt-list");
        if (!list) return false;
        const itemRect = element.getBoundingClientRect();
        const listRect = list.getBoundingClientRect();
        return itemRect.top >= listRect.top - 1 && itemRect.bottom <= listRect.bottom + 1;
      });
      if (!lastVisible) {
        throw new Error("The oldest retained recent prompt could not be reached by scrolling");
      }
      await recentOptions.first().evaluate((element) =>
        element.scrollIntoView({ block: "nearest", behavior: "auto" }),
      );
      await recentOptions.first().click();
      await menu.waitFor({ state: "hidden" });
      if ((await input.inputValue()) !== "Most recent reusable prompt for this phone test") {
        throw new Error(`Recent prompt was not restored exactly: ${await input.inputValue()}`);
      }
      if (
        postCount !== 0 ||
        (await page.locator(".vh-chat-message.is-user").count()) !== userMessageCount ||
        (await page.locator("[data-run-card]").count()) !== runCardCount
      ) {
        throw new Error("Reusing a recent prompt submitted or started work automatically");
      }
      await clear.click();
      await clear.waitFor({ state: "hidden" });

      await input.fill("/recent");
      await menu.waitFor({ state: "visible" });
      const slashOptions = menu.locator("[data-prompt-value]:visible");
      if ((await slashOptions.count()) !== 5) {
        throw new Error(`The /recent filter exposed ${await slashOptions.count()} options instead of five`);
      }
      await page.keyboard.press("Enter");
      await menu.waitFor({ state: "hidden" });
      if ((await input.inputValue()) !== "Most recent reusable prompt for this phone test") {
        throw new Error(`/recent did not insert the newest prompt: ${await input.inputValue()}`);
      }
      if (
        postCount !== 0 ||
        (await page.locator(".vh-chat-message.is-user").count()) !== userMessageCount
      ) {
        throw new Error("Selecting /recent submitted the prompt instead of inserting it");
      }
      await clear.click();
      await context.close();
    }
    console.log("Phone recent-prompt reuse, deduplication and /recent acceptance passed.");
  } finally {
    await browser.close();
  }
})().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
