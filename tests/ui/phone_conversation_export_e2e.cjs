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
      const context = await browser.newContext({
        viewport,
        colorScheme: "dark",
        permissions: ["clipboard-read", "clipboard-write"],
      });
      const page = await context.newPage();
      await login(page);
      await page.goto(`${baseUrl}/`, { waitUntil: "domcontentloaded" });

      const feed = page.locator("[data-conversation-feed]");
      const trigger = page.locator("[data-conversation-export-trigger]");
      const panel = page.locator("[data-conversation-export]");
      await feed.waitFor({ state: "visible" });
      await trigger.waitFor({ state: "visible" });

      const userPrompt = "Export this exact authorised phone-test prompt.";
      const assistantRaw = [
        "## Export proof",
        "",
        "- **Provider:** Test provider",
        "- Preserve `inline-code` exactly",
        "",
        "```bash",
        "python manage.py vh_verify_llm --provider auto",
        "```",
      ].join("\n");
      const localNotice = "This local stop notice must never appear in the export.";
      await page.evaluate(
        ({ userPrompt, assistantRaw, localNotice }) => {
          const feedElement = document.querySelector("[data-conversation-feed]");
          const template = document.getElementById("vh-message-template");
          if (!feedElement || !template) throw new Error("Conversation fixtures are unavailable");

          const append = (role, copy, extraClass = "") => {
            const fragment = template.content.cloneNode(true);
            const article = fragment.querySelector(".vh-chat-message");
            const avatar = fragment.querySelector(".vh-message-avatar");
            const messageCopy = fragment.querySelector(".vh-message-copy");
            const actions = fragment.querySelector(".vh-message-actions");
            article.classList.add(role === "user" ? "is-user" : "is-assistant");
            if (extraClass) article.classList.add(extraClass);
            article.dataset.syntheticExportMessage = role;
            avatar.textContent = role === "user" ? "YO" : "VH";
            messageCopy.textContent = copy;
            actions?.remove();
            feedElement.append(fragment);
          };

          append("user", userPrompt);
          append("assistant", assistantRaw);
          append("assistant", localNotice, "is-local-notice");
        },
        { userPrompt, assistantRaw, localNotice },
      );

      const assistant = page
        .locator(".vh-chat-message.is-assistant")
        .filter({ hasText: "Export proof" })
        .last();
      await assistant.locator(".vh-rich-code").waitFor({ state: "visible" });
      const raw = await assistant.locator(".vh-message-copy").getAttribute("data-raw-message");
      if (raw !== assistantRaw) {
        throw new Error(`Rich rendering did not preserve the export source: ${raw}`);
      }

      let postCount = 0;
      page.on("request", (request) => {
        if (request.method() === "POST") postCount += 1;
      });

      await trigger.click();
      await panel.waitFor({ state: "visible" });
      if ((await trigger.getAttribute("aria-expanded")) !== "true") {
        throw new Error("Export trigger did not expose its expanded state");
      }
      const geometry = await panel.evaluate((element) => {
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
          stylesLoaded: Boolean(document.querySelector("link[data-conversation-export-styles]")),
        };
      });
      if (
        !geometry.stylesLoaded ||
        geometry.width <= 0 ||
        geometry.height <= 0 ||
        geometry.left < -1 ||
        geometry.right > geometry.innerWidth + 1 ||
        geometry.top < -1 ||
        geometry.bottom > geometry.innerHeight + 1
      ) {
        throw new Error(`Conversation export leaves the phone viewport: ${JSON.stringify(geometry)}`);
      }

      const markdown = await page.evaluate(() =>
        window.VulnHunterConversationExport?.buildMarkdown(),
      );
      if (!markdown || !markdown.includes(`## You\n\n${userPrompt}`)) {
        throw new Error(`Export omitted the user prompt: ${markdown}`);
      }
      if (!markdown.includes(`## VulnHunter\n\n${assistantRaw}`)) {
        throw new Error(`Export omitted the raw assistant Markdown: ${markdown}`);
      }
      if (markdown.includes(localNotice)) {
        throw new Error("Export included a local stop/error notice");
      }
      if (markdown.includes("Copy code") || markdown.includes("Copy Markdown")) {
        throw new Error("Export included rendered control labels instead of raw message content");
      }

      const copy = panel.locator("[data-conversation-export-copy]");
      await copy.click();
      for (let attempt = 0; attempt < 40; attempt += 1) {
        if (((await copy.textContent()) || "").trim() === "Copied") break;
        await page.waitForTimeout(50);
      }
      if (((await copy.textContent()) || "").trim() !== "Copied") {
        throw new Error("Copy Markdown did not confirm clipboard completion");
      }
      const clipboard = await page.evaluate(() => navigator.clipboard.readText());
      if (clipboard !== markdown) {
        throw new Error("Clipboard Markdown did not match the current-thread export");
      }

      const downloadPromise = page.waitForEvent("download");
      await panel.locator("[data-conversation-export-download]").click();
      const downloaded = await downloadPromise;
      const path = await downloaded.path();
      if (!path) throw new Error("The Markdown download did not produce a local file");
      const downloadedMarkdown = fs.readFileSync(path, "utf8");
      if (downloadedMarkdown !== markdown) {
        throw new Error("Downloaded Markdown did not match the current-thread export");
      }
      if (!downloaded.suggestedFilename().endsWith(".md")) {
        throw new Error(`Unexpected export filename: ${downloaded.suggestedFilename()}`);
      }

      await page.keyboard.press("Escape");
      await panel.waitFor({ state: "hidden" });
      if ((await trigger.getAttribute("aria-expanded")) !== "false") {
        throw new Error("Escape did not close conversation export accessibly");
      }
      if (postCount !== 0) {
        throw new Error(`Conversation export made ${postCount} unexpected POST request(s)`);
      }
      await context.close();
    }
    console.log("Phone conversation copy and Markdown download acceptance passed.");
  } finally {
    await browser.close();
  }
})().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});