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

async function openAdvancedSettings(page) {
  const disclosure = page.locator("[data-composer-advanced]");
  await disclosure.waitFor({ state: "visible" });
  if (!(await disclosure.evaluate((element) => element.open))) {
    await disclosure.locator("summary").click();
  }
  await page.locator("[data-reasoning-effort]").waitFor({ state: "visible" });
  const providerRuntime = page.locator("[data-provider-runtime]");
  await providerRuntime.waitFor({ state: "attached" });
  if (await providerRuntime.isVisible()) {
    throw new Error("Provider runtime infrastructure became visible in Advanced settings");
  }
}

async function verifyContextualSearchAccess(page) {
  const menu = page.locator(".vh-task-menu");
  const summary = menu.locator("summary");
  const searchTrigger = page.locator("[data-conversation-search-toggle]");
  await searchTrigger.waitFor({ state: "attached" });
  const placement = await searchTrigger.evaluate((element) => ({
    inOverflow: Boolean(element.closest(".vh-task-menu-popover")),
    headerToolbar: Boolean(element.closest(".vh-chat-runtime")?.matches(".vh-chat-actions")),
  }));
  if (!placement.inOverflow || placement.headerToolbar) {
    throw new Error(`Search is not contextual: ${JSON.stringify(placement)}`);
  }
  if (!(await menu.evaluate((element) => element.open))) await summary.click();
  await searchTrigger.waitFor({ state: "visible" });
  if (await menu.evaluate((element) => element.open)) await summary.click();
}

(async () => {
  const browser = await chromium.launch({ headless: true });
  try {
    for (const viewport of viewports) {
      const context = await browser.newContext({ viewport, colorScheme: "light" });
      const page = await context.newPage();
      await login(page);
      await page.goto(`${baseUrl}/`, { waitUntil: "domcontentloaded" });
      await page.locator("[data-conversation-form]").waitFor({ state: "visible" });
      await openAdvancedSettings(page);
      await page.locator("[data-stop-response]").waitFor({ state: "attached" });
      await page.locator("[data-draft-status]").waitFor({ state: "attached" });
      await verifyContextualSearchAccess(page);

      const draftProbe = `Recovered phone draft ${viewport.width}`;
      let input = page.locator("[data-conversation-input]");
      await input.fill(draftProbe);
      await page.waitForTimeout(500);
      await page.reload({ waitUntil: "domcontentloaded" });
      await page.locator("[data-conversation-form]").waitFor({ state: "visible" });
      await openAdvancedSettings(page);
      await page.locator("[data-stop-response]").waitFor({ state: "attached" });
      await page.locator("[data-draft-status]").waitFor({ state: "attached" });
      await verifyContextualSearchAccess(page);
      input = page.locator("[data-conversation-input]");
      if ((await input.inputValue()) !== draftProbe) {
        throw new Error(`The phone draft was not restored after reload at ${viewport.width}px`);
      }

      const layout = await page.evaluate(async () => {
        const composer = document.querySelector("[data-conversation-form]");
        const reasoning = document.querySelector("[data-reasoning-effort]");
        const provider = document.querySelector("[data-provider-runtime]");
        const providerPreference = document.querySelector("select[data-provider-preference]");
        const stopResponse = document.querySelector("[data-stop-response]");
        const draftStatus = document.querySelector("[data-draft-status]");
        const searchTrigger = document.querySelector("[data-conversation-search-toggle]");
        if (!composer || !reasoning || !provider || !stopResponse || !draftStatus || !searchTrigger) {
          return { missing: true };
        }

        const dock = document.createElement("div");
        dock.className = "vh-background-upload-dock";
        dock.innerHTML = `
          <article class="vh-background-upload is-failed">
            <div><strong>Phone acceptance.apk</strong><small>Upload needs attention</small><progress max="1" value="0"></progress></div>
            <div><button type="button">Retry</button><button type="button">Cancel</button></div>
          </article>`;
        document.body.append(dock);
        await new Promise((resolve) => requestAnimationFrame(() => requestAnimationFrame(resolve)));

        const composerRect = composer.getBoundingClientRect();
        const dockRect = dock.getBoundingClientRect();
        const reasoningRect = reasoning.getBoundingClientRect();
        const providerRect = provider.getBoundingClientRect();
        const stopResponseStyle = getComputedStyle(stopResponse);
        const draftStatusStyle = getComputedStyle(draftStatus);
        const dockStyle = getComputedStyle(dock);
        const options = [...reasoning.options].map((option) => option.textContent.trim());
        const overlapsComposer = !(
          dockRect.bottom <= composerRect.top + 1 ||
          dockRect.top >= composerRect.bottom - 1
        );
        const result = {
          missing: false,
          innerWidth: window.innerWidth,
          innerHeight: window.innerHeight,
          composerRect: {
            top: composerRect.top,
            right: composerRect.right,
            bottom: composerRect.bottom,
            left: composerRect.left,
            width: composerRect.width,
            height: composerRect.height,
          },
          dockRect: {
            top: dockRect.top,
            right: dockRect.right,
            bottom: dockRect.bottom,
            left: dockRect.left,
            width: dockRect.width,
            height: dockRect.height,
          },
          dockComputed: {
            position: dockStyle.position,
            bottom: dockStyle.bottom,
            maxHeight: dockStyle.maxHeight,
            zIndex: dockStyle.zIndex,
          },
          responseStylePresent: Boolean(
            document.querySelector("link[data-response-controls-styles]"),
          ),
          richStylePresent: Boolean(document.querySelector("link[data-rich-content-styles]")),
          draftStylePresent: Boolean(
            document.querySelector("link[data-conversation-draft-styles]"),
          ),
          searchStylePresent: Boolean(
            document.querySelector("link[data-conversation-search-styles]"),
          ),
          searchTriggerInOverflow: Boolean(searchTrigger.closest(".vh-task-menu-popover")),
          stopResponseMinimumHeight: Number.parseFloat(stopResponseStyle.minHeight || "0"),
          draftStatusFontSize: Number.parseFloat(draftStatusStyle.fontSize || "0"),
          composerVisible: composerRect.width > 0 && composerRect.height > 0,
          composerInsideViewport:
            composerRect.left >= -1 &&
            composerRect.right <= window.innerWidth + 1 &&
            composerRect.bottom <= window.innerHeight + 1,
          reasoningVisible: reasoningRect.width >= 80 && reasoningRect.height >= 38,
          reasoningOptions: options,
          providerVisible: providerRect.width > 0 && providerRect.height > 0,
          providerPreferencePresent: Boolean(providerPreference),
          providerText: provider.textContent || "",
          dockVisible: dockRect.width > 0 && dockRect.height > 0,
          dockInsideViewport:
            dockRect.left >= -1 &&
            dockRect.right <= window.innerWidth + 1 &&
            dockRect.top >= -1 &&
            dockRect.bottom <= window.innerHeight + 1,
          overlapsComposer,
        };
        dock.remove();
        return result;
      });

      if (layout.missing) throw new Error(`Phone controls are missing at ${viewport.width}px`);
      if (layout.innerWidth !== viewport.width) {
        throw new Error(`Viewport mismatch: expected ${viewport.width}, received ${layout.innerWidth}`);
      }
      if (!layout.composerVisible || !layout.composerInsideViewport) {
        throw new Error(`Composer is clipped at ${viewport.width}px: ${JSON.stringify(layout)}`);
      }
      if (!layout.reasoningVisible) {
        throw new Error(
          `High-reasoning selector is not usable at ${viewport.width}px: ${JSON.stringify(layout)}`,
        );
      }
      if (layout.reasoningOptions.join(",") !== "High") {
        throw new Error(`High-only reasoning mode is not enforced: ${layout.reasoningOptions.join(",")}`);
      }
      if (layout.providerVisible || !/Automatic routing/i.test(layout.providerText)) {
        throw new Error(`Provider runtime infrastructure is not private at ${viewport.width}px`);
      }
      if (layout.providerPreferencePresent) {
        throw new Error("A manual provider selector is visible even though routing must be automatic");
      }
      if (
        !layout.responseStylePresent ||
        !layout.richStylePresent ||
        !layout.draftStylePresent ||
        !layout.searchStylePresent ||
        !layout.searchTriggerInOverflow ||
        layout.stopResponseMinimumHeight < 32 ||
        layout.draftStatusFontSize <= 0
      ) {
        throw new Error(`Conversation controls are not styled safely: ${JSON.stringify(layout)}`);
      }
      if (!layout.dockVisible || !layout.dockInsideViewport || layout.overlapsComposer) {
        throw new Error(`Upload dock overlaps or leaves the viewport: ${JSON.stringify(layout)}`);
      }

      const messageUrl = await page.locator("[data-conversation-form]").getAttribute("action");
      if (!messageUrl) throw new Error("Conversation message URL is missing");
      const absoluteMessageUrl = new URL(messageUrl, baseUrl).toString();
      let providerPostData = "";
      let messageAttempts = 0;
      await page.route(absoluteMessageUrl, async (route) => {
        messageAttempts += 1;
        if (messageAttempts === 1) {
          try {
            await page.waitForTimeout(5000);
            await route.fulfill({
              status: 200,
              contentType: "application/json",
              body: JSON.stringify({}),
            });
          } catch (_error) {
            // The Stop waiting control intentionally aborts this paused request.
          }
          return;
        }
        providerPostData = route.request().postData() || "";
        await page.waitForTimeout(700);
        await route.fulfill({
          status: 200,
          contentType: "application/json",
          body: JSON.stringify({
            message: {
              role: "assistant",
              kind: "text",
              content: [
                "## Automatic reasoning test complete.",
                "",
                "- **Mode:** Automatic",
                "- Status: `validated`",
                "",
                "```bash",
                "python manage.py vh_verify_llm --mode auto",
                "```",
              ].join("\n"),
              timestamp: new Date().toISOString(),
              metadata: {
                provider: "huggingface",
                model: "test/huggingface-model",
                reasoning_effort: "high",
                provider_detail: "internal provider detail must stay hidden",
              },
            },
          }),
        });
      });

      const prompt = "Explain the current automatic reasoning mode";
      await input.fill(prompt);
      await page.locator("[data-conversation-send]").click();
      const progress = page.locator("[data-progress-mode='validated-stages']");
      const stopResponse = page.locator("[data-stop-response]");
      await progress.waitFor({ state: "visible" });
      await stopResponse.waitFor({ state: "visible" });
      await page.waitForTimeout(1100);
      const progressText = await progress.textContent();
      if (!/Reasoning over the request|Validating the response/i.test(progressText || "")) {
        throw new Error(`Automatic reasoning progress did not advance: ${progressText}`);
      }
      if (/Groq|Gemini|Hugging Face|Ollama/i.test(progressText || "")) {
        throw new Error(`Provider leaked through progress UI: ${progressText}`);
      }
      await stopResponse.click();
      await page
        .getByText("Stopped waiting for this response. You can retry the last prompt.")
        .waitFor({ state: "visible" });
      await progress.waitFor({ state: "hidden" });
      for (let attempt = 0; attempt < 40 && (await input.inputValue()) !== prompt; attempt += 1) {
        await page.waitForTimeout(50);
      }
      if ((await input.inputValue()) !== prompt) {
        throw new Error("The stopped prompt was not restored to the phone composer");
      }
      if (messageAttempts !== 1) {
        throw new Error(`Expected one stopped request, observed ${messageAttempts}`);
      }

      const localNotice = page.locator(".vh-chat-message.is-local-notice").last();
      const retryStopped = localNotice.getByRole("button", { name: /retry the prompt/i });
      await retryStopped.waitFor({ state: "visible" });
      await retryStopped.click();
      await progress.waitFor({ state: "visible" });
      await page.getByText("Automatic reasoning test complete.").waitFor({ state: "visible" });
      await progress.waitFor({ state: "hidden" });
      if (messageAttempts !== 2) {
        throw new Error(`Expected the stopped prompt to retry once, observed ${messageAttempts} requests`);
      }
      if (!providerPostData.includes('name="provider_preference"')) {
        throw new Error("The automatic provider preference field was missing from the retried chat request");
      }
      if (!providerPostData.includes("auto")) {
        throw new Error("The retried chat request did not force automatic provider routing");
      }
      if (/huggingface|groq/i.test(providerPostData)) {
        throw new Error("A specific provider leaked into the automatic routing request");
      }
      const draftState = await page.evaluate(() => {
        const api = window.VulnHunterConversationDraft;
        const key = api?.storageKey || "";
        return { key, value: key ? window.sessionStorage.getItem(key) : "missing-api" };
      });
      if (!draftState.key || draftState.value !== null) {
        throw new Error(
          `The successful response did not clear its session draft: ${JSON.stringify(draftState)}`,
        );
      }
      const runtime = page.locator("[data-provider-runtime]");
      if (await runtime.isVisible()) {
        throw new Error("Provider runtime infrastructure became visible after a completed response");
      }
      const runtimeText = await runtime.textContent();
      if (!/Automatic routing/i.test(runtimeText || "")) {
        throw new Error(`Automatic routing marker changed unexpectedly: ${runtimeText}`);
      }
      if (/Groq|Gemini|Hugging Face|Ollama/i.test(runtimeText || "")) {
        throw new Error(`Provider leaked through hidden runtime state: ${runtimeText}`);
      }

      const finalAnswer = page
        .locator(".vh-chat-message.is-assistant")
        .filter({ hasText: "Automatic reasoning test complete." })
        .last();
      await finalAnswer.locator(".vh-rich-heading").waitFor({ state: "visible" });
      await finalAnswer.locator(".vh-rich-list li").first().waitFor({ state: "visible" });
      const finalAnswerText = await finalAnswer.textContent();
      if (/Hugging Face|test\/huggingface-model|internal provider detail/i.test(finalAnswerText || "")) {
        throw new Error(`Provider metadata leaked into the rendered answer: ${finalAnswerText}`);
      }
      const codeBlock = finalAnswer.locator(".vh-rich-code");
      await codeBlock.waitFor({ state: "visible" });
      const renderedCode = await codeBlock.locator("pre code").textContent();
      if (renderedCode !== "python manage.py vh_verify_llm --mode auto") {
        throw new Error(`The fenced command was not preserved safely: ${renderedCode}`);
      }
      await codeBlock
        .getByRole("button", { name: /copy bash block/i })
        .waitFor({ state: "visible" });
      const rawAnswer = await finalAnswer.locator(".vh-message-copy").getAttribute("data-raw-message");
      if (!rawAnswer?.includes("```bash") || !rawAnswer.includes("**Mode:**")) {
        throw new Error("The original assistant answer was not preserved for whole-message copying");
      }

      await input.focus();
      await page.keyboard.press("Control+f");
      const searchPanel = page.locator("[data-conversation-search-panel]");
      await searchPanel.waitFor({ state: "visible" });
      const searchInput = searchPanel.locator("[data-conversation-search-input]");
      await searchInput.fill("vh_verify_llm");
      const searchPosition = searchPanel.locator("[data-conversation-search-position]");
      for (let attempt = 0; attempt < 40; attempt += 1) {
        if ((await searchPosition.textContent()) === "1 of 1") break;
        await page.waitForTimeout(50);
      }
      const searchCount = await searchPosition.textContent();
      if (searchCount !== "1 of 1") {
        throw new Error(`Conversation search did not find the fenced command: ${searchCount}`);
      }
      const activeMatch = finalAnswer.locator("mark[data-vh-search-match].is-vh-search-active");
      await activeMatch.waitFor({ state: "visible" });
      const searchGeometry = await searchPanel.evaluate((element) => {
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
        };
      });
      if (
        searchGeometry.width <= 0 ||
        searchGeometry.height <= 0 ||
        searchGeometry.left < -1 ||
        searchGeometry.right > searchGeometry.innerWidth + 1 ||
        searchGeometry.top < -1 ||
        searchGeometry.bottom > searchGeometry.innerHeight + 1
      ) {
        throw new Error(
          `Conversation search is outside the phone viewport: ${JSON.stringify(searchGeometry)}`,
        );
      }
      await page.keyboard.press("Escape");
      await searchPanel.waitFor({ state: "hidden" });
      if ((await finalAnswer.locator("mark[data-vh-search-match]").count()) !== 0) {
        throw new Error("Closing conversation search left matching markup behind");
      }

      await finalAnswer.getByRole("button", { name: "Copy this answer" }).waitFor({ state: "visible" });
      await finalAnswer
        .getByRole("button", { name: /retry the prompt that produced this answer/i })
        .waitFor({ state: "visible" });
      const latestUser = page.locator(".vh-chat-message.is-user").last();
      const edit = latestUser.getByRole("button", { name: /edit this prompt/i });
      await edit.waitFor({ state: "visible" });
      await edit.click();
      if ((await input.inputValue()) !== prompt) {
        throw new Error("Edit did not restore the user prompt to the composer");
      }
      await input.fill("");
      await page.waitForTimeout(400);
      await page.unroute(absoluteMessageUrl);

      const startUrl = await page
        .locator("[data-conversation-form]")
        .getAttribute("data-upload-start-url");
      if (!startUrl) throw new Error("Upload start URL is missing");
      const absoluteStartUrl = new URL(startUrl, baseUrl).toString();
      let startAttempts = 0;
      await page.route(absoluteStartUrl, async (route) => {
        startAttempts += 1;
        if (startAttempts === 1) {
          await route.fulfill({
            status: 403,
            contentType: "application/json",
            body: JSON.stringify({ detail: "Synthetic stale CSRF response" }),
          });
          return;
        }
        await route.fulfill({
          status: 201,
          contentType: "application/json",
          body: JSON.stringify({
            upload_id: "phone-acceptance-upload",
            chunk_size: 4,
            offset: 0,
            status_url: "/__phone-upload-status__",
            chunk_url: "/__phone-upload-chunk__",
            complete_url: "/__phone-upload-complete__",
            cancel_url: "/__phone-upload-cancel__",
          }),
        });
      });
      await page.route("**/__phone-upload-chunk__", (route) =>
        route.fulfill({
          status: 503,
          contentType: "application/json",
          body: JSON.stringify({ detail: "Synthetic paused upload" }),
        }),
      );
      await page.route("**/__phone-upload-status__", (route) =>
        route.fulfill({
          status: 200,
          contentType: "application/json",
          body: JSON.stringify({ state: "uploading", offset: 0 }),
        }),
      );
      await page.route("**/__phone-upload-cancel__", (route) =>
        route.fulfill({
          status: 200,
          contentType: "application/json",
          body: JSON.stringify({ state: "cancelled" }),
        }),
      );

      await page.locator("[data-conversation-form]").evaluate((form) => {
        form.dataset.mobileUploadMode = "background";
      });
      await page.locator("[data-conversation-file]").setInputFiles({
        name: "phone-acceptance.apk",
        mimeType: "application/vnd.android.package-archive",
        buffer: Buffer.from("PK\u0003\u0004phone-acceptance"),
      });
      for (let attempt = 0; attempt < 100 && startAttempts < 2; attempt += 1) {
        await page.waitForTimeout(50);
      }
      if (startAttempts !== 2) {
        throw new Error(`Expected one automatic CSRF retry, observed ${startAttempts} start attempts`);
      }
      const dockText = await page.locator("[data-background-upload-dock]").textContent();
      if (/session protection/i.test(dockText || "")) {
        throw new Error("The stale CSRF response remained visible after automatic recovery");
      }
      await page.getByRole("button", { name: "Cancel" }).last().click();
      await context.close();
    }
    console.log(
      "Phone contextual search, automatic hidden reasoning, drafts, stop/retry, rich answers, upload recovery and layout acceptance passed.",
    );
  } finally {
    await browser.close();
  }
})().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});