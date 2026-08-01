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
      await page.locator("[data-conversation-form]").waitFor({ state: "visible" });
      await page.locator("select[data-provider-preference]").waitFor({ state: "visible" });
      await page.locator("[data-stop-response]").waitFor({ state: "attached" });
      await page.locator("[data-draft-status]").waitFor({ state: "attached" });

      const draftProbe = `Recovered phone draft ${viewport.width}`;
      let input = page.locator("[data-conversation-input]");
      await input.fill(draftProbe);
      await page.waitForTimeout(500);
      await page.reload({ waitUntil: "domcontentloaded" });
      await page.locator("[data-conversation-form]").waitFor({ state: "visible" });
      await page.locator("select[data-provider-preference]").waitFor({ state: "visible" });
      await page.locator("[data-stop-response]").waitFor({ state: "attached" });
      await page.locator("[data-draft-status]").waitFor({ state: "attached" });
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
        if (!composer || !reasoning || !provider || !providerPreference || !stopResponse || !draftStatus) {
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
        const providerPreferenceRect = providerPreference.getBoundingClientRect();
        const stopResponseStyle = getComputedStyle(stopResponse);
        const draftStatusStyle = getComputedStyle(draftStatus);
        const dockStyle = getComputedStyle(dock);
        const options = [...reasoning.options].map((option) => option.textContent.trim());
        const providerOptions = [...providerPreference.options].map((option) =>
          option.textContent.trim(),
        );
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
          providerPreferenceVisible:
            providerPreferenceRect.width >= 110 && providerPreferenceRect.height >= 32,
          providerOptions,
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
          `Reasoning selector is not usable at ${viewport.width}px: ${JSON.stringify(layout)}`,
        );
      }
      if (layout.reasoningOptions.join(",") !== "Low,Medium,High") {
        throw new Error(`Reasoning options are incomplete: ${layout.reasoningOptions.join(",")}`);
      }
      if (!layout.providerVisible) {
        throw new Error(`AI runtime status is hidden at ${viewport.width}px`);
      }
      if (!layout.providerPreferenceVisible) {
        throw new Error(
          `Provider selector is not usable at ${viewport.width}px: ${JSON.stringify(layout)}`,
        );
      }
      if (layout.providerOptions.join(",") !== "Auto,Groq,Hugging Face") {
        throw new Error(`Provider options are incomplete: ${layout.providerOptions.join(",")}`);
      }
      if (
        !layout.responseStylePresent ||
        !layout.richStylePresent ||
        !layout.draftStylePresent ||
        layout.stopResponseMinimumHeight < 32 ||
        layout.draftStatusFontSize <= 0
      ) {
        throw new Error(`Conversation controls are not styled safely: ${JSON.stringify(layout)}`);
      }
      if (!layout.dockVisible || !layout.dockInsideViewport || layout.overlapsComposer) {
        throw new Error(`Upload dock overlaps or leaves the viewport: ${JSON.stringify(layout)}`);
      }

      const providerSelect = page.locator("select[data-provider-preference]");
      await providerSelect.selectOption("huggingface");
      for (let attempt = 0; attempt < 80; attempt += 1) {
        if ((await providerSelect.inputValue()) === "huggingface" && (await providerSelect.isEnabled())) {
          break;
        }
        await page.waitForTimeout(50);
      }
      if ((await providerSelect.inputValue()) !== "huggingface") {
        throw new Error("The Hugging Face preference did not persist in the active workspace");
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
                "## Provider selection test complete.",
                "",
                "- **Provider:** Hugging Face",
                "- Model: `test/huggingface-model`",
                "",
                "```bash",
                "python manage.py vh_verify_llm --provider huggingface",
                "```",
              ].join("\n"),
              timestamp: new Date().toISOString(),
              metadata: {
                provider: "huggingface",
                model: "test/huggingface-model",
                reasoning_effort: "medium",
                provider_detail: "Hugging Face model: test/huggingface-model",
              },
            },
          }),
        });
      });

      const prompt = "Explain the current workspace provider selection";
      await input.fill(prompt);
      await page.locator("[data-conversation-send]").click();
      const progress = page.locator("[data-progress-mode='validated-stages']");
      const stopResponse = page.locator("[data-stop-response]");
      await progress.waitFor({ state: "visible" });
      await stopResponse.waitFor({ state: "visible" });
      await page.waitForTimeout(1100);
      const progressText = await progress.textContent();
      if (!/Contacting Hugging Face|validated model response/i.test(progressText || "")) {
        throw new Error(`Provider progress did not advance: ${progressText}`);
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
      await page.getByText("Provider selection test complete.").waitFor({ state: "visible" });
      await progress.waitFor({ state: "hidden" });
      if (messageAttempts !== 2) {
        throw new Error(`Expected the stopped prompt to retry once, observed ${messageAttempts} requests`);
      }
      if (!providerPostData.includes('name="provider_preference"')) {
        throw new Error("The provider preference field was missing from the retried chat request");
      }
      if (!providerPostData.includes("huggingface")) {
        throw new Error("The selected Hugging Face provider was not submitted with the retried request");
      }
      const draftState = await page.evaluate(() => {
        const api = window.VulnHunterConversationDraft;
        const key = api?.storageKey || "";
        return { key, value: key ? window.sessionStorage.getItem(key) : "missing-api" };
      });
      if (!draftState.key || draftState.value !== null) {
        throw new Error(`The successful response did not clear its session draft: ${JSON.stringify(draftState)}`);
      }
      const runtimeText = await page.locator("[data-provider-runtime]").textContent();
      if (!/Hugging Face answered/i.test(runtimeText || "")) {
        throw new Error(`The actual response provider was not shown: ${runtimeText}`);
      }

      const finalAnswer = page
        .locator(".vh-chat-message.is-assistant")
        .filter({ hasText: "Provider selection test complete." })
        .last();
      await finalAnswer.locator(".vh-rich-heading").waitFor({ state: "visible" });
      await finalAnswer.locator(".vh-rich-list li").first().waitFor({ state: "visible" });
      const codeBlock = finalAnswer.locator(".vh-rich-code");
      await codeBlock.waitFor({ state: "visible" });
      const renderedCode = await codeBlock.locator("pre code").textContent();
      if (renderedCode !== "python manage.py vh_verify_llm --provider huggingface") {
        throw new Error(`The fenced command was not preserved safely: ${renderedCode}`);
      }
      await codeBlock
        .getByRole("button", { name: /copy bash block/i })
        .waitFor({ state: "visible" });
      const rawAnswer = await finalAnswer.locator(".vh-message-copy").getAttribute("data-raw-message");
      if (!rawAnswer?.includes("```bash") || !rawAnswer.includes("**Provider:**")) {
        throw new Error("The original assistant answer was not preserved for whole-message copying");
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
      "Phone provider selection, session drafts, stop waiting, retry, safe rich answers, copy/edit controls, upload recovery and layout acceptance passed.",
    );
  } finally {
    await browser.close();
  }
})().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});