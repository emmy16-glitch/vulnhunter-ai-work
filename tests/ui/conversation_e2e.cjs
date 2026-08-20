const { execFile } = require("child_process");
const fs = require("fs");
const path = require("path");
const { promisify } = require("util");
const { chromium } = require("playwright");

const execFileAsync = promisify(execFile);
const baseUrl = process.env.VULNHUNTER_UI_BASE_URL || "http://127.0.0.1:8767";
const username = "conversation-e2e";
const password = "Vh-Conversation-E2E-2026!";
const outputDir = process.env.VULNHUNTER_UI_OUTPUT || "/tmp/vh-ui/screenshots";
const failureScreenshot = path.join(outputDir, "conversation-e2e-failure.png");
const serverLog =
  process.env.VULNHUNTER_UI_SERVER_LOG || path.join(path.dirname(outputDir), "server.log");
const python = process.env.VULNHUNTER_PYTHON || "python3";
const preparationScript = path.join(__dirname, "prepare_conversation_e2e.py");

async function prepareConversationEnvironment() {
  await execFileAsync(python, [preparationScript], {
    env: {
      ...process.env,
      DJANGO_SETTINGS_MODULE: "vulnhunter.web.settings",
      VULNHUNTER_WEB_DEBUG: process.env.VULNHUNTER_WEB_DEBUG || "true",
      VULNHUNTER_WEB_SECRET_KEY: process.env.VULNHUNTER_WEB_SECRET_KEY || "browser-e2e-local",
    },
  });
}

let browser;
let page;

(async () => {
  try {
    await prepareConversationEnvironment();
    browser = await chromium.launch({ headless: true });
    page = await browser.newPage({ viewport: { width: 1280, height: 820 } });
    const consoleErrors = [];
    const activityRequests = [];
    page.on("console", (message) => {
      if (message.type() === "error") consoleErrors.push(message.text());
    });
    page.on("request", (request) => {
      if (request.url().includes("/activity/stream/")) activityRequests.push(request.url());
    });
    await page.goto(`${baseUrl}/login/`, { waitUntil: "networkidle" });
    await page.getByLabel("Username").fill(username);
    await page.getByLabel("Password").fill(password);
    await Promise.all([
      page.waitForURL(`${baseUrl}/`),
      page.getByRole("button", { name: /sign in securely/i }).click(),
    ]);

    await page.locator("[data-conversation-workspace]").waitFor({ timeout: 15000 });
    const previousWorkspaceUrl = page.url();
    const overflow = page.locator(".vh-task-menu > summary");
    await overflow.click();
    const newAssessment = page.locator("[data-thread-create]");
    await newAssessment.waitFor({ state: "visible", timeout: 5000 });
    await newAssessment.click();

    const newAssessmentCard = page.locator(
      '.vh-chat-action-card[data-action-type="new-assessment"]',
    );
    await newAssessmentCard.waitFor({ state: "visible", timeout: 5000 });
    const newAssessmentCopy = (await newAssessmentCard.textContent()) || "";
    if (!/Start a clean assessment thread\?/i.test(newAssessmentCopy)) {
      throw new Error(`New-assessment confirmation was not rendered in chat: ${newAssessmentCopy}`);
    }

    await Promise.all([
      page.waitForURL(
        (url) => url.toString() !== previousWorkspaceUrl && url.searchParams.has("thread"),
        { timeout: 15000 },
      ),
      newAssessmentCard.getByRole("button", { name: /start new assessment/i }).click(),
    ]);
    await page.locator("[data-conversation-workspace]").waitFor({ timeout: 15000 });

    const input = page.locator("[data-conversation-input]");
    const send = page.locator("[data-conversation-send]");
    const assistantMessages = page.locator(".vh-chat-message.is-assistant .vh-message-copy");

    if (await assistantMessages.count()) {
      throw new Error("A fresh conversation must not contain a synthetic assistant message");
    }
    await page.locator("[data-chat-empty-state]").waitFor({ state: "visible", timeout: 5000 });

    async function waitForNewAssistantMessage(previousCount, expected, timeout = 15000) {
      const message = assistantMessages.nth(previousCount);
      await message.waitFor({ timeout });
      const deadline = Date.now() + timeout;
      while (Date.now() < deadline) {
        const copy = (await message.textContent()) || "";
        if (expected.test(copy)) return { message, copy };
        await page.waitForTimeout(50);
      }
      const copy = (await message.textContent()) || "";
      throw new Error(`Assistant message did not finish with expected content: ${copy}`);
    }

    await input.fill("Scan http://10.0.11.34:8010/ using the passive profile");
    await send.click();
    await page.getByText(/Review and confirm the plan below/i).waitFor({ timeout: 15000 });
    await page.locator("[data-inline-approval]").waitFor({ state: "visible", timeout: 15000 });
    const runId = await page.locator("[data-run-card]").last().getAttribute("data-run-id");
    if (!runId) throw new Error("The conversation did not expose an authoritative run id");
    const activityPanel = page.locator("[data-analysis-activity]");
    await activityPanel.waitFor({ state: "visible", timeout: 10000 });
    await activityPanel.locator(".vh-analysis-activity-node > summary").filter({ hasText: "Planning" }).waitFor({ timeout: 10000 });
    if (await activityPanel.locator(".vh-message-copy").count()) {
      throw new Error("Final answer markup must remain outside the operational activity panel");
    }
    const initialActivityCopy = (await activityPanel.textContent()) || "";
    if (/Groq|Gemini|Ollama/i.test(initialActivityCopy)) {
      throw new Error(`Provider details leaked into the activity panel: ${initialActivityCopy}`);
    }

    await input.fill("Confirm");
    await send.click();
    await assistantMessages
      .filter({ hasText: /Approved\. Starting the governed assessment/ })
      .last()
      .waitFor({ timeout: 15000 });
    const workerResult = await execFileAsync("python", [
      "tests/ui/complete_conversation_run.py",
      "--run-id",
      runId,
    ]);
    if (workerResult.stderr) {
      fs.appendFileSync(serverLog, `\n--- Browser E2E worker stderr ---\n${workerResult.stderr}\n`);
    }
    const activityEntries = page.locator("[data-activity-entry]");
    await activityEntries.filter({ hasText: /Running passive checks…/ }).waitFor({ timeout: 10000 });
    await activityEntries.filter({ hasText: /Verifying one possible finding…/ }).waitFor({ timeout: 10000 });
    await activityEntries.filter({ hasText: /Analysis complete\./ }).waitFor({ timeout: 10000 });
    if (!(await activityPanel.evaluate((element) => element.open))) {
      await activityPanel.locator(":scope > summary").click();
    }
    await activityPanel.locator(".vh-analysis-activity-node > summary").filter({ hasText: "Repository and file inspection" }).waitFor({ timeout: 10000 });
    const completedActivityCopy = (await activityPanel.textContent()) || "";
    if (!/Persisted operational work|compatibility manifests|Analysis complete/i.test(completedActivityCopy)) {
      throw new Error(`The activity hierarchy did not expose safe persisted summaries: ${completedActivityCopy}`);
    }
    if ((await activityEntries.count()) < 3) {
      throw new Error(`Expected at least three first-class activity entries, found ${await activityEntries.count()}`);
    }
    const activityCursors = activityRequests
      .map((url) => Number(new URL(url).searchParams.get("after_sequence") || 0))
      .filter((cursor, index, cursors) => cursors.indexOf(cursor) === index);
    if (!activityCursors.some((cursor) => cursor > 0)) {
      throw new Error(`SSE did not reconnect from a persisted cursor: ${activityRequests.join(" | ")}`);
    }

    const resultIndex = await assistantMessages.count();
    await input.fill("Show me the results");
    await send.click();
    const { copy: resultsCopy } = await waitForNewAssistantMessage(
      resultIndex,
      /Missing X-Content-Type-Options/,
    );

    const nextIndex = await assistantMessages.count();
    await input.fill("Next step");
    await send.click();
    const { copy: nextCopy } = await waitForNewAssistantMessage(
      nextIndex,
      /evidence|remediation|retest/i,
    );
    if (nextCopy === resultsCopy) {
      throw new Error(`Next-step reply repeated the results reply: ${nextCopy}`);
    }

    const previousThreadUrl = page.url();
    await overflow.click();
    await newAssessment.waitFor({ state: "visible", timeout: 5000 });
    await newAssessment.click();
    const stopThreadCard = page.locator(
      '.vh-chat-action-card[data-action-type="new-assessment"]',
    );
    await stopThreadCard.waitFor({ state: "visible", timeout: 5000 });
    await Promise.all([
      page.waitForURL(
        (url) => url.toString() !== previousThreadUrl && url.searchParams.has("thread"),
        { timeout: 15000 },
      ),
      stopThreadCard.getByRole("button", { name: /start new assessment/i }).click(),
    ]);
    await page.locator("[data-conversation-workspace]").waitFor({ timeout: 15000 });

    const stopInput = page.locator("[data-conversation-input]");
    const stopSend = page.locator("[data-conversation-send]");
    await stopInput.fill("Scan http://10.0.11.34:8010/ using the passive profile");
    await stopSend.click();
    await page.locator("[data-inline-approval]").waitFor({ state: "visible", timeout: 15000 });
    await stopInput.fill("Confirm");
    await stopSend.click();
    await page
      .locator(".vh-chat-message.is-assistant")
      .filter({ hasText: /Approved\. Starting the governed assessment/ })
      .last()
      .waitFor({ timeout: 15000 });
    const stopRunId = await page.locator("[data-run-card]").last().getAttribute("data-run-id");
    if (!stopRunId) throw new Error("The cancellation acceptance run did not expose a run id");
    const startOnlyResult = await execFileAsync("python", [
      "tests/ui/complete_conversation_run.py",
      "--run-id",
      stopRunId,
      "--start-only",
    ]);
    if (startOnlyResult.stderr) {
      fs.appendFileSync(serverLog, `\n--- Browser E2E start-only worker stderr ---\n${startOnlyResult.stderr}\n`);
    }
    const stopControl = page.locator("[data-conversation-stop]");
    await stopControl.waitFor({ state: "visible", timeout: 15000 });
    await stopControl.click();
    const cancelDialog = page.locator("[data-cancel-dialog]");
    await cancelDialog.waitFor({ state: "attached", timeout: 5000 });
    if (!(await cancelDialog.evaluate((dialog) => dialog.open))) {
      throw new Error("The governed cancellation dialog did not enter the native open state");
    }
    await cancelDialog.locator("[data-cancel-dialog-confirm]").evaluate((button) => button.click());
    await page.locator("[data-run-card].is-cancelled").waitFor({ state: "visible", timeout: 15000 });
    if (await stopControl.isVisible()) {
      throw new Error("The governed stop control remained visible after cancellation became terminal");
    }

    const technicalOpen = await page.locator('details[data-section="technical"]').evaluate(
      (element) => element.open,
    );
    if (technicalOpen) throw new Error("Technical details must remain collapsed by default");
    if (consoleErrors.length) throw new Error(`Browser console errors: ${consoleErrors.join(" | ")}`);
    console.log(JSON.stringify({ runId, resultsCopy, nextCopy }));
  } catch (error) {
    const detail = error && error.stack ? error.stack : String(error);
    console.error(detail);
    fs.appendFileSync(serverLog, `\n\n--- Conversational E2E failure ---\n${detail}\n`);
    if (page) {
      fs.mkdirSync(outputDir, { recursive: true });
      await page.screenshot({ path: failureScreenshot, fullPage: true }).catch(() => undefined);
    }
    process.exitCode = 1;
  } finally {
    if (browser) await browser.close();
  }
})();