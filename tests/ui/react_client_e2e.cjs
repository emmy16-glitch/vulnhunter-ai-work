const { chromium } = require("playwright");

const baseUrl = process.env.VULNHUNTER_UI_BASE_URL || "http://127.0.0.1:8000";
const frontendUrl = process.env.VULNHUNTER_REACT_URL || "http://127.0.0.1:5173";
const chromePath = process.env.VULNHUNTER_CHROME_PATH || "/usr/bin/chromium";
const username = process.env.VULNHUNTER_REACT_E2E_USERNAME || "conversation-e2e";
const password = process.env.VULNHUNTER_REACT_E2E_PASSWORD || "Vh-Conversation-E2E-2026!";

(async () => {
  const browser = await chromium.launch({ headless: true, executablePath: chromePath });
  const page = await browser.newPage({ viewport: { width: 1440, height: 900 } });
  const errors = [];
  page.on("console", (message) => {
    if (message.type() === "error") errors.push(message.text());
  });
  try {
    await page.goto(`${baseUrl}/login/`, { waitUntil: "networkidle" });
    await page.getByLabel("Username").fill(username);
    await page.getByLabel("Password").fill(password);
    await Promise.all([
      page.waitForURL(`${baseUrl}/`),
      page.getByRole("button", { name: /sign in securely/i }).click(),
    ]);

    await page.goto(frontendUrl, { waitUntil: "networkidle" });
    await page.getByRole("heading", { name: "Assessment operations" }).waitFor({ timeout: 15000 });
    await page.getByText("Deployment readiness").waitFor({ timeout: 5000 });
    await page.getByText("Assessments", { exact: true }).waitFor({ timeout: 5000 });

    const assessmentRows = page.locator(".assessment-row");
    const assessmentCount = await assessmentRows.count();
    if (assessmentCount > 0) {
      await assessmentRows.first().click();
      await page.getByRole("heading", { name: "Live assessment activity" }).waitFor({ timeout: 15000 });
      await page.getByText(/cursor \d+/).waitFor({ timeout: 5000 });
    } else {
      await page.getByText("No visible persisted assessments for this identity.").waitFor({ timeout: 5000 });
    }

    if (errors.length) throw new Error(`React client console errors: ${errors.join(" | ")}`);
    console.log(JSON.stringify({ reactClient: "passed", assessmentCount }));
  } finally {
    await browser.close();
  }
})().catch((error) => {
  console.error(error && error.stack ? error.stack : String(error));
  process.exitCode = 1;
});
