const fs = require('fs');
const { chromium } = require('playwright');

const baseUrl = process.env.VULNHUNTER_UI_BASE_URL || 'http://127.0.0.1:8000';
const manifestPath = process.env.VULNHUNTER_UI_MANIFEST;
if (!manifestPath) throw new Error('VULNHUNTER_UI_MANIFEST is required');
const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
const persona = manifest.personas.admin;

const attachment = {
  attachment_id: 'attachment-rapid-sse-0123456789',
  kind: 'android_apk',
  artifact_id: 'apk-rapid-sse-0123456789abcdef',
  artifact_sha256: 'c'.repeat(64),
  original_filename: 'rapid-sse.apk',
  size_bytes: 128,
  archive_entry_count: 3,
  dex_count: 1,
  native_library_count: 0,
  native_abis: [],
};
const plan = {
  run_id: 'mobile-rapid-sse-demo',
  plan_id: 'analysis-rapid-sse-demo',
  plan_digest: 'd'.repeat(64),
  profile: 'static',
  requested_profile: 'static',
  tool_count: 1,
  tools: [{ name: 'JADX', tool_id: 'jadx', gate: 'policy' }],
  rounds: [{ altitude: 'artifact', label: 'APK identity', purpose: 'Inspect the package envelope', status: 'planned' }],
  dynamic_deferred: false,
  execution: { state: 'queued', job_id: 'mobile-rapid-sse-demo' },
};

async function login(page) {
  await page.goto(`${baseUrl}/login/`, { waitUntil: 'domcontentloaded' });
  await page.getByLabel('Username').fill(persona.username);
  await page.getByLabel('Password').fill(persona.password);
  await Promise.all([
    page.waitForURL((url) => new URL(url).pathname !== '/login/'),
    page.getByRole('button', { name: /sign in securely/i }).click(),
  ]);
}

(async () => {
  const browser = await chromium.launch({
    headless: true,
    executablePath: process.env.VULNHUNTER_CHROME_PATH || '/usr/bin/chromium',
  });
  const page = await browser.newPage({ viewport: { width: 1280, height: 820 } });
  let streamBurst = 0;
  try {
    await login(page);
    await page.route('**/workspace/uploads/start/', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          upload_id: 'upload-rapid-sse-demo',
          chunk_url: '/workspace/uploads/upload-rapid-sse-demo/chunk/',
          status_url: '/workspace/uploads/upload-rapid-sse-demo/status/',
          cancel_url: '/workspace/uploads/upload-rapid-sse-demo/cancel/',
          chunk_bytes: 1024,
          maximum_bytes: 10_000_000,
        }),
      });
    });
    await page.route('**/workspace/uploads/upload-rapid-sse-demo/chunk/', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          upload_id: 'upload-rapid-sse-demo',
          received_bytes: 128,
          expected_bytes: 128,
          complete: false,
          attachment,
        }),
      });
    });
    await page.route('**/workspace/mobile-message/', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          attachment,
          mobile_plan: plan,
          message: {
            role: 'assistant',
            kind: 'mobile_plan',
            content: 'I prepared the APK assessment and selected the safe static tools first.',
            metadata: { mobile_plan: plan, attachment },
          },
        }),
      });
    });
    await page.route('**/workspace/mobile-activity/**/stream/**', async (route) => {
      streamBurst += 1;
      const completed = streamBurst >= 2;
      const sequence = completed ? 2 : 1;
      const detail = completed
        ? 'JADX completed in burst 2 and persisted its bounded capture.'
        : 'JADX started in burst 1 and is collecting bounded source evidence.';
      const progressEvent = {
        sequence,
        at: `2026-08-19T12:01:0${sequence}+00:00`,
        state: completed ? 'completed' : 'running',
        stage: 'decompile',
        detail,
        tool: 'jadx',
        tool_state: completed ? 'completed' : 'running',
      };
      const event = {
        run_id: plan.run_id,
        events: [
          {
            event_id: `rapid_evt_${sequence}`,
            sequence,
            event_type: completed ? 'tool_execution_completed' : 'tool_progress',
            summary: detail,
            timestamp: progressEvent.at,
            metadata: { profile: 'static', mobile_progress_sequence: String(sequence) },
          },
        ],
        last_sequence: sequence,
        run_state: completed ? 'completed' : 'executing',
        terminal: completed,
        mobile_execution: {
          state: completed ? 'completed' : 'running',
          job_id: plan.run_id,
          progress: { active_tool: completed ? null : 'jadx', events: [progressEvent] },
        },
      };
      await route.fulfill({
        status: 200,
        contentType: 'text/event-stream',
        body: `retry: 50\nid: ${sequence}\nevent: activity\ndata: ${JSON.stringify(event)}\n\n`,
      });
    });

    await page.goto(`${baseUrl}/`, { waitUntil: 'domcontentloaded' });
    await page.locator('[data-conversation-form]').waitFor({ state: 'visible' });
    await page.locator('[data-conversation-file]').setInputFiles({
      name: 'rapid-sse.apk',
      mimeType: 'application/vnd.android.package-archive',
      buffer: Buffer.alloc(128, 0x41),
    });
    await page.locator('[data-attachment-tray]').getByText('rapid-sse.apk').waitFor();
    await page.locator('[data-conversation-input]').fill('Scan this APK with rapid progress');
    await page.getByRole('button', { name: 'Send message' }).click();

    const liveBlock = page.locator(`[data-mobile-live-execution="${plan.run_id}"]`);
    await liveBlock.waitFor();
    await page.waitForFunction(() => document.body.innerText.includes('JADX completed in burst 2'));
    if (streamBurst < 2) throw new Error(`Expected at least two rapid SSE bursts, received ${streamBurst}`);
    const stepRows = liveBlock.locator('[data-mobile-live-steps] > li');
    if (await stepRows.count() !== 1) throw new Error(`Expected one in-place step row, found ${await stepRows.count()}`);
    const rowText = await stepRows.first().textContent();
    if (!/JADX completed in burst 2/i.test(rowText || '')) throw new Error(`Final step detail missing: ${rowText}`);
    if (!(await stepRows.first().evaluate((node) => node.classList.contains('is-completed')))) {
      throw new Error('The in-place step did not transition to completed state');
    }
    if (await page.locator('[data-activity-entry].is-mobile-activity').count() < 2) {
      throw new Error('Rapid SSE activity history was not preserved');
    }
    console.log('Rapid APK SSE in-place update acceptance passed.');
  } finally {
    await browser.close();
  }
})();
