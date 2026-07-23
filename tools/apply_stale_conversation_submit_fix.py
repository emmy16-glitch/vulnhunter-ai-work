#!/usr/bin/env python3
"""Place terminal-run clearing only in the normal conversation submit path."""

from pathlib import Path


path = Path(__file__).resolve().parents[1] / "vulnhunter/web/static/web/conversation.js"
text = path.read_text(encoding="utf-8")

approval_with_clear = '''      const runId = text(data.run?.run_id || card.dataset.runId);
      if (runId) confirmedRuns.add(runId);
      if (data.message) appendMessage(data.message, { animate: true });
      if (data.clear_run) {
        if (pollTimer) window.clearTimeout(pollTimer);
        runCard?.remove();
        runCard = null;
        activeRun = null;
        lastRunSignature = "";
      }
      if (data.run) {
'''
approval_without_clear = '''      const runId = text(data.run?.run_id || card.dataset.runId);
      if (runId) confirmedRuns.add(runId);
      if (data.message) appendMessage(data.message, { animate: true });
      if (data.run) {
'''
if approval_with_clear in text:
    text = text.replace(approval_with_clear, approval_without_clear, 1)

submit_without_clear = '''      const data = await postForm(initial.message_url, { message: value });
      if (data.message) appendMessage(data.message, { animate: true });
      if (data.run) {
'''
submit_with_clear = '''      const data = await postForm(initial.message_url, { message: value });
      if (data.message) appendMessage(data.message, { animate: true });
      if (data.clear_run) {
        if (pollTimer) window.clearTimeout(pollTimer);
        runCard?.remove();
        runCard = null;
        activeRun = null;
        lastRunSignature = "";
      }
      if (data.run) {
'''
if submit_with_clear not in text:
    if submit_without_clear not in text:
        raise SystemExit("Message-submit patch context was not found")
    text = text.replace(submit_without_clear, submit_with_clear, 1)

path.write_text(text, encoding="utf-8")
