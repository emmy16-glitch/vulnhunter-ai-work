#!/usr/bin/env python3
"""Place terminal-run clearing in the normal conversation submit path."""

from pathlib import Path


path = Path(__file__).resolve().parents[1] / "vulnhunter/web/static/web/conversation.js"
text = path.read_text(encoding="utf-8")
old = '''      const data = await postForm(initial.message_url, { message: value });
      if (data.message) appendMessage(data.message, { animate: true });
      if (data.run) {
'''
new = '''      const data = await postForm(initial.message_url, { message: value });
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
if new not in text:
    if old not in text:
        raise SystemExit("Message-submit patch context was not found")
    path.write_text(text.replace(old, new, 1), encoding="utf-8")
