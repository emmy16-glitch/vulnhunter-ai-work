from __future__ import annotations

from pathlib import Path

path = Path(__file__).resolve().parents[1] / "vulnhunter/web/static/web/app.js"
text = path.read_text(encoding="utf-8")
old = '''    if (elapsed) elapsed.textContent = formatElapsed(elapsedSeconds);
    const timer = window.setInterval(() => {
      if (!root.classList.contains("is-active")) return;
      elapsedSeconds += 1;
      if (elapsed) elapsed.textContent = formatElapsed(elapsedSeconds);
    }, 1000);
'''
new = '''    if (elapsed) elapsed.textContent = formatElapsed(elapsedSeconds);
'''
if old not in text:
    raise RuntimeError("operational timer block changed")
text = text.replace(old, new, 1)
text = text.replace("        window.clearInterval(timer);\n", "", 1)
path.write_text(text, encoding="utf-8")
