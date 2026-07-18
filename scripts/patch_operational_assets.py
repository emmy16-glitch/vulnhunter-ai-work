from __future__ import annotations

from pathlib import Path

path = Path(__file__).resolve().parents[1] / "vulnhunter/web/templates/web/base.html"
text = path.read_text(encoding="utf-8")
text = text.replace("20260717-product2", "20260718-operational")
old = """  <link rel="stylesheet" href="{% static 'web/product.css' %}?v=20260718-operational">
  <script src="{% static 'web/app.js' %}?v=20260718-operational" defer></script>"""
new = """  <link rel="stylesheet" href="{% static 'web/product.css' %}?v=20260718-operational">
  <link rel="stylesheet" href="{% static 'web/operational.css' %}?v=20260718-operational">
  <script src="{% static 'web/app.js' %}?v=20260718-operational" defer></script>"""
if old not in text:
    raise RuntimeError("base asset block changed")
path.write_text(text.replace(old, new, 1), encoding="utf-8")
