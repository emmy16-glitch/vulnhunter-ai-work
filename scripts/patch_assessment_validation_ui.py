from __future__ import annotations

from pathlib import Path

path = Path(__file__).resolve().parents[1] / "vulnhunter/web/templates/web/agent_run_detail.html"
text = path.read_text(encoding="utf-8")

old = '''<span class="vh-visually-hidden">Human controls</span>

<div class="vh-assessment-layout">'''
new = '''<span class="vh-visually-hidden">Human controls</span>

<div class="vh-operational-status{% if not timeline.terminal %} is-active{% else %} is-terminal{% endif %}"
     data-operational-stream="{% url 'web-agent-run-activity-stream' run.run_id %}"
     data-last-sequence="{{ timeline.last_sequence|default:0 }}"
     data-started-at="{{ run.created_at|date:'c' }}"
     aria-live="polite">
  <span class="vh-operational-pulse" aria-hidden="true"></span>
  {% with last_event=timeline.events|last %}<span class="vh-operational-copy" data-operational-copy>{% if last_event %}{{ last_event.summary }}{% else %}{{ run.execution_blocking_reason|default:"Waiting for the next recorded assessment event." }}{% endif %}</span>{% endwith %}
  <span class="vh-operational-meta"><strong data-operational-state>{{ run.workflow_state|default:run.current_state }}</strong><time data-operational-elapsed>00:00:00</time></span>
</div>

<div class="vh-assessment-layout">'''
if old not in text:
    raise RuntimeError("assessment layout marker changed")
text = text.replace(old, new, 1)

old = '''        <li class="vh-stage {% if run.current_state == 'completed' %}is-complete{% endif %}"><span class="vh-stage-marker">{% if run.current_state == 'completed' %}✓{% else %}07{% endif %}</span><details class="vh-stage-card vh-stage-disclosure"><summary><span class="vh-stage-number">07</span><span class="vh-stage-copy"><strong>Packaging and Release</strong><small>Completion does not publish a finding.</small></span><span class="vh-stage-state">{{ run.current_state }}</span><svg class="vh-stage-chevron"><use href="#vh-i-chevron"></use></svg></summary><div class="vh-stage-detail"><span>Run state</span><strong>{{ run.current_state }}</strong><span>Release</span><strong>Separately gated</strong></div></details></li>'''
new = '''        <li class="vh-stage {% if latest_lab %}is-complete{% elif run.findings %}is-warning{% endif %}"><span class="vh-stage-marker">{% if latest_lab %}✓{% else %}07{% endif %}</span><details class="vh-stage-card vh-stage-disclosure" data-persist-disclosure data-disclosure-key="assessment-active-validation"><summary><span class="vh-stage-number">07</span><span class="vh-stage-copy"><strong>Active Validation</strong><small>Controlled synthetic impact simulation for a persisted finding.</small></span><span class="vh-stage-state">{% if latest_lab %}{{ latest_lab.state.value }}{% elif run.findings %}Available{% else %}No finding{% endif %}</span><svg class="vh-stage-chevron"><use href="#vh-i-chevron"></use></svg></summary><div class="vh-stage-expanded-body">{% if latest_lab %}<a class="vh-button-secondary" href="{% url 'web-lab-detail' latest_lab.plan.lab_id %}">Open latest validation run</a>{% elif run.findings and can_request_lab %}<a class="vh-button-primary" href="{% url 'web-lab-create' run.run_id %}">Request active validation</a>{% elif run.findings %}<p class="vh-terminal-empty">A governed staff operator must request this action.</p>{% else %}<p class="vh-terminal-empty">A persisted finding is required.</p>{% endif %}</div></details></li>
        <li class="vh-stage {% if run.current_state == 'completed' %}is-complete{% endif %}"><span class="vh-stage-marker">{% if run.current_state == 'completed' %}✓{% else %}08{% endif %}</span><details class="vh-stage-card vh-stage-disclosure" data-persist-disclosure data-disclosure-key="assessment-release"><summary><span class="vh-stage-number">08</span><span class="vh-stage-copy"><strong>Packaging and Release</strong><small>Completion does not publish a finding.</small></span><span class="vh-stage-state">{{ run.current_state }}</span><svg class="vh-stage-chevron"><use href="#vh-i-chevron"></use></svg></summary><div class="vh-stage-detail"><span>Run state</span><strong>{{ run.current_state }}</strong><span>Release</span><strong>Separately gated</strong></div></details></li>'''
if old not in text:
    raise RuntimeError("release stage marker changed")
text = text.replace(old, new, 1)

old = '''{% if controls.stop.available %}<a class="vh-button-secondary" href="{% url 'web-agent-run-stop' run.run_id %}">Stop run</a>{% endif %}<a class="vh-button-secondary" href="{% url 'web-authorization-list' %}">Authorization</a>'''
new = '''{% if controls.stop.available %}<a class="vh-button-secondary" href="{% url 'web-agent-run-stop' run.run_id %}">Stop run</a>{% endif %}{% if latest_lab %}<a class="vh-button-secondary" href="{% url 'web-lab-detail' latest_lab.plan.lab_id %}">Active validation</a>{% elif run.findings and can_request_lab %}<a class="vh-button-secondary" href="{% url 'web-lab-create' run.run_id %}">Request active validation</a>{% endif %}<a class="vh-button-secondary" href="{% url 'web-authorization-list' %}">Authorization</a>'''
if old not in text:
    raise RuntimeError("assessment action marker changed")
text = text.replace(old, new, 1)
path.write_text(text, encoding="utf-8")
