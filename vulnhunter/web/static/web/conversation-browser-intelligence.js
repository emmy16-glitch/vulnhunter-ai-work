(() => {
  'use strict';

  const jsonHeaders = (form) => {
    const token = form.querySelector('input[name="csrfmiddlewaretoken"]');
    return {
      'Content-Type': 'application/json',
      'X-CSRFToken': token ? token.value : '',
    };
  };

  const requestJson = async (url, options) => {
    const response = await fetch(url, { credentials: 'same-origin', ...options });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok || payload.ok === false) {
      throw new Error(payload.error || 'Browser Intelligence request failed.');
    }
    return payload;
  };

  const setStatus = (form, text, kind = '') => {
    const node = form.querySelector('[data-browser-intelligence-status]');
    if (!node) return;
    node.textContent = text;
    node.className = kind ? `is-${kind}` : '';
  };

  const appendLive = (card, text, kind = '') => {
    const live = card.querySelector('[data-browser-intelligence-live]');
    if (!live) return;
    const row = document.createElement('p');
    row.className = `vh-browser-intelligence-receipt ${kind ? `is-${kind}` : ''}`;
    row.textContent = text;
    live.prepend(row);
  };

  const renderReceipt = (card, receipt) => {
    const summary = receipt.result_summary || {};
    const preview = summary.text_preview || summary.action || 'No public result summary.';
    const state = card.querySelector('[data-browser-intelligence-state]');
    if (state) state.textContent = receipt.status || 'recorded';
    appendLive(card, `${receipt.action_type}: ${preview}`, receipt.status || 'recorded');
  };

  const addEvidenceLink = (card, report, sessionId, workspaceId) => {
    const item = (report.screenshots || [])[0];
    const link = card.querySelector('[data-browser-intelligence-evidence]');
    if (!item || !link) return;
    const relative = String(item.relative_path || '').split('/').map(encodeURIComponent).join('/');
    link.href = `/workspace/browser-intelligence/${encodeURIComponent(sessionId)}/evidence/${relative}/?workspace_id=${encodeURIComponent(workspaceId)}`;
    link.textContent = `Open private screenshot evidence (${item.sha256.slice(0, 12)})`;
    link.hidden = false;
  };

  const bindCard = (card, session, form, targetUrl, workspaceId) => {
    const sessionId = session.session_id;
    card.dataset.sessionId = sessionId;
    card.querySelector('[data-browser-intelligence-target]').textContent = targetUrl;
    card.querySelector('[data-browser-intelligence-runtime]').textContent = `${session.runtime} ${session.runtime_version}`;
    card.querySelectorAll('[data-browser-action]').forEach((button) => {
      button.addEventListener('click', async () => {
        const action = button.dataset.browserAction;
        button.disabled = true;
        try {
          if (action === 'finish') {
            const payload = await requestJson(`/workspace/browser-intelligence/${encodeURIComponent(sessionId)}/finish/`, {
              method: 'POST',
              headers: jsonHeaders(form),
              body: JSON.stringify({}),
            });
            (payload.report.action_receipts || []).slice(-1).forEach((receipt) => renderReceipt(card, receipt));
            addEvidenceLink(card, payload.report, sessionId, workspaceId);
            appendLive(card, `Report persisted: ${payload.report.report_sha256.slice(0, 16)}`, 'completed');
            card.querySelectorAll('[data-browser-action]').forEach((control) => { control.disabled = true; });
            return;
          }
          const payload = await requestJson(`/workspace/browser-intelligence/${encodeURIComponent(sessionId)}/action/`, {
            method: 'POST',
            headers: jsonHeaders(form),
            body: JSON.stringify({ action, parameters: action === 'take_screenshot' ? { width: 1280, height: 900 } : {} }),
          });
          renderReceipt(card, payload.receipt);
        } catch (error) {
          appendLive(card, error instanceof Error ? error.message : 'Browser action failed.', 'failed');
        } finally {
          button.disabled = false;
        }
      });
    });
    return requestJson(`/workspace/browser-intelligence/${encodeURIComponent(sessionId)}/action/`, {
      method: 'POST',
      headers: jsonHeaders(form),
      body: JSON.stringify({ action: 'navigate', parameters: { url: targetUrl } }),
    }).then((payload) => renderReceipt(card, payload.receipt));
  };

  const init = () => {
    const form = document.querySelector('[data-browser-intelligence-form]');
    const sessions = document.querySelector('[data-browser-intelligence-sessions]');
    const template = document.querySelector('#vh-browser-intelligence-template');
    const workspace = document.querySelector('[data-conversation-workspace]');
    if (!form || !sessions || !template || !workspace) return;

    /* The setup form lives in the progressive empty-workspace disclosure, but
       live Browser Intelligence sessions are task evidence. Move only the
       session projection into the persistent conversation feed so it remains
       visible after the empty state disappears. */
    const feed = workspace.querySelector('[data-conversation-feed]');
    if (feed && sessions.closest('[data-conversation-empty]')) {
      sessions.classList.add('vh-browser-intelligence-sessions');
      feed.append(sessions);
    }

    form.addEventListener('submit', async (event) => {
      event.preventDefault();
      const data = new FormData(form);
      const targetUrl = String(data.get('target_url') || '').trim();
      const authorizationId = String(data.get('authorization_id') || '').trim();
      const workspaceId = workspace.dataset.threadId || 'conversation-workspace';
      setStatus(form, 'Starting governed browser worker…');
      const button = form.querySelector('[data-browser-intelligence-start]');
      if (button) button.disabled = true;
      try {
        const payload = await requestJson(form.action, {
          method: 'POST',
          headers: jsonHeaders(form),
          body: JSON.stringify({ target_url: targetUrl, authorization_id: authorizationId, workspace_id: workspaceId }),
        });
        const card = template.content.firstElementChild.cloneNode(true);
        sessions.prepend(card);
        await bindCard(card, payload.session, form, targetUrl, workspaceId);
        setStatus(form, 'Browser worker active.', 'completed');
      } catch (error) {
        setStatus(form, error instanceof Error ? error.message : 'Browser worker could not start.', 'failed');
      } finally {
        if (button) button.disabled = false;
      }
    });
  };

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init);
  else init();
})();