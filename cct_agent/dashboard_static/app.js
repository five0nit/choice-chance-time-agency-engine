'use strict';

const state = {
  snapshot: null,
  csrfToken: null,
  session: null,
  preview: null,
};

function node(tag, className, text) {
  const item = document.createElement(tag);
  if (className) item.className = className;
  if (text !== undefined && text !== null) item.textContent = String(text);
  return item;
}

function clear(element) {
  while (element.firstChild) element.removeChild(element.firstChild);
}

function badge(value) {
  const item = node('span', 'status-badge', value);
  item.dataset.state = String(value);
  return item;
}

function number(value) {
  return new Intl.NumberFormat().format(Number(value || 0));
}

function shortId(value) {
  const text = String(value || 'none');
  return text.length > 22 ? `${text.slice(0, 11)}…${text.slice(-8)}` : text;
}

function empty(target, text) {
  clear(target);
  target.append(node('div', 'empty', text));
}

function setControlMessage(text, isError = false) {
  const message = document.getElementById('control-message');
  message.textContent = text;
  message.dataset.state = isError ? 'error' : 'ok';
}

async function responseJson(response) {
  try {
    return await response.json();
  } catch (_failure) {
    return { error: 'CONTROL_RESPONSE_INVALID' };
  }
}

async function apiPost(path, body) {
  const headers = { 'Content-Type': 'application/json' };
  if (state.csrfToken) headers['X-CCT-CSRF'] = state.csrfToken;
  const response = await fetch(path, {
    method: 'POST',
    credentials: 'same-origin',
    cache: 'no-store',
    headers,
    body: JSON.stringify(body),
  });
  const payload = await responseJson(response);
  if (!response.ok) throw new Error(payload.error || 'CONTROL_REQUEST_FAILED');
  return payload;
}

async function loadSession() {
  const response = await fetch('/api/operator/session', {
    cache: 'no-store',
    credentials: 'same-origin',
  });
  const payload = await responseJson(response);
  if (!response.ok || payload.authenticated !== true) {
    state.session = null;
    state.csrfToken = null;
    return payload;
  }
  state.session = payload;
  state.csrfToken = payload.csrf_token;
  return payload;
}

function renderOutcome(snapshot) {
  const outcome = document.getElementById('outcome');
  outcome.className = `outcome state-${String(snapshot.outcome.state).toLowerCase().replaceAll('_', '-')}`;
  document.getElementById('overview-title').textContent = snapshot.outcome.headline;
  document.getElementById('outcome-detail').textContent = snapshot.outcome.detail;
  document.getElementById('next-action').textContent = snapshot.outcome.next_action;

  const summary = document.getElementById('summary-grid');
  clear(summary);
  const metrics = [
    ['Events', snapshot.summary.event_count],
    ['Active goals', snapshot.summary.active_goals],
    ['Capabilities', snapshot.summary.capability_count],
    ['Active leases', snapshot.summary.active_leases],
    ['Pending approvals', snapshot.summary.pending_approvals],
    ['External effects', snapshot.summary.external_effects],
  ];
  metrics.forEach(([label, value]) => {
    const card = node('div', 'metric');
    card.append(node('strong', '', number(value)), node('span', '', label));
    summary.append(card);
  });

  const dashboardGoal = snapshot.goals.find((goal) => goal.goal_id.includes('administrative_control_plane'));
  const current = dashboardGoal || snapshot.goals.find((goal) => goal.status === 'active');
  document.getElementById('current-goal').textContent = current
    ? `${dashboardGoal ? 'Administrative control plane' : current.goal_id} · ${current.status}`
    : 'No active goal recorded';
}

function previewText(preview) {
  const action = preview.after.active ? 'Resume operator.web' : 'Pause operator.web';
  const stateChange = `${preview.before.effective_state} → ${preview.after.effective_state}`;
  return { action, stateChange };
}

function openPreviewDialog(preview) {
  state.preview = preview;
  const copy = previewText(preview);
  document.getElementById('control-dialog-title').textContent = copy.action;
  document.getElementById('preview-state-change').textContent = copy.stateChange;
  document.getElementById('preview-scope').textContent = preview.draft.capability;
  document.getElementById('preview-revision').textContent = `${preview.before.control_revision} → ${preview.after.control_revision}`;
  document.getElementById('preview-digest').textContent = preview.preview_sha256;
  document.getElementById('preview-expiry').textContent = preview.expires_at;
  document.getElementById('preview-expiry').title = preview.expires_at;
  const pausing = preview.after.active !== true;
  document.getElementById('preview-impact').textContent = pausing
    ? 'Configured intent changes from DENY to PAUSED on this local CCTAE ledger.'
    : 'Configured intent changes from PAUSED to active; effective authority remains DENY.';
  document.getElementById('preview-authority-impact').textContent = pausing
    ? 'New evaluations, lease grants, ticket issuance/claims, and reservation consumption are rejected.'
    : 'Resume restores consideration only; any later effect still requires a matching lease, exact ticket, and readback.';
  document.getElementById('preview-duration-impact').textContent = pausing
    ? 'Pause persists until a separate exact resume. The displayed expiry applies only to this confirmation.'
    : 'Resume persists until a separate exact pause. The displayed expiry applies only to this confirmation.';
  const result = document.getElementById('control-dialog-result');
  result.textContent = 'Review exact scope and state. Confirmation is short-lived and one-use.';
  result.dataset.state = 'ready';
  const applyButton = document.getElementById('confirm-apply');
  applyButton.textContent = pausing ? 'Confirm pause and host-apply' : 'Confirm resume and host-apply';
  applyButton.disabled = false;
  const dialog = document.getElementById('control-dialog');
  if (typeof dialog.showModal === 'function') dialog.showModal();
  else dialog.setAttribute('open', '');
}

async function draftPermissionChange(row) {
  setControlMessage(`Building zero-mutation preview for ${row.name}…`);
  try {
    const preview = await apiPost('/api/controls/preview', {
      draft: {
        draft_id: `draft-${crypto.randomUUID()}`,
        action: 'SET_CAPABILITY_ADMINISTRATIVE_ACTIVE',
        capability: row.name,
        active: row.administrative_active === false,
      },
    });
    openPreviewDialog(preview);
    setControlMessage('Preview verified. No canonical state changed.');
  } catch (failure) {
    setControlMessage(`Preview blocked: ${failure.message}`, true);
  }
}

function renderPermissions(rows, controls) {
  const body = document.getElementById('permissions-body');
  clear(body);
  rows.forEach((row) => {
    const tr = document.createElement('tr');
    const capability = document.createElement('td');
    capability.append(node('strong', '', row.name), node('small', '', `${row.effect_kind} · ${row.reversible ? 'reversible' : 'non-reversible'}`));
    const effective = document.createElement('td');
    effective.append(badge(row.effective_state));
    const risk = node('td', '', row.risk_class);
    const scope = document.createElement('td');
    scope.append(node('strong', '', row.scopes[0] || 'No scope'), node('small', '', row.verifier_id));
    const lease = document.createElement('td');
    lease.append(node('strong', '', `${row.active_lease_count} active`), node('small', '', row.next_expiry || 'No active expiry'));
    const budget = document.createElement('td');
    budget.append(node('strong', '', `${number(row.remaining_actions)} actions`), node('small', '', `${number(row.remaining_bytes)} bytes`));
    const control = document.createElement('td');
    const supported = Boolean(controls && controls.installed && row.name === controls.capability);
    const ready = supported && row.control_state === 'READY';
    const controlActive = row.administrative_active !== false;
    const button = node('button', 'button secondary', controlActive ? 'Preview pause' : 'Preview resume');
    button.type = 'button';
    button.disabled = !ready;
    button.dataset.mutation = 'configured-intent';
    button.title = supported
      ? ready
        ? 'Create a deterministic zero-mutation preview.'
        : 'Unlock the host-issued operator session first.'
      : 'This capability is outside the first controlled mutation slice.';
    if (ready) button.addEventListener('click', () => draftPermissionChange(row));
    control.append(button);
    tr.append(capability, effective, risk, scope, lease, budget, control);
    body.append(tr);
  });
}

function dataCard(title, id, currentState, facts) {
  const card = node('article', 'data-card');
  const top = node('div', 'card-top');
  const heading = node('div');
  heading.append(node('p', 'section-kicker', id), node('h3', '', title));
  top.append(heading, badge(currentState));
  card.append(top);
  const list = document.createElement('dl');
  facts.forEach(([label, value]) => {
    const pair = node('div');
    pair.append(node('dt', '', label), node('dd', '', value));
    list.append(pair);
  });
  card.append(list);
  return card;
}

function renderAccess(rows) {
  const grid = document.getElementById('access-grid');
  if (!rows.length) return empty(grid, 'No authenticated access route has been prepared.');
  clear(grid);
  rows.forEach((row) => {
    grid.append(dataCard(row.target_id, row.route, row.state, [
      ['Authority', row.execution_authority_granted ? 'Granted' : 'Not granted'],
      ['Last change', row.last_changed_at],
      ['Receipt', shortId(row.last_event_id)],
    ]));
  });
}

function renderAutomations(rows) {
  const grid = document.getElementById('automation-grid');
  clear(grid);
  rows.forEach((row) => {
    grid.append(dataCard(row.label, row.id, row.state, [
      ['Observed', number(row.observed_events)],
      ['Runs', number(row.runs)],
      ['Verified / failed', `${number(row.verified_runs)} / ${number(row.failed_runs)}`],
    ]));
  });
}

function renderApprovals(rows) {
  const list = document.getElementById('approval-list');
  if (!rows.length) return empty(list, 'No operator decision is pending.');
  clear(list);
  rows.forEach((row) => {
    const item = node('article', 'stack-item');
    const detail = node('div');
    detail.append(node('strong', '', row.request_id), node('small', '', `Revision ${row.revision} · ${row.question_count} question(s) · ${row.presented_at}`));
    item.append(detail, badge(row.state));
    list.append(item);
  });
}

function renderAudit(audit) {
  document.getElementById('audit-summary').textContent = audit.rows.length
    ? `${audit.rows.length} recent human-relevant receipts. Event chain: ${audit.chain.valid ? 'valid' : 'invalid'} with ${number(audit.chain.event_count)} events.`
    : 'No human-relevant event has been recorded.';
  const list = document.getElementById('audit-list');
  if (!audit.rows.length) return empty(list, 'No human-relevant event has been recorded.');
  clear(list);
  audit.rows.forEach((row) => {
    const item = node('article', 'timeline-item');
    item.append(node('span', 'timeline-dot'));
    const copy = node('div');
    copy.append(node('p', '', row.text));
    item.append(copy, node('code', '', `${row.trace.seq} · ${shortId(row.trace.event_id)}`));
    list.append(item);
  });
}

function renderEmergency(emergency) {
  const active = Boolean(emergency.kill_switch_active);
  const light = document.getElementById('stop-light');
  light.classList.toggle('active', active);
  document.getElementById('stop-state').textContent = active ? 'STOP ACTIVE' : 'CLEAR';
  document.getElementById('stop-detail').textContent = active
    ? `Trip: ${emergency.active_trip_id || 'recorded'} · operator inspection required.`
    : 'No global effect stop is currently active.';
}

function renderControlSession(controls) {
  const panel = document.getElementById('control-session');
  const modeLabel = document.getElementById('mode-label');
  const modeDetail = document.getElementById('mode-detail');
  panel.hidden = !controls.installed;
  modeLabel.textContent = controls.installed ? 'HOST CONTROLLED' : 'READ ONLY';
  modeDetail.textContent = controls.installed ? 'Preview + confirmed apply' : 'Local ledger projection';
  if (!controls.installed) return;

  const authenticated = Boolean(state.session && controls.authenticated);
  document.getElementById('bootstrap-token').disabled = authenticated;
  document.getElementById('unlock-controls').disabled = authenticated;
  document.getElementById('unlock-controls').textContent = authenticated ? 'Session unlocked' : 'Unlock controls';
  document.getElementById('session-state').textContent = authenticated
    ? `Authenticated as ${state.session.principal_id} until ${state.session.expires_at}`
    : 'Locked. Paste the one-use token from the owner-only host bootstrap file.';
  if (!authenticated) setControlMessage('No permission change can be applied while locked.');
}

function render(snapshot) {
  state.snapshot = snapshot;
  renderOutcome(snapshot);
  renderControlSession(snapshot.controls || { installed: false, authenticated: false });
  renderPermissions(snapshot.permissions, snapshot.controls);
  renderAccess(snapshot.access);
  renderAutomations(snapshot.automations);
  renderApprovals(snapshot.approvals);
  renderAudit(snapshot.audit);
  renderEmergency(snapshot.emergency);
  const generated = new Date(snapshot.generated_at);
  const freshness = document.getElementById('freshness');
  freshness.textContent = `Verified ${Number.isNaN(generated.valueOf()) ? snapshot.generated_at : generated.toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' })}`;
  freshness.title = snapshot.generated_at;
  document.getElementById('schema-version').textContent = `${snapshot.schema_version} · ${snapshot.mode}`;
}

async function load() {
  const loading = document.getElementById('loading');
  const error = document.getElementById('error');
  loading.hidden = false;
  error.hidden = true;
  try {
    await loadSession();
    const response = await fetch('/api/dashboard', { cache: 'no-store', credentials: 'same-origin' });
    const payload = await responseJson(response);
    if (!response.ok) throw new Error(payload.error || 'DASHBOARD_STATE_UNAVAILABLE');
    render(payload);
  } catch (failure) {
    error.textContent = `Dashboard unavailable: ${failure.message}`;
    error.hidden = false;
  } finally {
    loading.hidden = true;
  }
}

async function unlockControls() {
  const input = document.getElementById('bootstrap-token');
  const token = input.value.trim();
  if (!token) return setControlMessage('Bootstrap token required.', true);
  setControlMessage('Verifying one-use host bootstrap…');
  try {
    const session = await apiPost('/api/operator/session', { bootstrap_token: token });
    input.value = '';
    state.session = session;
    state.csrfToken = session.csrf_token;
    setControlMessage('Operator session authenticated. Preview remains zero-mutation.');
    await load();
  } catch (failure) {
    input.value = '';
    setControlMessage(`Unlock blocked: ${failure.message}`, true);
  }
}

async function confirmAndApply() {
  if (!state.preview) return;
  const button = document.getElementById('confirm-apply');
  const result = document.getElementById('control-dialog-result');
  button.disabled = true;
  result.textContent = 'Recording authenticated confirmation…';
  result.dataset.state = 'working';
  try {
    const confirmation = await apiPost('/api/controls/confirm', { preview: state.preview });
    result.textContent = 'Confirmation bound. Host apply and canonical readback running…';
    const applied = await apiPost('/api/controls/apply', {
      preview: state.preview,
      confirmation,
    });
    result.textContent = `${applied.status}: ${applied.capability} is ${applied.active ? 'active' : 'paused'} at control revision ${applied.control_revision}.`;
    result.dataset.state = 'ok';
    setControlMessage(`${applied.status}: canonical readback matched; external effects ${applied.external_effects}.`);
    state.preview = null;
    await load();
    window.setTimeout(() => document.getElementById('control-dialog').close(), 800);
  } catch (failure) {
    result.textContent = `Apply blocked: ${failure.message}`;
    result.dataset.state = 'error';
    setControlMessage(`Apply blocked: ${failure.message}`, true);
    button.disabled = false;
  }
}

document.querySelectorAll('nav button[data-target]').forEach((button) => {
  button.addEventListener('click', () => {
    document.querySelectorAll('nav button').forEach((item) => item.removeAttribute('aria-current'));
    button.setAttribute('aria-current', 'page');
    document.getElementById(button.dataset.target).scrollIntoView({ behavior: 'smooth', block: 'start' });
  });
});

document.getElementById('refresh').addEventListener('click', load);
document.getElementById('inspect-failure').addEventListener('click', () => {
  document.getElementById('audit').scrollIntoView({ behavior: 'smooth', block: 'start' });
});
document.getElementById('unlock-controls').addEventListener('click', unlockControls);
document.getElementById('bootstrap-token').addEventListener('keydown', (event) => {
  if (event.key === 'Enter') unlockControls();
});
document.getElementById('confirm-apply').addEventListener('click', confirmAndApply);
document.getElementById('cancel-control').addEventListener('click', () => {
  state.preview = null;
  document.getElementById('control-dialog').close();
});
load();
