import '../../../cct_agent/dashboard_static/styles.css';
import './remote.css';
import { initializeApp } from 'firebase/app';
import {
  GoogleAuthProvider,
  browserLocalPersistence,
  getAuth,
  onAuthStateChanged,
  setPersistence,
  signInWithPopup,
  signOut,
} from 'firebase/auth';
import {
  doc,
  getDoc,
  getFirestore,
  onSnapshot,
  serverTimestamp,
  setDoc,
} from 'firebase/firestore';
import { firebaseConfig, ownerPolicy } from './firebase-config.js';
import { mountWorkspace } from './workspace-ui.js';
import { mountExecutor } from './executor-ui.js';

'use strict';

const REQUEST_SCHEMA = 'cct.firebase_control_request.v1';
const DASHBOARD_SCHEMA = 'cct.firebase_dashboard.v1';
const RECEIPT_TIMEOUT_MS = 60_000;
const CONTROL_ACTION = 'SET_CAPABILITY_ADMINISTRATIVE_ACTIVE';
const CONTROL_CAPABILITY = 'operator.web';

const firebaseApp = initializeApp(firebaseConfig);
const auth = getAuth(firebaseApp);
const db = getFirestore(firebaseApp);
const provider = new GoogleAuthProvider();

const state = {
  user: null,
  snapshot: null,
  preview: null,
  previewRequestId: null,
  previewAuthTokenSha256: null,
  unsubscribeSnapshot: null,
  workspace: null,
  snapshotFromCache: false,
  authGeneration: 0,
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

function authStatus(text, isError = false) {
  const status = document.getElementById('auth-status');
  status.textContent = text;
  status.dataset.state = isError ? 'error' : 'ok';
}

function boundedAuthError(error) {
  const code = typeof error?.code === 'string' ? error.code : 'auth/failed';
  const allowed = new Set([
    'auth/popup-closed-by-user',
    'auth/popup-blocked',
    'auth/cancelled-popup-request',
    'auth/network-request-failed',
    'auth/unauthorized-domain',
    'auth/internal-error',
    'auth/operation-not-allowed',
  ]);
  return allowed.has(code) ? code : 'auth/owner-verification-failed';
}

async function verifyOwner(user) {
  if (!user || !user.email || user.emailVerified !== true) return false;
  if (!ownerPolicy.pinnedUid || user.uid !== ownerPolicy.pinnedUid) return false;
  const googleProvider = user.providerData.some((entry) => entry.providerId === ownerPolicy.provider);
  if (!googleProvider) return false;
  const token = await user.getIdTokenResult(true);
  return token.claims.email === user.email
    && token.claims.email_verified === true
    && token.signInProvider === ownerPolicy.provider;
}

function showGate(message, isError = false) {
  document.getElementById('auth-gate').hidden = false;
  document.getElementById('app-shell').hidden = true;
  authStatus(message, isError);
}

function showApp(user) {
  document.getElementById('auth-gate').hidden = true;
  document.getElementById('app-shell').hidden = false;
  document.getElementById('identity').textContent = `${user.email} · ${shortId(user.uid)}`;
}

function renderOutcome(snapshot) {
  const outcome = document.getElementById('outcome');
  outcome.className = `outcome state-${String(snapshot.outcome.state).toLowerCase().replaceAll('_', '-')}`;
  document.getElementById('overview-title').textContent = snapshot.outcome.headline;
  document.getElementById('outcome-detail').textContent = snapshot.outcome.detail;
  document.getElementById('next-action').textContent = snapshot.outcome.next_action;

  const summary = document.getElementById('summary-grid');
  clear(summary);
  [
    ['Events', snapshot.summary.event_count],
    ['Active goals', snapshot.summary.active_goals],
    ['Capabilities', snapshot.summary.capability_count],
    ['Active leases', snapshot.summary.active_leases],
    ['Pending approvals', snapshot.summary.pending_approvals],
    ['External effects', snapshot.summary.external_effects],
  ].forEach(([label, value]) => {
    const card = node('div', 'metric');
    card.append(node('strong', '', number(value)), node('span', '', label));
    summary.append(card);
  });

  const goals = Array.isArray(snapshot.goals) ? snapshot.goals : [];
  const dashboardGoal = goals.find((goal) => String(goal.goal_id).includes('administrative_control_plane'));
  const current = dashboardGoal || goals.find((goal) => goal.status === 'active');
  document.getElementById('current-goal').textContent = current
    ? `${dashboardGoal ? 'Administrative control plane' : current.goal_id} · ${current.status}`
    : 'No active goal recorded';
}

function previewText(preview) {
  return {
    action: preview.after.active ? 'Resume operator.web' : 'Pause operator.web',
    stateChange: `${preview.before.effective_state} → ${preview.after.effective_state}`,
  };
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
    ? 'Configured intent changes from DENY to PAUSED on the canonical local CCTAE ledger.'
    : 'Configured intent changes from PAUSED to active; effective authority remains DENY.';
  document.getElementById('preview-authority-impact').textContent = pausing
    ? 'New evaluations, lease grants, ticket issuance/claims, and reservation consumption are rejected.'
    : 'Resume restores consideration only; later effects still require matching lease, ticket, and readback.';
  document.getElementById('preview-duration-impact').textContent = pausing
    ? 'Pause persists until a separate exact resume. Displayed expiry applies only to this preview.'
    : 'Resume persists until a separate exact pause. Displayed expiry applies only to this preview.';
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

function requestId() {
  return `req-${crypto.randomUUID().replaceAll('-', '')}`;
}

async function sha256Hex(value) {
  const bytes = new TextEncoder().encode(value);
  const digest = await crypto.subtle.digest('SHA-256', bytes);
  return [...new Uint8Array(digest)].map((item) => item.toString(16).padStart(2, '0')).join('');
}

async function freshOwnerIdToken(previousDigest = null) {
  for (let attempt = 0; attempt < 3; attempt += 1) {
    const idToken = await state.user.getIdToken(true);
    const digest = await sha256Hex(idToken);
    if (!previousDigest || digest !== previousDigest) return { idToken, digest };
    await new Promise((resolve) => window.setTimeout(resolve, 1100));
  }
  throw new Error('OWNER_AUTH_TOKEN_NOT_ROTATED');
}

async function createRequest(kind, fields = {}) {
  if (!state.user) throw new Error('OWNER_AUTHENTICATION_REQUIRED');
  const id = requestId();
  const authProof = await freshOwnerIdToken(
    kind === 'APPLY' ? state.previewAuthTokenSha256 : null,
  );
  const payload = {
    schemaVersion: REQUEST_SCHEMA,
    requestId: id,
    kind,
    action: CONTROL_ACTION,
    capability: CONTROL_CAPABILITY,
    active: Boolean(fields.active),
    ownerUid: state.user.uid,
    ownerEmail: state.user.email,
    idToken: authProof.idToken,
    state: 'PENDING',
    createdAt: serverTimestamp(),
  };
  if (kind === 'APPLY') {
    payload.parentRequestId = fields.parentRequestId;
    payload.previewSha256 = fields.previewSha256;
  }
  await setDoc(doc(db, 'cct_control_requests', id), payload);
  return { id, authTokenSha256: authProof.digest };
}

function waitForReceipt(id) {
  return new Promise((resolve, reject) => {
    let settled = false;
    const timer = window.setTimeout(() => {
      if (settled) return;
      settled = true;
      unsubscribe();
      reject(new Error('BRIDGE_RECEIPT_TIMEOUT'));
    }, RECEIPT_TIMEOUT_MS);
    const unsubscribe = onSnapshot(
      doc(db, 'cct_control_receipts', id),
      (snapshot) => {
        if (settled || !snapshot.exists()) return;
        settled = true;
        window.clearTimeout(timer);
        unsubscribe();
        const receipt = snapshot.data();
        if (receipt.status === 'ERROR') reject(new Error(receipt.reasonCode || 'BRIDGE_REQUEST_DENIED'));
        else resolve(receipt);
      },
      () => {
        if (settled) return;
        settled = true;
        window.clearTimeout(timer);
        unsubscribe();
        reject(new Error('BRIDGE_RECEIPT_UNAVAILABLE'));
      },
    );
  });
}

async function draftPermissionChange(row) {
  if (!state.snapshot || !availableControls(state.snapshot).bridge_online) {
    setControlMessage('Preview blocked: a fresh, online bridge snapshot is required.', true);
    return;
  }
  setControlMessage(`Requesting zero-mutation preview for ${row.name}…`);
  try {
    const request = await createRequest('PREVIEW', { active: row.administrative_active === false });
    const receipt = await waitForReceipt(request.id);
    if (receipt.status !== 'PREVIEW_READY' || !receipt.payload?.preview) throw new Error('BRIDGE_PREVIEW_INVALID');
    if (receipt.authTokenSha256 !== request.authTokenSha256) throw new Error('BRIDGE_AUTH_PROOF_MISMATCH');
    state.previewRequestId = request.id;
    state.previewAuthTokenSha256 = receipt.authTokenSha256;
    openPreviewDialog(receipt.payload.preview);
    setControlMessage('Preview verified by local host. Canonical state unchanged.');
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
    scope.append(node('strong', '', row.scopes?.[0] || 'No scope'), node('small', '', row.verifier_id));
    const lease = document.createElement('td');
    lease.append(node('strong', '', `${row.active_lease_count} active`), node('small', '', row.next_expiry || 'No active expiry'));
    const budget = document.createElement('td');
    budget.append(node('strong', '', `${number(row.remaining_actions)} actions`), node('small', '', `${number(row.remaining_bytes)} bytes`));
    const control = document.createElement('td');
    const supported = Boolean(controls?.installed && controls?.bridge_online && row.name === controls.capability);
    const ready = supported && row.control_state === 'READY';
    const controlActive = row.administrative_active !== false;
    const button = node('button', 'button secondary', controlActive ? 'Preview pause' : 'Preview resume');
    button.type = 'button';
    button.disabled = !ready;
    button.dataset.mutation = 'configured-intent';
    button.title = ready ? 'Request deterministic zero-mutation preview.' : 'Local host bridge unavailable or control out of scope.';
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
  rows.forEach((row) => grid.append(dataCard(row.target_id, row.route, row.state, [
    ['Authority', row.execution_authority_granted ? 'Granted' : 'Not granted'],
    ['Last change', row.last_changed_at],
    ['Receipt', shortId(row.last_event_id)],
  ])));
}

function renderAutomations(rows) {
  const grid = document.getElementById('automation-grid');
  clear(grid);
  rows.forEach((row) => grid.append(dataCard(row.label, row.id, row.state, [
    ['Observed', number(row.observed_events)],
    ['Runs', number(row.runs)],
    ['Verified / failed', `${number(row.verified_runs)} / ${number(row.failed_runs)}`],
  ])));
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

function snapshotIsFresh(snapshot) {
  const age = Date.now() - new Date(snapshot?.generated_at).valueOf();
  return Number.isFinite(age) && age >= -60_000 && age <= 120_000;
}

function availableControls(snapshot) {
  return { ...snapshot.controls, bridge_online: Boolean(snapshot.controls?.bridge_online)
    && !state.snapshotFromCache && navigator.onLine !== false && snapshotIsFresh(snapshot) };
}

function renderControlSession(controls) {
  const online = Boolean(controls?.bridge_online);
  document.getElementById('mode-label').textContent = online ? 'HOST BRIDGE ONLINE' : 'HOST BRIDGE OFFLINE';
  document.getElementById('mode-detail').textContent = online ? 'Preview + confirmed local apply · separate from workspace intent' : 'Read-only projection · bridge offline or snapshot not fresh';
  document.getElementById('session-state').textContent = online
    ? `Authenticated as ${state.user.email}; local bridge ${shortId(controls.bridge_instance_id)}.`
    : `Authenticated as ${state.user.email}; control requests disabled.`;
  setControlMessage(online
    ? 'Owner identity verified. Every mutation requires local preview and canonical readback.'
    : 'No mutation can apply while local host bridge is offline.', !online);
}

function render(snapshot) {
  if (!snapshot || snapshot.schema_version !== 'cct.admin_dashboard.snapshot.v1') throw new Error('DASHBOARD_SNAPSHOT_INVALID');
  state.snapshot = snapshot;
  renderOutcome(snapshot);
  const controls = availableControls(snapshot);
  renderControlSession(controls);
  renderPermissions(Array.isArray(snapshot.permissions) ? snapshot.permissions : [], controls);
  renderAccess(Array.isArray(snapshot.access) ? snapshot.access : []);
  renderAutomations(Array.isArray(snapshot.automations) ? snapshot.automations : []);
  renderApprovals(Array.isArray(snapshot.approvals) ? snapshot.approvals : []);
  renderAudit(snapshot.audit);
  renderEmergency(snapshot.emergency);
  const generated = new Date(snapshot.generated_at);
  const freshness = document.getElementById('freshness');
  const source = state.snapshotFromCache ? 'Cached' : snapshotIsFresh(snapshot) ? 'Recent' : 'Stale';
  freshness.textContent = `${source} bridge snapshot · ${Number.isNaN(generated.valueOf()) ? 'unknown age' : generated.toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' })}`;
  freshness.title = snapshot.generated_at;
  document.getElementById('schema-version').textContent = `${snapshot.schema_version} · ${snapshot.mode}`;
}

function consumeDashboardDocument(documentSnapshot) {
  if (!state.user) return;
  const loading = document.getElementById('loading');
  const error = document.getElementById('error');
  loading.hidden = false;
  error.hidden = true;
  if (!documentSnapshot.exists()) {
    state.snapshot = null;
    state.workspace?.setSnapshot(null);
    loading.textContent = 'Waiting for first local bridge projection…';
    return;
  }
  const envelope = documentSnapshot.data();
  if (envelope.schemaVersion !== DASHBOARD_SCHEMA || envelope.ownerEmail !== state.user.email || !envelope.snapshot) {
    error.textContent = 'Dashboard unavailable: FIREBASE_DASHBOARD_ENVELOPE_INVALID';
    error.hidden = false;
    loading.hidden = true;
    return;
  }
  if (envelope.ownerUid && envelope.ownerUid !== state.user.uid) {
    error.textContent = 'Dashboard unavailable: FIREBASE_OWNER_UID_MISMATCH';
    error.hidden = false;
    loading.hidden = true;
    return;
  }
  try {
    state.snapshotFromCache = Boolean(documentSnapshot.metadata.fromCache);
    render(envelope.snapshot);
    state.workspace?.setSnapshot(envelope.snapshot, { fromCache: state.snapshotFromCache });
    loading.hidden = true;
  } catch (failure) {
    error.textContent = `Dashboard unavailable: ${failure.message}`;
    error.hidden = false;
    loading.hidden = true;
  }
}

function startSnapshotListener() {
  if (state.unsubscribeSnapshot) state.unsubscribeSnapshot();
  state.unsubscribeSnapshot = onSnapshot(
    doc(db, 'cct_dashboard', 'current'),
    { includeMetadataChanges: true },
    consumeDashboardDocument,
    () => {
      const error = document.getElementById('error');
      error.textContent = 'Dashboard unavailable: FIRESTORE_READ_DENIED';
      error.hidden = false;
      document.getElementById('loading').hidden = true;
    },
  );
}

async function refresh() {
  if (!state.user) return;
  await state.executor?.refresh();
  await state.workspace?.refresh();
  try {
    consumeDashboardDocument(await getDoc(doc(db, 'cct_dashboard', 'current')));
  } catch (_failure) {
    const error = document.getElementById('error');
    error.textContent = 'Dashboard unavailable: FIRESTORE_READ_DENIED';
    error.hidden = false;
  }
}

async function confirmAndApply() {
  if (!state.preview || !state.previewRequestId) return;
  if (!state.snapshot || !availableControls(state.snapshot).bridge_online) {
    document.getElementById('control-dialog-result').textContent = 'Apply blocked: reconnect and refresh the bridge snapshot.';
    return;
  }
  const button = document.getElementById('confirm-apply');
  const result = document.getElementById('control-dialog-result');
  button.disabled = true;
  result.textContent = 'Recording owner-confirmed request…';
  result.dataset.state = 'working';
  try {
    const request = await createRequest('APPLY', {
      active: state.preview.after.active,
      parentRequestId: state.previewRequestId,
      previewSha256: state.preview.preview_sha256,
    });
    result.textContent = 'Local host apply and canonical readback running…';
    const receipt = await waitForReceipt(request.id);
    if (receipt.authTokenSha256 !== request.authTokenSha256) throw new Error('BRIDGE_AUTH_PROOF_MISMATCH');
    const applied = receipt.payload?.result;
    if (receipt.status !== 'APPLY_VERIFIED' || !applied || applied.status !== 'VERIFIED') throw new Error('BRIDGE_APPLY_INVALID');
    result.textContent = `${applied.status}: ${applied.capability} is ${applied.active ? 'active' : 'paused'} at control revision ${applied.control_revision}.`;
    result.dataset.state = 'ok';
    setControlMessage(`${applied.status}: canonical readback matched; external effects ${applied.external_effects}.`);
    state.preview = null;
    state.previewRequestId = null;
    state.previewAuthTokenSha256 = null;
    await refresh();
    window.setTimeout(() => document.getElementById('control-dialog').close(), 900);
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

document.getElementById('sign-in').addEventListener('click', async () => {
  authStatus('Opening Google owner verification…');
  try {
    await signInWithPopup(auth, provider);
  } catch (error) {
    authStatus(`Sign-in blocked: ${boundedAuthError(error)}`, true);
  }
});
document.getElementById('sign-out').addEventListener('click', () => signOut(auth));
document.getElementById('refresh').addEventListener('click', refresh);
document.getElementById('inspect-failure').addEventListener('click', () => document.getElementById('audit').scrollIntoView({ behavior: 'smooth', block: 'start' }));
document.getElementById('confirm-apply').addEventListener('click', confirmAndApply);
document.getElementById('cancel-control').addEventListener('click', () => {
  state.preview = null;
  state.previewRequestId = null;
  state.previewAuthTokenSha256 = null;
  document.getElementById('control-dialog').close();
});

await setPersistence(auth, browserLocalPersistence);
onAuthStateChanged(auth, async (user) => {
  const generation = ++state.authGeneration;
  state.executor?.stop();
  state.executor = null;
  state.workspace?.stop();
  state.workspace = null;
  const controlDialog = document.getElementById('control-dialog');
  if (controlDialog.open) controlDialog.close();
  if (state.unsubscribeSnapshot) {
    state.unsubscribeSnapshot();
    state.unsubscribeSnapshot = null;
  }
  state.user = null;
  state.snapshot = null;
  state.preview = null;
  state.previewRequestId = null;
  state.previewAuthTokenSha256 = null;
  if (!user) {
    showGate('Only the configured owner account is accepted.');
    return;
  }
  try {
    const isOwner = await verifyOwner(user);
    if (generation !== state.authGeneration) return;
    if (!isOwner) {
      await signOut(auth);
      showGate('Access denied: exact verified Google owner required.', true);
      return;
    }
    state.user = user;
    showApp(user);
    state.executor = mountExecutor(db, user.uid, firebaseConfig.projectId);
    state.workspace = mountWorkspace(db, user.uid);
    startSnapshotListener();
  } catch (_failure) {
    await signOut(auth);
    showGate('Access denied: owner token verification failed.', true);
  }
});

// Expired or cached projections must never keep host controls looking live.
function refreshRuntimeAvailability() {
  if (!state.user || !state.snapshot) return;
  const message = document.getElementById('control-message');
  const previousMessage = message.textContent;
  const previousState = message.dataset.state;
  const previousMode = document.getElementById('mode-label').textContent;
  render(state.snapshot);
  if (previousMode === document.getElementById('mode-label').textContent) {
    message.textContent = previousMessage;
    message.dataset.state = previousState;
  }
}
window.setInterval(refreshRuntimeAvailability, 30_000);
window.addEventListener('offline', refreshRuntimeAvailability);
window.addEventListener('online', refreshRuntimeAvailability);
