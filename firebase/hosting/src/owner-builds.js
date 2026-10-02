import './owner-builds.css';
import { collection, doc, documentId, getDocFromServer, limit, onSnapshot, orderBy, query, runTransaction, serverTimestamp, startAfter, Timestamp, where } from 'firebase/firestore';
import { ACTIONS, CEILINGS, CONTINUATION_RESEARCH_LABEL, DISCOVERY_LABEL, PAGE_SIZE, TOOL_LABEL, authorityReason, continuationSummary, controlsPreview, downloadName, filterBuilds, requestPreview, requestReason, sameRequest, timeMillis, validBuild, validControls, validReceipt, validRequest, validStatus } from './owner-builds-model.js';

const node = (tag, text, className = '') => {
  const item = document.createElement(tag);
  if (text !== undefined) item.textContent = text;
  if (className) item.className = className;
  return item;
};
const button = (text, action) => {
  const item = node('button', text, 'button secondary');
  item.type = 'button'; item.addEventListener('click', action); return item;
};
const serverVerified = snapshot => !snapshot.metadata.fromCache && !snapshot.metadata.hasPendingWrites;
const json = value => JSON.stringify(value, null, 2);
const date = value => new Date(timeMillis(value)).toLocaleString();
const matchesControls = (actual, expected) => Object.entries(expected).every(([key, value]) => actual?.[key] === value);
const capsLabels = { maxDailyJobs: 'Jobs', maxDailyProviderCalls: 'Provider calls', maxDailyToolCalls: TOOL_LABEL };

// Read-only view: the caller forwards the existing delivery subscription. No
// writes, extra listener, inferred results or links built from private IDs.
export function renderOwnerContinuation(root, delivery, options = {}) {
  const view = continuationSummary(delivery, options);
  const expanded = Boolean(root.querySelector('[data-continuation-receipt]')?.open);
  root.replaceChildren();
  root.dataset.state = view.available ? 'recorded' : 'unavailable';
  const heading = node('h3', 'Automatic continuation'); heading.id = 'builds-continuation-title';
  root.setAttribute('aria-labelledby', heading.id);
  const status = node('p', view.label, 'builds-continuation-status');
  status.setAttribute('role', 'status'); status.setAttribute('aria-live', 'polite');
  root.append(heading, status);
  if (!view.available) {
    root.append(node('p', view.reason), node('p', 'No current objective, running work or successful improvement is inferred.', 'microcopy'));
  } else {
    root.append(node('p', 'Current objective', 'microcopy'), node('h4', view.objective));
    const steps = node('dl', undefined, 'builds-continuation-steps');
    for (const [key, label, text] of [['happened', 'What happened', view.happened],
      ['improved', 'What improved', view.improved], ['next', 'What comes next', view.nextAction]]) {
      const step = node('div'); step.dataset.continuationStep = key;
      step.append(node('dt', label), node('dd', text)); steps.append(step);
    }
    if (view.blocker) {
      const blocker = node('div', undefined, 'builds-continuation-blocker'); blocker.dataset.continuationStep = 'blocker';
      blocker.append(node('dt', 'What is blocking it'), node('dd', view.blocker)); steps.append(blocker);
    }
    root.append(steps);
    if (view.nextEligibleAt) {
      const next = node('p', `Earliest eligible attempt: ${date(view.nextEligibleAt)}. This is not a scheduled start or a promise of execution.`, 'microcopy');
      next.title = view.nextEligibleAt; root.append(next);
    }
    root.append(node('p', view.researchLabel, 'builds-continuation-research'),
      node('p', 'Verified fetch receipts mean public evidence was fetched, not that a build improved. Queued work has not necessarily run; build verification and outcomes remain separate.', 'microcopy'));
    const receipt = node('details'); receipt.dataset.continuationReceipt = ''; receipt.open = expanded;
    receipt.append(node('summary', 'Technical receipt · cycle, lineage, counters and timestamps'),
      node('pre', json(view.receipt), 'builds-text'));
    root.append(receipt);
  }
  root.append(node('p', CONTINUATION_RESEARCH_LABEL, 'microcopy'),
    node('p', 'Read-only host status. Existing delivery budgets, pause checks and owner authority still apply.', 'microcopy'));
  return view;
}

// Each live page is owner-scoped and bounded. If its cursor changes, discard
// subsequent pages rather than silently keeping a hole or duplicate boundary.
function subscribePages(db, uid, name, validate, changed) {
  const pages = [];
  let stopped = false;
  const current = () => ({
    rows: [...new Map(pages.flatMap(p => p.rows).map(row => [row.id, row.value])).values()],
    verified: pages.length > 0 && pages.every(p => p.verified),
    error: pages.map(p => p.error).filter(Boolean).join(' '),
    more: Boolean(pages.at(-1)?.full), loading: pages.some(p => p.loading),
  });
  const emit = () => { if (!stopped) changed(current()); };
  function add(after) {
    const page = { rows: [], verified: false, error: '', full: false, loading: true, cursor: null, stop() {} };
    pages.push(page);
    const constraints = [where('ownerUid', '==', uid), orderBy(documentId())];
    if (after) constraints.push(startAfter(after));
    constraints.push(limit(PAGE_SIZE));
    page.stop = onSnapshot(query(collection(db, name), ...constraints), { includeMetadataChanges: true }, snapshot => {
      if (stopped || !pages.includes(page)) return;
      const cursor = snapshot.docs.at(-1)?.id || null;
      if (page.cursor !== null && cursor !== page.cursor) {
        pages.splice(pages.indexOf(page) + 1).forEach(p => p.stop());
      }
      page.cursor = cursor; page.full = snapshot.size === PAGE_SIZE; page.loading = false;
      const valid = snapshot.docs.every(d => validate(d.data(), uid, d.id));
      page.verified = serverVerified(snapshot) && valid;
      page.error = !valid ? `${name}: invalid owner projection rejected.` : snapshot.metadata.hasPendingWrites ? `${name}: uncommitted local data ignored.` : '';
      page.rows = valid && !snapshot.metadata.hasPendingWrites ? snapshot.docs.map(d => ({ id: d.id, value: d.data() })) : [];
      emit();
    }, () => {
      if (stopped) return;
      page.loading = false; page.verified = false; page.error = `${name}: subscription unavailable. Reconnect to verify.`; emit();
    });
    emit();
  }
  add(null);
  return {
    more() { const last = pages.at(-1); if (last?.full && last.verified && !last.loading) add(last.cursor); },
    stop() { stopped = true; pages.forEach(p => p.stop()); pages.length = 0; },
  };
}

export function mountOwnerBuilds(db, uid, initialWorkspace, getRuntime = () => null) {
  const root = document.getElementById('owner-builds');
  if (!root || !uid) return { setWorkspace() {}, setDelivery() {}, refresh() {}, stop() {} };
  let closed = false, workspace = initialWorkspace, controls = null, status = null;
  let delivery = null, deliveryMetadata = { fromCache: true, hasPendingWrites: false }, deliveryError = '', continuationKey = '';
  let verified = { controls: false, status: false, builds: false };
  let selectedId = '', detailKey = '', message = '', busy = false, pending = null;
  let preview = null, previewKind = '', previewAt = 0, budgetDirty = false;
  const errors = {}, disposers = [], objectUrls = new Set(), extraBuilds = new Map();
  const streams = {}, library = {};
  const storageKey = `cct-owner-builds-pending-v1:${uid}`;
  const controlRef = doc(db, 'cct_owner_build_controls', 'current');
  const statusRef = doc(db, 'cct_owner_build_controls_status', 'current');
  const context = () => ({ uid, workspace, controls, status, verified, offline: navigator.onLine === false });
  const runtimeReason = () => getRuntime()?.state === 'CONNECTED' ? '' : 'A fresh, matching owner-runtime connection is required. Owner messaging does not itself authorize delivery.';
  const blocked = () => closed ? 'Owner session ended.' : runtimeReason() || authorityReason(context());
  const allBuilds = () => [...new Map([...extraBuilds.values(), ...(library.builds?.rows || [])].map(b => [b.buildId, b])).values()];
  const selected = () => allBuilds().find(b => b.buildId === selectedId);
  const listen = (target, type, handler) => { target.addEventListener(type, handler); disposers.push(() => target.removeEventListener(type, handler)); };
  const report = text => { message = text; renderStatus(); };
  const assertActive = () => { const reason = blocked(); if (reason) throw new Error(reason); };

  root.replaceChildren();
  const heading = node('h2', 'Autonomous builds.'); heading.id = 'owner-builds-title';
  const connection = node('p', '', 'discovery-status'); connection.setAttribute('role', 'status');
  const feedback = node('p', '', 'builds-feedback'); feedback.setAttribute('role', 'status');
  const continuation = node('section', undefined, 'builds-continuation'); continuation.id = 'builds-continuation';
  const usage = node('div', undefined, 'builds-usage');
  const budgetForm = node('form', undefined, 'builds-form');
  const inputs = {};
  for (const [key, ceiling] of Object.entries(CEILINGS)) {
    const label = node('label', capsLabels[key]);
    const input = node('input'); input.type = 'number'; input.min = '1'; input.max = String(ceiling); input.step = '1';
    input.name = key; input.required = true; input.value = String({ maxDailyJobs: 1, maxDailyProviderCalls: 12, maxDailyToolCalls: 4 }[key]);
    inputs[key] = input; input.addEventListener('input', () => { budgetDirty = true; }); label.append(input); budgetForm.append(label);
  }
  const budgetPreview = button('Preview budget change', () => {}); budgetPreview.type = 'submit'; budgetForm.append(budgetPreview);
  const search = node('input'); search.type = 'search'; search.placeholder = 'Search title, purpose or build ID'; search.setAttribute('aria-label', 'Search builds');
  const archive = node('input'); archive.type = 'checkbox';
  const archiveLabel = node('label', 'Show archived'); archiveLabel.prepend(archive);
  const resume = button('Reconcile unfinished confirmation', () => openPending()); resume.hidden = true;
  const toolbar = node('div', undefined, 'builds-toolbar'); toolbar.append(search, archiveLabel, resume);
  const list = node('div', undefined, 'builds-list');
  const moreBuilds = button('Load more builds', () => streams.builds.more());
  const inspector = node('article', undefined, 'builds-inspector');
  const requests = node('div', undefined, 'builds-requests');
  const moreRequests = button('Load more requests', () => streams.requests.more());
  const moreReceipts = button('Load more host receipts', () => streams.receipts.more());
  root.append(node('p', 'PRIVATE ARTIFACT LIBRARY', 'section-kicker'), heading,
    node('p', 'Saved versions, exact verification receipts and owner-confirmed follow-up work. Files are plain text only; nothing in this library is executed.'),
    continuation, connection, feedback, node('h3', 'Rolling 24-hour delivery budgets'),
    node('p', 'Provider calls are tool-free delivery model requests. Tool calls count bounded sandbox verification dispatches tracked since the Builds upgrade, NOT generic Hermes tools, network requests, tests within a sandbox, or Firebase sync reads. Legacy artifacts may show zero because their earlier dispatches were not counted; zero is not proof that no checks ran. Changing a limit retains charged usage; host authority and pause checks still apply.', 'microcopy'),
    usage, budgetForm, toolbar, list, moreBuilds, inspector, node('h3', 'Follow-up requests and host receipts'), requests, moreRequests, moreReceipts);

  const dialog = node('dialog', undefined, 'control-dialog builds-dialog');
  dialog.setAttribute('aria-labelledby', 'builds-confirm-title');
  const dialogTitle = node('h2', 'Confirm exact intent'); dialogTitle.id = 'builds-confirm-title';
  const previewText = node('pre', '', 'builds-text');
  const previewNote = node('p', '', 'microcopy');
  const confirm = button('Confirm and save', () => commit());
  const cancel = button('Cancel preview', () => { if (!busy) dialog.close(); });
  dialog.append(dialogTitle, previewNote, previewText, confirm, cancel); root.append(dialog);
  listen(dialog, 'cancel', event => { if (busy) event.preventDefault(); });
  listen(search, 'input', renderList); listen(archive, 'change', renderList);
  listen(budgetForm, 'submit', event => {
    event.preventDefault();
    try { assertActive(); if (pending || busy) throw new Error('Reconcile the unfinished confirmation first.');
      openPreview('controls', controlsPreview(context(), Object.fromEntries(Object.entries(inputs).map(([k, input]) => [k, Number(input.value)]))));
    } catch (error) { report(error.message); }
  });

  function openPreview(kind, payload) {
    previewKind = kind; preview = payload; previewAt = Date.now();
    dialogTitle.textContent = kind === 'controls' ? 'Confirm delivery budget intent' : `Confirm ${payload.action} request`;
    previewText.textContent = json(payload);
    previewNote.textContent = kind === 'controls' ? 'updatedAt is assigned by the server. This saves requested limits, not applied limits. Existing usage is retained.'
      : `${payload.action === 'discover' ? DISCOVERY_LABEL + '. ' : ''}${['archive', 'restore'].includes(payload.action) ? 'Reversible organization only; files and history are retained. ' : 'A separate durable host worker performs acceptance, bounded work and review. '}createdAt is assigned by the server. Expiry limits initial acceptance only; accepted work waiting for budget does not expire. Original artifacts remain unchanged. Review the exact parent digest, instructions, caps and expiry below.`;
    if (!dialog.open) dialog.showModal(); renderStatus();
  }
  function openPending() { if (pending) { openPreview(pending.kind, Object.freeze(pending.payload)); previewAt = pending.previewAt; renderStatus(); } }
  function persistPending(value) {
    // A durable nonce precedes any write: network ambiguity never gets a new ID.
    if (value) sessionStorage.setItem(storageKey, JSON.stringify(value)); else sessionStorage.removeItem(storageKey);
    pending = value;
  }
  try {
    const saved = JSON.parse(sessionStorage.getItem(storageKey) || 'null');
    if (saved?.payload?.ownerUid === uid && ['controls', 'request'].includes(saved.kind)
      && (saved.kind === 'controls' ? validControls({ ...saved.payload, updatedAt: new Date().toISOString() }, uid)
        : validRequest({ ...saved.payload, createdAt: new Date().toISOString() }, uid))) pending = saved;
  } catch { message = 'Browser confirmation storage is unavailable. Writes require a retained nonce.'; }

  async function reconcile(item) {
    const ref = item.kind === 'controls' ? controlRef : doc(db, 'cct_owner_build_requests', item.payload.requestId);
    const snapshot = await getDocFromServer(ref);
    if (closed) throw new Error('Owner session ended.');
    if (!serverVerified(snapshot)) throw new Error('Server readback is not verified.');
    const notCommitted = () => {
      if (Date.now() - item.previewAt > 180000) {
        persistPending(null); preview = null; dialog.close();
        throw new Error('Server readback found no matching committed intent and this preview expired. Review a fresh preview.');
      }
      return false;
    };
    if (!snapshot.exists()) return notCommitted();
    const actual = snapshot.data();
    const match = item.kind === 'controls' ? validControls(actual, uid) && matchesControls(actual, item.payload)
      : validRequest(actual, uid, item.payload.requestId) && sameRequest(actual, item.payload);
    if (match) {
      persistPending(null); preview = null; dialog.close();
      report(item.kind === 'controls' ? `Budget intent revision ${actual.revision} server-verified. Wait for separate host-applied readback.`
        : `Request ${actual.requestId} server-verified. Submission is not acceptance or completion; inspect its host receipt.`);
      return true;
    }
    if (item.kind === 'controls' && validControls(actual, uid) && actual.revision < item.payload.revision) return notCommitted();
    // No overwrite: a different transaction won, or the intended revision was superseded.
    persistPending(null); preview = null; dialog.close();
    throw new Error('Server target differs from this confirmation. It was not overwritten. Review current state and host receipts before making another request.');
  }
  async function commit() {
    if (busy || !preview || closed) return;
    busy = true; renderStatus();
    try {
      let item = pending;
      if (item && await reconcile(item)) return;
      assertActive();
      if (Date.now() - previewAt > 180000) throw new Error('Preview expired. Reconcile any saved intent, then review a fresh preview.');
      item ||= { kind: previewKind, payload: preview, previewAt };
      const payload = item.payload;
      if (item.kind === 'controls') {
        const fresh = controlsPreview(context(), payload);
        if (!matchesControls(fresh, payload)) throw new Error('Budget revision changed. Cancel and preview again.');
      } else {
        const reason = requestReason(context(), allBuilds().find(b => b.buildId === payload.parentBuildId), payload.action);
        if (reason) throw new Error(reason);
        if (timeMillis(payload.expiresAt) <= Date.now()) throw new Error('Request expiry elapsed.');
      }
      persistPending(item);
      await runTransaction(db, async transaction => {
        assertActive();
        if (Date.now() - previewAt > 180000) throw new Error('Preview expired during transaction.');
        const target = item.kind === 'controls' ? controlRef : doc(db, 'cct_owner_build_requests', payload.requestId);
        const [controlSnap, statusSnap, targetSnap] = await Promise.all([
          transaction.get(controlRef), transaction.get(statusRef), transaction.get(target),
        ]);
        const actualControls = controlSnap.exists() ? controlSnap.data() : null;
        const actualStatus = statusSnap.exists() ? statusSnap.data() : null;
        const ctx = { ...context(), controls: actualControls, status: actualStatus,
          verified: { ...verified, controls: true, status: true } };
        const reason = runtimeReason() || authorityReason(ctx); if (reason) throw new Error(reason);
        if (item.kind === 'controls') {
          if (targetSnap.exists() && matchesControls(targetSnap.data(), payload)) return;
          const fresh = controlsPreview(ctx, payload);
          if (!matchesControls(fresh, payload)) throw new Error('Concurrent budget edit. Preview a fresh revision.');
          assertActive(); transaction.set(target, { ...payload, updatedAt: serverTimestamp() });
        } else {
          if (targetSnap.exists()) {
            if (validRequest(targetSnap.data(), uid, payload.requestId) && sameRequest(targetSnap.data(), payload)) return;
            throw new Error('Request ID already exists with a different payload; never overwritten.');
          }
          const parentSnap = await transaction.get(doc(db, 'cct_owner_builds', payload.parentBuildId));
          const parent = parentSnap.exists() ? parentSnap.data() : null;
          const reason = requestReason({ ...ctx, verified: { ...ctx.verified, builds: true } }, parent, payload.action);
          if (reason) throw new Error(reason);
          if (parent.bundleDigest !== payload.parentDigest || payload.controlRevision !== (actualControls?.revision || 0)) throw new Error('Parent digest or applied budget revision changed. Preview again.');
          if (payload.maxProviderCalls > actualStatus.effective.maxDailyProviderCalls || payload.maxToolCalls > actualStatus.effective.maxDailyToolCalls) throw new Error('Request exceeds applied budgets.');
          assertActive();
          // Transaction reads existence first. Rules permit create only, never updates.
          transaction.set(target, { ...payload, createdAt: serverTimestamp(), expiresAt: Timestamp.fromMillis(timeMillis(payload.expiresAt)) });
        }
      });
      if (!await reconcile(item)) throw new Error('Write not yet visible at the server.');
    } catch (error) {
      if (!closed) report(`${error.message}${pending ? ' Confirmation retained. Reconcile this exact target before trying new work.' : ''}`);
    } finally { busy = false; if (!closed) renderStatus(); }
  }

  function renderStatus() {
    if (closed) return;
    const continuationOptions = { uid, ...deliveryMetadata, error: deliveryError, offline: navigator.onLine === false };
    const nextKey = json(continuationSummary(delivery, continuationOptions));
    if (nextKey !== continuationKey) {
      continuationKey = nextKey; renderOwnerContinuation(continuation, delivery, continuationOptions);
    }
    const reason = blocked();
    connection.textContent = reason || 'Fresh owner and host budget readback. Delivery remains separately host-authorized.';
    connection.dataset.state = reason ? 'attention' : 'ok';
    feedback.textContent = [message, ...Object.values(errors)].filter(Boolean).join(' ');
    budgetPreview.disabled = Boolean(reason || busy || pending);
    for (const input of Object.values(inputs)) input.disabled = Boolean(reason || busy || pending);
    resume.hidden = !pending; resume.disabled = busy;
    confirm.disabled = busy || !preview || (!pending && Boolean(reason));
    confirm.textContent = busy ? 'Verifying server intent…' : pending ? 'Reconcile / retry exact confirmation' : 'Confirm and save';
    cancel.disabled = busy; cancel.textContent = pending ? 'Close · keep pending confirmation' : 'Cancel preview';
    usage.replaceChildren();
    if (!status) usage.append(node('p', 'No host budget or usage projection. Controls are unavailable.'));
    else {
      usage.append(node('p', `Intent revision: ${controls?.revision ?? 0} · Host requested: ${status.requestedRevision} · Host applied: ${status.effectiveRevision} · ${status.state} · ${verified.status ? 'server read' : 'unverified cache'} · ${date(status.updatedAt)}`));
      if (status.reason) usage.append(node('p', status.reason));
      for (const [key, label] of Object.entries(capsLabels)) {
        const usageKey = { maxDailyJobs: 'jobs', maxDailyProviderCalls: 'providerCalls', maxDailyToolCalls: 'toolCalls' }[key];
        usage.append(node('p', `${label}: ${status.usage[usageKey]} charged / ${status.effective[key]} host-applied · requested ${controls?.[key] ?? 'host default'} · ceiling ${status.ceilings[key]}`));
      }
    }
    for (const actionButton of inspector.querySelectorAll('[data-build-action]')) {
      actionButton.disabled = Boolean(reason || pending || busy || requestReason(context(), selected(), actionButton.dataset.buildAction));
    }
    const actionReason = inspector.querySelector('[data-action-reason]');
    if (actionReason) actionReason.textContent = reason || requestReason(context(), selected(), selected()?.archived ? 'restore' : 'upgrade') || 'Preview before confirming. Waiting requests retain their identity across worker restarts.';
  }
  function renderList() {
    if (closed) return;
    const values = filterBuilds(allBuilds(), search.value, archive.checked);
    list.replaceChildren(node('p', `${values.length} matching / ${allBuilds().length} loaded builds · ${library.builds?.verified ? 'server-verified' : 'not currently server-verified'}${library.builds?.more ? ' · more available; search covers loaded builds only' : ''}`));
    if (!values.length) list.append(node('p', library.builds?.loading ? 'Reading owner build projections…' : 'No matching saved build in the loaded pages.'));
    for (const build of values) {
      const card = button(build.title, () => { selectedId = build.buildId; detailKey = ''; renderInspector(); });
      card.className = 'builds-card'; card.setAttribute('aria-pressed', String(selectedId === build.buildId));
      card.append(node('span', `${build.status} · ${date(build.createdAt)}`), node('span', build.summary)); list.append(card);
    }
    moreBuilds.hidden = !library.builds?.more; moreBuilds.disabled = !library.builds?.verified || library.builds?.loading;
  }
  async function selectLineage(id) {
    if (allBuilds().some(b => b.buildId === id)) { selectedId = id; detailKey = ''; renderInspector(); return; }
    try {
      const snapshot = await getDocFromServer(doc(db, 'cct_owner_builds', id));
      if (closed) return;
      if (!snapshot.exists() || !serverVerified(snapshot) || !validBuild(snapshot.data(), uid, id)) throw new Error('Lineage build is not available as a verified owner projection.');
      extraBuilds.set(id, snapshot.data()); selectedId = id; detailKey = ''; renderList(); renderInspector();
    } catch (error) { if (!closed) report(error.message); }
  }
  function renderInspector() {
    if (closed) return;
    const build = selected();
    const key = json(build || null); if (key === detailKey) { renderStatus(); return; } detailKey = key;
    inspector.replaceChildren();
    if (!build) { inspector.append(node('p', 'Select a build to inspect files, lineage and follow-up actions.')); renderStatus(); return; }
    inspector.append(node('h3', build.title), node('p', build.summary), node('p', `${build.status} · ${build.reason || 'No waiting reason recorded.'}`),
      node('p', `Created ${date(build.createdAt)} · updated ${date(build.updatedAt)} · ${build.action}`), node('code', `Build ${build.buildId}\nBundle SHA-256 ${build.bundleDigest || 'not yet saved'}`));
    if (build.action === 'discover') inspector.append(node('p', DISCOVERY_LABEL));
    const lineage = node('div', undefined, 'builds-toolbar');
    if (build.parentBuildId) lineage.append(button(`Parent: ${build.parentBuildId}`, () => selectLineage(build.parentBuildId)));
    lineage.append(button(`Root: ${build.rootBuildId}`, () => selectLineage(build.rootBuildId)));
    allBuilds().filter(b => b.parentBuildId === build.buildId).forEach(child => lineage.append(button(`Child: ${child.title}`, () => selectLineage(child.buildId))));
    inspector.append(lineage, node('p', 'Lineage children shown from loaded pages. Parent and root links fetch exact owner records.', 'microcopy'));
    const evidence = node('details'); evidence.append(node('summary', 'Exact verification scope and charged usage'), node('pre', json({ verification: build.verification, usage: build.usage }), 'builds-text'));
    inspector.append(evidence, node('p', 'Model acceptance review is not arbitrary correctness, external outcome or revenue proof.', 'microcopy'), node('h4', 'Immutable files · plain text'));
    for (const file of build.files) {
      const details = node('details'); details.append(node('summary', file.path), node('code', `SHA-256 ${file.sha256}`));
      const text = node('pre', file.content, 'builds-text');
      const download = button('Download as text', () => {
        if (closed) return;
        const url = URL.createObjectURL(new Blob([file.content], { type: 'text/plain;charset=utf-8' })); objectUrls.add(url);
        const link = node('a'); link.href = url; link.download = downloadName(file.path); link.hidden = true;
        root.append(link); link.click(); link.remove();
        window.setTimeout(() => { URL.revokeObjectURL(url); objectUrls.delete(url); }, 1000);
      }); details.append(text, download); inspector.append(details);
    }
    if (!build.files.length) inspector.append(node('p', 'No files projected yet.'));
    const form = node('div', undefined, 'builds-form');
    const instructionsLabel = node('label', 'Direction / instructions (required for steer, maximum 2,000 characters)');
    const instructions = node('textarea'); instructions.rows = 4; instructions.maxLength = 2000; instructionsLabel.append(instructions);
    const provider = node('input'), tools = node('input');
    for (const [input, label, cap] of [[provider, 'Per-request provider calls', status?.effective.maxDailyProviderCalls || 12], [tools, 'Per-request sandbox dispatches', status?.effective.maxDailyToolCalls || 4]]) {
      input.type = 'number'; input.min = '1'; input.max = String(cap); input.step = '1'; input.value = String(cap);
      const field = node('label', label); field.append(input); form.append(field);
    }
    inspector.append(instructionsLabel, form, node('p', DISCOVERY_LABEL + '. Archive and restore retain all versions.', 'microcopy'));
    const actions = node('div', undefined, 'builds-toolbar');
    for (const action of ACTIONS) {
      const actionButton = button(`Preview ${action}`, () => {
        try {
          assertActive(); if (pending || busy) throw new Error('Reconcile the unfinished confirmation first.');
          const payload = requestPreview(context(), selected(), { action, instructions: instructions.value, maxProviderCalls: Number(provider.value), maxToolCalls: Number(tools.value) }, crypto.randomUUID());
          openPreview('request', payload);
        } catch (error) { report(error.message); }
      }); actionButton.dataset.buildAction = action; actions.append(actionButton);
    }
    const reason = node('p', '', 'microcopy'); reason.dataset.actionReason = '';
    inspector.append(actions, reason); renderStatus(); renderRequests();
  }
  function renderRequests() {
    if (closed) return;
    const receipts = new Map((library.receipts?.rows || []).map(r => [r.requestId, r]));
    const intents = new Map((library.requests?.rows || []).map(r => [r.requestId, r]));
    requests.replaceChildren(node('p', `${intents.size} requests / ${receipts.size} host receipts loaded. ${library.requests?.verified && library.receipts?.verified ? 'Server read.' : 'Unverified or reconnecting; do not infer acceptance.'}`));
    for (const id of new Set([...intents.keys(), ...receipts.keys()])) {
      const intent = intents.get(id), receipt = receipts.get(id), row = node('details');
      row.append(node('summary', `${intent?.action || receipt.action} · ${receipt?.state || 'SUBMITTED · awaiting host receipt'} · ${id}`));
      row.append(node('p', receipt?.reason || 'No host reason recorded.'), node('pre', json({ request: intent || 'Not loaded', hostReceipt: receipt || 'Not yet received' }), 'builds-text'));
      if (receipt?.buildId) row.append(button(`Open resulting build ${receipt.buildId}`, () => selectLineage(receipt.buildId)));
      requests.append(row);
    }
    moreRequests.hidden = !library.requests?.more; moreRequests.disabled = !library.requests?.verified || library.requests?.loading;
    moreReceipts.hidden = !library.receipts?.more; moreReceipts.disabled = !library.receipts?.verified || library.receipts?.loading;
  }
  function watch(ref, key, validate) {
    return onSnapshot(ref, { includeMetadataChanges: true }, snapshot => {
      if (closed) return;
      const value = snapshot.exists() ? snapshot.data() : null;
      const valid = value === null ? key === 'controls' : validate(value, uid);
      verified[key] = valid && serverVerified(snapshot);
      errors[key] = valid ? '' : `${key}: host identity or contract did not verify.`;
      if (key === 'controls') controls = valid && !snapshot.metadata.hasPendingWrites ? value : null;
      else status = valid && !snapshot.metadata.hasPendingWrites ? value : null;
      if (!budgetDirty && verified.controls && verified.status) {
        for (const [field, input] of Object.entries(inputs)) input.value = String(controls?.[field] ?? status?.effective[field] ?? input.value);
      }
      renderStatus();
    }, () => { if (!closed) { verified[key] = false; errors[key] = `${key}: readback unavailable.`; renderStatus(); } });
  }
  disposers.push(watch(controlRef, 'controls', validControls), watch(statusRef, 'status', validStatus));
  for (const [key, name, validate] of [['builds', 'cct_owner_builds', validBuild], ['requests', 'cct_owner_build_requests', validRequest], ['receipts', 'cct_owner_build_request_status', validReceipt]]) {
    streams[key] = subscribePages(db, uid, name, validate, value => {
      if (closed) return;
      library[key] = value; errors[key] = value.error;
      if (key === 'builds') { verified.builds = value.verified; renderList(); renderInspector(); }
      else renderRequests();
      renderStatus();
    });
  }
  listen(window, 'offline', renderStatus); listen(window, 'online', renderStatus);
  const timer = window.setInterval(renderStatus, 10000);
  renderList(); renderInspector(); renderRequests(); renderStatus();
  return {
    setWorkspace(next) { workspace = next; renderStatus(); },
    // Feed this from mountOwnerDelivery's existing owner-scoped readback.
    // Metadata defaults fail closed; a bare payload is not a server receipt.
    setDelivery(next, { fromCache = true, hasPendingWrites = false, error = '' } = {}) {
      if (closed) return;
      delivery = next; deliveryMetadata = { fromCache, hasPendingWrites }; deliveryError = error;
      renderStatus();
    },
    refresh() { renderStatus(); },
    stop() {
      closed = true; disposers.forEach(dispose => dispose()); Object.values(streams).forEach(stream => stream.stop());
      window.clearInterval(timer); objectUrls.forEach(url => URL.revokeObjectURL(url)); objectUrls.clear();
      if (dialog.open) dialog.close(); root.replaceChildren(); extraBuilds.clear();
      controls = status = workspace = preview = pending = delivery = null;
      deliveryMetadata = { fromCache: true, hasPendingWrites: false }; deliveryError = continuationKey = '';
    },
  };
}
