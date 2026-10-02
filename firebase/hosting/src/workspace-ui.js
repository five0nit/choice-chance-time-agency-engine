import { mountDiscovery } from './discovery.js';
import { mountOwnerDelivery } from './owner-delivery.js';
import { mountOwnerBuilds } from './owner-builds.js';
import { createWorkspaceStore } from './workspace-store.js';
import { CHOICE_LABELS, PERMISSION_KEYS, defaultWorkspace, learningSummary, questionsFor, recommendationsFor } from './workspace-model.js';
import { firebaseConfig } from './firebase-config.js';
import { createOwnerConnection } from './owner-connection.js';
import { canReplyToMessage, validateRuntimeStatus } from './owner-connection-model.js';

const el = (tag, className, text) => {
  const item = document.createElement(tag);
  if (className) item.className = className;
  if (text !== undefined) item.textContent = text;
  return item;
};
const byId = (id) => document.getElementById(id);
const PERMISSION_COPY = {
  credentialAccess: ['Credential access', 'Request access through host-managed credentials. Never paste secrets here.'],
  webResearch: ['Web research', 'Request public-web research, not account access.'],
  workspaceRead: ['Read workspace', 'Request reading within a separately host-approved scope.'],
  workspaceWrite: ['Write workspace', 'Request changes within a separately host-approved scope.'],
  externalMessages: ['External messages', 'Request private owner messages. Third-party sends and publishing remain unavailable.'],
  payments: ['Payments & spending', 'Request spending authority. No payment method is connected here.'],
};

export function mountWorkspace(db, ownerUid) {
  let view = { workspace: defaultWorkspace(ownerUid), ready: false, busy: false, exists: false, verified: false, message: 'Reading your private workspace…', error: false };
  let snapshot = null;
  let cachedSnapshot = false;
  let showAllDecisions = false;
  let stopped = false;
  let discovery = null;
  let delivery = null;
  let builds = null;
  let restoreFocus = null;
  const disposers = [];
  const listen = (target, event, handler) => {
    target.addEventListener(event, handler);
    disposers.push(() => target.removeEventListener(event, handler));
  };
  const store = createWorkspaceStore(db, ownerUid, (next) => { view = next; render(); });
  let ownerView = { runtime: null, runtimeFromCache: true, messages: [], messagesFromCache: true, replies: {} };
  const messageRows = new Map();
  const workspaceContext = () => ({ workspaceRevision: view.workspace.revision, workspaceVerified: view.verified && view.exists && !view.busy });
  const connection = createOwnerConnection(db, ownerUid, firebaseConfig.projectId, workspaceContext, (next) => { ownerView = next; renderOwnerConnection(); });
  const ownerStatus = () => validateRuntimeStatus(ownerView.runtime, { ...workspaceContext(), ownerUid, projectId: firebaseConfig.projectId, fromCache: ownerView.runtimeFromCache || navigator.onLine === false, hasPendingWrites: ownerView.runtimePending });
  const canSave = () => view.ready && !view.busy && navigator.onLine !== false;
  const save = (action) => store.save(action);
  const button = (label, className, action, focusKey) => {
    const item = el('button', className, label);
    item.type = 'button';
    item.disabled = !canSave();
    if (focusKey) item.dataset.focus = focusKey;
    item.addEventListener('click', action);
    return item;
  };
  const source = (card) => el('span', `source-label ${card.source}`, card.sourceLabel);
  const rationale = (card) => {
    const details = el('details', 'why-details');
    details.append(el('summary', '', 'Why this is here'));
    const list = el('ul');
    card.reasons.forEach((reason) => list.append(el('li', '', reason)));
    details.append(list);
    return details;
  };

  function renderDecisions(cards) {
    const decisions = cards.filter((card) => card.kind !== 'goal');
    const pending = decisions.filter((card) => !card.feedback);
    const shown = showAllDecisions ? decisions : (pending.length ? pending.slice(0, 3) : decisions.slice(0, 3));
    byId('decision-count').textContent = `${pending.length} to consider`;
    byId('decision-toggle').textContent = showAllDecisions ? 'Show next three' : 'View all & feedback';
    const target = byId('decision-cards');
    target.replaceChildren();
    shown.forEach((card, index) => {
      const article = el('article', `decision-card ${card.source}`);
      const top = el('div', 'card-eyebrow');
      top.append(source(card), el('span', 'card-index', String(index + 1).padStart(2, '0')));
      article.append(top, el('h3', '', card.title), el('p', 'card-summary', card.summary), rationale(card));
      const response = el('div', 'decision-response', card.feedback ? `Recorded: ${card.feedback} · feedback only` : 'Your call. Feedback, not execution.');
      article.append(response);
      const actions = el('div', 'decision-actions');
      [['approve', 'Approve idea'], ['reject', 'Not for me'], ['later', 'Later']].forEach(([value, label]) => {
        const item = button(label, `button ${value === 'approve' ? 'primary' : 'secondary'} ${card.feedback === value ? 'selected' : ''}`, () => save({ type: 'decision', id: card.id, value }), `${card.id}-${value}`);
        item.setAttribute('aria-pressed', String(card.feedback === value));
        if (card.kind === 'approval' && value === 'approve') item.textContent = 'Support idea';
        actions.append(item);
      });
      article.append(actions);
      target.append(article);
    });
  }

  function renderIdeas(cards) {
    const goals = cards.filter((card) => card.kind === 'goal');
    const goalTarget = byId('workspace-goals');
    goalTarget.replaceChildren();
    const generated = snapshot?.generated_at ? new Date(snapshot.generated_at) : null;
    const age = generated && !Number.isNaN(generated.valueOf()) ? Date.now() - generated.valueOf() : null;
    const stale = age === null || age > 120_000 || age < -60_000;
    byId('workspace-snapshot-status').textContent = !snapshot ? 'No runtime snapshot received'
      : `${cachedSnapshot ? 'Cached' : stale ? 'Stale' : 'Recent'} snapshot · ${generated && !Number.isNaN(generated.valueOf()) ? generated.toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' }) : 'unknown age'}`;
    byId('workspace-snapshot-status').dataset.state = stale || cachedSnapshot ? 'stale' : 'recent';
    if (!goals.length) {
      const empty = el('div', 'goal-empty');
      empty.append(el('span', 'empty-mark', '↗'), el('strong', '', 'No CCT goals in the available snapshot.'), el('p', '', 'The ideas below are clearly labelled starting points, not invented runtime thoughts.'));
      goalTarget.append(empty);
    } else {
      goals.forEach((goal) => {
        const row = el('article', 'goal-row');
        const copy = el('div');
        copy.append(source(goal), el('h3', '', goal.title), el('p', '', goal.summary));
        row.append(el('span', 'goal-symbol', '↗'), copy, el('span', 'pill', goal.status || 'Unknown'));
        goalTarget.append(row);
      });
    }
    const ideas = byId('ranked-ideas');
    ideas.replaceChildren();
    cards.filter((card) => card.source === 'onboarding').slice(0, 4).forEach((card, index) => {
      const row = el('article', 'idea-row');
      const copy = el('div', 'idea-copy');
      copy.append(source(card), el('h3', '', card.title), el('p', '', card.reasons[0]));
      row.append(el('span', 'idea-rank', String(index + 1).padStart(2, '0')), copy);
      ideas.append(row);
    });
  }

  function renderQuestions(workspace) {
    const questions = questionsFor(workspace);
    const summary = learningSummary(workspace);
    const active = questions.find((question) => !question.answer);
    byId('question-progress').textContent = `${summary.answered} / ${summary.total} answered`;
    byId('learning-meter').value = summary.answered;
    byId('learning-meter').max = summary.total;
    byId('learning-state').textContent = workspace.learningEnabled ? 'Preference learning on' : 'Preference learning paused';
    byId('learning-enabled').checked = workspace.learningEnabled;
    byId('learning-enabled').disabled = !canSave();
    byId('learning-explanation').textContent = summary.explanation;
    const activeTarget = byId('active-question');
    activeTarget.replaceChildren();
    if (active) {
      activeTarget.append(el('p', 'question-context', workspace.learningEnabled ? active.reason : 'Learning is paused. You can record answers; they will not influence the board until enabled.'),
        el('h3', '', active.title), el('p', 'question-detail', active.detail));
      const choices = el('div', 'question-choices');
      active.options.forEach((option) => choices.append(button(option.label, 'choice-button', () => save({ type: 'answer', key: active.id, value: option.value }), `question-${active.id}-${option.value}`)));
      activeTarget.append(choices);
    } else {
      activeTarget.append(el('p', 'question-context', 'A useful starting profile'), el('h3', '', 'Less guessing. Better next steps.'), el('p', 'question-detail', 'All six preferences are recorded. Keep shaping the board with decision feedback, or revise any answer below.'));
    }
    const answers = byId('learned-answers');
    answers.replaceChildren();
    questions.forEach((question) => {
      const row = el('label', 'answer-row');
      row.append(el('span', '', question.id === 'nextStep' ? 'Next step' : question.id[0].toUpperCase() + question.id.slice(1)));
      const select = el('select');
      select.setAttribute('aria-label', question.title);
      select.dataset.focus = `edit-answer-${question.id}`;
      select.disabled = !canSave();
      const placeholder = el('option', '', 'Not answered');
      placeholder.value = '';
      placeholder.disabled = true;
      select.append(placeholder);
      question.options.forEach((option) => {
        const item = el('option', '', option.label);
        item.value = option.value;
        select.append(item);
      });
      select.value = question.answer;
      select.addEventListener('change', () => save({ type: 'answer', key: question.id, value: select.value }));
      row.append(select);
      answers.append(row);
    });
    byId('feedback-total').textContent = `${summary.feedbackCount} card responses retained`;
    byId('reset-learning').disabled = !canSave() || summary.answered === 0;
  }

  function renderPermissions(workspace) {
    const target = byId('workspace-permissions');
    target.replaceChildren();
    const enabled = PERMISSION_KEYS.filter((key) => workspace.permissions[key]).length;
    byId('permissions-count').textContent = `${enabled} / ${PERMISSION_KEYS.length} requested`;
    PERMISSION_KEYS.forEach((key) => {
      const row = el('label', 'permission-switch');
      const text = el('span', 'permission-copy');
      text.append(el('strong', '', PERMISSION_COPY[key][0]), el('small', '', PERMISSION_COPY[key][1]));
      const control = el('span', 'switch-control');
      const input = el('input', 'switch-input');
      input.type = 'checkbox';
      input.setAttribute('role', 'switch');
      input.setAttribute('aria-label', `Request ${PERMISSION_COPY[key][0].toLowerCase()}`);
      input.dataset.focus = `permission-${key}`;
      input.checked = workspace.permissions[key];
      input.disabled = !canSave();
      input.addEventListener('change', () => save({ type: 'permission', key, value: input.checked }));
      control.append(input, el('span', 'switch-track'));
      row.append(text, control);
      target.append(row);
    });
    const full = workspace.autonomyMode === 'full';
    byId('autonomy-switch').checked = full;
    byId('autonomy-switch').disabled = !canSave();
    byId('autonomy-requested').textContent = full ? 'Full autonomy requested' : 'Supervised by default';
    byId('autonomy-detail').textContent = full
      ? `${view.verified ? 'Explicit confirmation saved.' : 'Last available request; not freshly verified.'} Full mode can trigger the separate local delivery lane only within host-approved sandbox boundaries. Its actual capabilities and receipts are shown above; no extra permissions were enabled.`
      : 'CCT proposes; you decide. Changing this requires a separate, explicit confirmation.';
    renderOwnerConnection();
  }

  function renderOwnerConnection() {
    if (stopped) return;
    builds?.refresh();
    const status = ownerStatus();
    byId('workspace-runtime-state').textContent = status.state;
    byId('workspace-runtime-state').closest('.runtime-boundary').dataset.state = status.state;
    byId('workspace-runtime-detail').textContent = ownerView.runtimeError || status.detail;
    byId('policy-effective').textContent = status.state === 'CONNECTED'
      ? (status.effectivePolicy.ownerMessages ? 'Effective: private owner messages only' : 'Connected · owner messages disabled') : 'No effective owner messaging';
    byId('owner-policy-scope').textContent = 'This owner-messaging connection remains supervised. It does not authorize third-party sends, payments or delivery. The separate local delivery lane reports its own host-authorized scope above.';
    byId('owner-runtime-freshness').textContent = ownerView.runtime?.updatedAt
      ? `Host check: ${ownerView.runtime.updatedAt} · ${ownerView.runtimeFromCache ? 'cached' : 'server read'} · workspace revision ${ownerView.runtime.revision ?? 'unavailable'}`
      : 'Waiting for host-written owner-runtime evidence.';
    const requested = ownerView.runtime?.unsupportedPermissions;
    byId('owner-unsupported').textContent = Array.isArray(requested) && requested.length && status.state === 'CONNECTED'
      ? `Unsupported requests: ${requested.join(', ')}. No authority granted.` : '';
    byId('owner-messages-status').textContent = ownerView.messagesError || (ownerView.messagesFromCache
      ? 'Last available messages · connect to verify before replying.' : `${ownerView.messages.length} recent messages · server read`);
    byId('owner-messages-status').dataset.state = ownerView.messagesError ? 'error' : 'ok';
    const target = byId('owner-messages');
    byId('owner-messages-empty').hidden = ownerView.messages.length > 0;
    const ids = new Set(ownerView.messages.map((message) => message.messageId));
    for (const [id, row] of messageRows) if (!ids.has(id)) { row.article.remove(); messageRows.delete(id); }
    ownerView.messages.forEach((message, index) => {
      let row = messageRows.get(message.messageId);
      if (!row) {
        const article = el('article', 'owner-message');
        const heading = el('div', 'owner-message-heading');
        const kind = el('strong');
        const badge = el('span', 'pill');
        heading.append(kind, badge);
        const text = el('p', 'owner-message-text');
        const time = el('p', 'microcopy');
        const answer = el('p', 'owner-message-answer');
        const form = el('form', 'owner-reply-form');
        const label = el('label', '', 'Your answer');
        const input = el('textarea');
        input.id = `reply-${message.messageId}`;
        input.maxLength = 2000;
        input.rows = 3;
        input.required = true;
        input.dataset.focus = input.id;
        label.htmlFor = input.id;
        const submit = el('button', 'button primary', 'Send answer');
        submit.type = 'submit';
        const feedback = el('p', 'microcopy owner-reply-feedback');
        feedback.setAttribute('role', 'status');
        form.append(label, input, submit);
        form.addEventListener('submit', async (event) => {
          event.preventDefault();
          if (submit.disabled) return;
          if (await connection.reply(message.messageId, input.value)) input.value = '';
        });
        article.append(heading, text, time, answer, form, feedback);
        row = { article, kind, badge, text, time, answer, form, input, submit, feedback };
        messageRows.set(message.messageId, row);
      }
      row.kind.textContent = message.kind === 'ask' ? 'CCT asks you' : 'CCT update';
      row.badge.textContent = message.state;
      row.text.textContent = message.text;
      row.time.textContent = `${new Date(message.createdAt).toLocaleString()} · ${message.kind === 'ask' ? 'Answer by' : 'Expires'} ${new Date(message.expiresAt).toLocaleString()}`;
      row.answer.textContent = message.answer === null ? '' : `Your answer: ${message.answer}`;
      row.answer.hidden = message.answer === null;
      const reply = ownerView.replies[message.messageId];
      row.form.hidden = !canReplyToMessage(message) || reply?.verified === true;
      row.input.disabled = reply?.busy === true;
      row.submit.disabled = reply?.busy === true || ownerView.messagesFromCache || navigator.onLine === false
        || status.state !== 'CONNECTED' || !status.effectivePolicy.ownerMessages || message.revision !== ownerView.runtime?.revision || message.policySha256 !== ownerView.runtime?.policySha256;
      row.submit.textContent = reply?.busy ? 'Verifying answer…' : 'Send answer';
      row.feedback.textContent = reply?.message || (message.state === 'UNKNOWN' ? 'Delivery is uncertain. Do not assume this message was sent.' : (!row.form.hidden && row.submit.disabled ? 'Reply waits for a fresh, matching owner connection.' : ''));
      row.feedback.dataset.state = reply?.error ? 'error' : 'ok';
      // Keep existing textareas mounted: live snapshots must not erase drafts or caret position.
      if (target.children[index] !== row.article) target.insertBefore(row.article, target.children[index] || null);
    });
  }

  function render() {
    if (stopped) return;
    delivery?.setWorkspace(view);
    builds?.setWorkspace(view);
    const focused = document.activeElement?.dataset?.focus || restoreFocus;
    restoreFocus = view.busy ? focused : null;
    const workspace = view.workspace;
    byId('workspace-save-status').textContent = navigator.onLine === false ? 'Offline · changes cannot be saved. Showing last available settings.' : view.message;
    byId('workspace-save-status').dataset.state = view.error || navigator.onLine === false ? 'error' : view.busy ? 'working' : 'ok';
    byId('workspace-revision').textContent = view.exists ? `R${String(workspace.revision).padStart(3, '0')}` : 'UNSAVED';
    byId('workspace-save-label').textContent = view.busy ? 'Verifying save' : view.verified ? (view.exists ? 'Server verified' : 'Ready to personalise') : 'Awaiting connection';
    byId('confirm-autonomy').disabled = !canSave() || !byId('autonomy-acknowledge').checked;
    const summary = learningSummary(workspace);
    byId('focus-value').textContent = workspace.answers.focus ? CHOICE_LABELS[workspace.answers.focus] : 'Not set yet';
    byId('horizon-value').textContent = workspace.answers.horizon ? CHOICE_LABELS[workspace.answers.horizon] : 'Your call';
    byId('profile-value').textContent = `${summary.answered}/${summary.total}`;
    const cards = recommendationsFor(workspace, snapshot);
    renderDecisions(cards);
    renderIdeas(cards);
    renderQuestions(workspace);
    renderPermissions(workspace);
    discovery?.render();
    if (focused) {
      const target = [...document.querySelectorAll('[data-focus]')].find((item) => item.dataset.focus === focused);
      if (target && !target.disabled) target.focus({ preventScroll: true });
      else if (!view.busy && focused.startsWith('question-')) byId('active-question').focus({ preventScroll: true });
    }
  }

  listen(byId('decision-toggle'), 'click', () => { showAllDecisions = !showAllDecisions; render(); });
  listen(byId('learning-enabled'), 'change', (event) => save({ type: 'learning', value: event.target.checked }));
  listen(byId('reset-learning'), 'click', () => {
    if (window.confirm('Clear the six learned answers? Decision feedback, permissions, and autonomy will stay unchanged.')) save({ type: 'resetAnswers' });
  });
  const dialog = byId('autonomy-dialog');
  const closeDialog = () => {
    dialog.close();
    byId('autonomy-switch').focus({ preventScroll: true });
    byId('autonomy-acknowledge').checked = false;
    byId('confirm-autonomy').disabled = true;
    render();
  };
  listen(byId('autonomy-switch'), 'change', (event) => {
    const requested = event.target.checked;
    event.target.checked = view.workspace.autonomyMode === 'full';
    if (!requested) { save({ type: 'autonomy', value: 'supervised', confirmed: false }); return; }
    byId('autonomy-acknowledge').checked = false;
    byId('confirm-autonomy').disabled = true;
    dialog.showModal();
  });
  listen(byId('autonomy-acknowledge'), 'change', (event) => { byId('confirm-autonomy').disabled = !event.target.checked || !canSave(); });
  listen(byId('cancel-autonomy'), 'click', closeDialog);
  listen(dialog, 'cancel', () => { byId('autonomy-acknowledge').checked = false; byId('confirm-autonomy').disabled = true; });
  listen(byId('confirm-autonomy'), 'click', async () => {
    if (!byId('autonomy-acknowledge').checked || !canSave()) return;
    closeDialog();
    await save({ type: 'autonomy', value: 'full', confirmed: true });
  });
  listen(window, 'offline', render);
  const refresh = () => Promise.all([store.refresh(), connection.refresh(), discovery?.refresh(), builds?.refresh()]);
  listen(window, 'online', refresh);
  const freshnessTimer = window.setInterval(() => {
    if (snapshot) renderIdeas(recommendationsFor(view.workspace, snapshot));
    renderOwnerConnection();
  }, 10_000);
  discovery = mountDiscovery(db, ownerUid, () => view, (value) => save({ type: 'learning', value }));
  builds = mountOwnerBuilds(db, ownerUid, view, ownerStatus);
  delivery = mountOwnerDelivery(db, ownerUid, view, (value, metadata) => builds?.setDelivery(value, metadata));
  store.start();
  connection.start();
  return {
    setSnapshot(value, { fromCache = false } = {}) { snapshot = value; cachedSnapshot = fromCache; render(); },
    refresh,
    stop() {
      stopped = true;
      discovery?.stop();
      delivery?.stop();
      builds?.stop();
      store.stop();
      connection.stop();
      messageRows.clear();
      byId('owner-messages').replaceChildren();
      disposers.forEach((dispose) => dispose());
      window.clearInterval(freshnessTimer);
      if (dialog.open) dialog.close();
      ['decision-cards', 'workspace-goals', 'ranked-ideas', 'active-question', 'learned-answers', 'workspace-permissions'].forEach((id) => byId(id).replaceChildren());
    },
  };
}