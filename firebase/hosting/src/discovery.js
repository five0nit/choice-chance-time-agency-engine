import './discovery.css';
import { mountOwnerWork, WORK_PHASES, workReason } from './owner-work.js';
import { doc, getDocFromServer, onSnapshot, serverTimestamp, setDoc } from 'firebase/firestore';
import { validateWorkspace } from './workspace-model.js';
import { answerFailureReason, answerStage, createAnswerDraftStore, createAnswerSaver, draftRetention } from './discovery-answer-save.js';

const byId = (id) => document.getElementById(id);
const text = (value, max = 4000) => typeof value === 'string' && value.trim().length > 0 && value.length <= max;
const questionId = (value) => typeof value === 'string' && /^q-[a-f0-9]{32}$/.test(value);
const sourceId = (value) => typeof value === 'string' && /^(q|msg)-[a-f0-9]{32}$/.test(value);
const list = (value, check, max = 100) => Array.isArray(value) && value.length <= max && value.every(check);
const timestamp = (value) => typeof value === 'string' && Number.isFinite(Date.parse(value));
const storedTimestamp = (value) => typeof value?.toMillis === 'function' && Number.isFinite(value.toMillis());
const staleDiscovery = (value) => !value || Date.now() - Date.parse(value.updatedAt) > 180_000 || Date.parse(value.updatedAt) - Date.now() > 60_000;
// Firestore map key order is not significant; array order and every value are.
const sameIdea = (a, b) => a === b || !!a && !!b && typeof a === 'object' && typeof b === 'object'
  && Array.isArray(a) === Array.isArray(b) && Object.keys(a).length === Object.keys(b).length
  && Object.keys(a).every(key => Object.hasOwn(b, key) && sameIdea(a[key], b[key]));
const promotionId = (turnId, ideaIndex) => `promote-${turnId.slice(2)}-${ideaIndex}`;

export function validWorkRequest(value, uid, target) {
  const fields = ['schemaVersion', 'ownerUid', 'conversationId', 'turnId', 'ideaIndex', 'idea', 'scope', 'state', 'createdAt'];
  return !!value && fields.every(key => Object.hasOwn(value, key))
    && Object.keys(value).every(key => fields.includes(key) || ['jobId', 'reason'].includes(key))
    && value.schemaVersion === 'cct.work_request.v1' && value.ownerUid === uid
    && value.conversationId === target.conversationId && value.turnId === target.turnId
    && value.ideaIndex === target.ideaIndex && sameIdea(value.idea, target.idea)
    && value.scope === 'PUBLIC_RESEARCH_PRIVATE_REPORT' && ['PENDING', 'RECEIVED', 'REJECTED'].includes(value.state)
    && storedTimestamp(value.createdAt)
    && (value.jobId === undefined || value.jobId === null || /^work-[a-f0-9]{24}$/.test(value.jobId))
    && (value.reason === undefined || typeof value.reason === 'string' && value.reason.length <= 2000);
}

export function validWorkReceipt(value, uid, target) {
  return !!value && value.schemaVersion === 'cct.work_receipt.v1' && value.ownerUid === uid
    && value.requestId === target.requestId && value.title === target.idea.title
    && (value.jobId === null || value.jobId === '' || typeof value.jobId === 'string' && /^work-[a-f0-9]{24}$/.test(value.jobId))
    && WORK_PHASES.includes(value.phase) && typeof value.reason === 'string' && value.reason.length <= 2000
    && (timestamp(value.updatedAt) || storedTimestamp(value.updatedAt));
}
const element = (tag, className, value) => {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (value !== undefined) node.textContent = value;
  return node;
};

export function validDiscovery(value, ownerUid) {
  if (!value || value.schemaVersion !== 'cct.discovery.v1' || value.ownerUid !== ownerUid
    || !text(value.conversationId, 80) || !Number.isSafeInteger(value.revision) || value.revision < 1
    || !timestamp(value.updatedAt) || value.executionEnabled !== false
    || !['AWAITING_INPUT', 'THINKING', 'PAUSED', 'BLOCKED'].includes(value.phase)
    || typeof value.reason !== 'string' || value.reason.length > 2000
    || !(value.question === null || (questionId(value.question?.id) && text(value.question.text, 2000)))
    || (value.phase === 'AWAITING_INPUT' && !value.question)
    || !Number.isSafeInteger(value.answersConsumed) || value.answersConsumed < 0
    || !list(value.history, (item) => sourceId(item?.questionId) && text(item.question, 4000) && text(item.answer) && timestamp(item.createdAt))
    || !list(value.unknowns, (item) => text(item, 2000))) return false;
  const ids = new Set(value.history.map((item) => item.questionId));
  const cited = (item) => list(item?.sourceAnswerIds, (id) => ids.has(id)) && item.sourceAnswerIds.length > 0;
  return ['wants', 'frustrations', 'constraints', 'delegation'].every((key) => list(value.learning?.[key], (item) => text(item?.text, 2000) && cited(item)))
    && list(value.workIdeas, (item) => text(item?.title, 500) && text(item.why, 2000) && text(item.firstStep, 2000) && item.readiness === 'DRAFT_ONLY' && cited(item));
}

export function mountDiscovery(db, ownerUid, getWorkspace, saveLearning) {
  const stateRef = doc(db, 'cct_discovery', 'current');
  let value = null;
  let fromCache = true;
  let error = '';
  let closed = false;
  let busy = false;
  let saved = null;
  let watchedId = null;
  let displayedId = null;
  let unsubscribeAnswer = null;
  let renderedLearning = '';
  let renderedIdeas = '';
  let promotionBusy = false;
  const promotions = new Map();
  // Once a write was attempted, never retry it in this mount, even if its acknowledgement is lost.
  const attemptedPromotions = new Set();
  const drafts = createAnswerDraftStore(ownerUid);
  const disposers = [];
  const input = byId('discovery-input');
  const submit = byId('discovery-submit');
  const feedback = byId('discovery-feedback');
  const listen = (node, event, fn) => { node.addEventListener(event, fn); disposers.push(() => node.removeEventListener(event, fn)); };
  const fresh = (snapshot) => !snapshot.metadata.fromCache && !snapshot.metadata.hasPendingWrites;
  const workspaceReady = () => {
    const view = getWorkspace();
    return view.ready && view.exists && view.verified && !view.busy && view.workspace.learningEnabled;
  };
  // Mounts never inherit another owner's visible input or status.
  input.value = '';
  feedback.textContent = '';
  const answerSaver = createAnswerSaver({
    ownerUid, drafts, isActive: () => !closed, onChange: render,
    readAnswer: id => getDocFromServer(doc(db, 'cct_discovery_answers', id)),
    checkContext: async id => {
      const [current, workspace] = await Promise.all([
        getDocFromServer(stateRef), getDocFromServer(doc(db, 'cct_workspace', 'current')),
      ]);
      if (![current, workspace].every(fresh)) throw Error('UNVERIFIED');
      if (closed || navigator.onLine === false || !workspaceReady() || displayedId !== id
        || !current.exists() || !validDiscovery(current.data(), ownerUid)
        || current.data().phase !== 'AWAITING_INPUT' || current.data().question?.id !== id
        || !workspace.exists() || !validateWorkspace(workspace.data(), ownerUid)
        || !workspace.data().learningEnabled) throw Error('QUESTION_CHANGED');
    },
    writeAnswer: (id, answer) => setDoc(doc(db, 'cct_discovery_answers', id), {
      schemaVersion: 'cct.discovery_answer.v1', ownerUid, questionId: id, text: answer, createdAt: serverTimestamp(),
    }),
  });
  const consume = (snapshot) => {
    if (closed) return;
    const candidate = snapshot.exists() ? snapshot.data() : null;
    error = candidate && !validDiscovery(candidate, ownerUid) ? 'The learning record could not be verified. Your replies are preserved.' : '';
    value = error ? null : candidate;
    fromCache = !fresh(snapshot);
    const id = value?.question?.id || null;
    if (id !== watchedId) {
      unsubscribeAnswer?.();
      watchedId = id;
      saved = null;
      if (id) unsubscribeAnswer = onSnapshot(doc(db, 'cct_discovery_answers', id), { includeMetadataChanges: true }, (answer) => {
        if (closed || watchedId !== id || !fresh(answer)) return;
        try { answerSaver.observe(id, answer); }
        catch { feedback.textContent = 'An existing reply could not be verified. It will not be overwritten.'; }
        render();
      }, failure => { if (!closed) { feedback.textContent = `${answerFailureReason(failure)} Saving will re-check the server. ${draftRetention(drafts.read(id))}`; } });
    }
    render();
  };
  const fail = failure => { if (!closed) { fromCache = true; error = `${answerFailureReason(failure)} Try Refresh after service recovers.`; render(); } };

  function evidence(ids) {
    const details = element('details', 'discovery-evidence');
    details.append(element('summary', '', 'Based on your words'));
    ids.forEach((id) => {
      const source = value.history.find((item) => item.questionId === id);
      if (!source) return;
      const quote = element('blockquote');
      quote.append(element('small', '', source.question), element('p', '', source.answer));
      details.append(quote);
    });
    return details;
  }

  function renderLearning() {
    const key = JSON.stringify(value && [value.learning, value.unknowns, value.workIdeas, value.history]);
    if (key === renderedLearning) return;
    renderedLearning = key;
    const labels = { wants: 'What you want', frustrations: 'What gets in the way', constraints: 'What needs respecting', delegation: 'What you’d like to hand off' };
    const facts = byId('discovery-learning');
    facts.replaceChildren();
    Object.entries(labels).forEach(([field, label]) => {
      const section = element('section', 'discovery-learning-group');
      section.append(element('h3', '', label));
      const items = value?.learning[field] || [];
      if (!items.length) section.append(element('p', 'discovery-empty', 'Still learning. No assumptions recorded.'));
      items.forEach((item) => {
        const card = element('article', 'discovery-fact');
        card.append(element('p', '', item.text), evidence(item.sourceAnswerIds));
        section.append(card);
      });
      facts.append(section);
    });
    const unknowns = byId('discovery-unknowns');
    unknowns.replaceChildren();
    (value?.unknowns?.length ? value.unknowns : ['No open questions recorded yet.']).forEach((item) => unknowns.append(element('li', '', item)));
    const history = byId('discovery-history');
    history.replaceChildren();
    if (!value?.history.length) history.append(element('p', 'discovery-empty', 'Your conversation starts with the first reply.'));
    value?.history.slice().reverse().forEach((item) => {
      const turn = element('article', 'discovery-history-turn');
      turn.append(element('h3', '', item.question), element('p', '', item.answer));
      history.append(turn);
    });
  }

  const activePromotion = entry => !closed && promotions.get(entry.requestId) === entry;
  const promotionReady = () => workspaceReady() && !busy && !fromCache && !error
    && navigator.onLine !== false && !staleDiscovery(value) && value?.phase === 'AWAITING_INPUT';

  function clearPromotions() {
    promotions.forEach(entry => entry.dispose());
    promotions.clear();
  }

  function consumePromotion(entry, kind, snapshot) {
    if (!activePromotion(entry)) return;
    entry[`${kind}Ready`] = fresh(snapshot);
    if (fresh(snapshot)) {
      const record = snapshot.exists() ? snapshot.data() : null;
      const valid = kind === 'request' ? validWorkRequest : validWorkReceipt;
      entry.errors[kind] = record && !valid(record, ownerUid, entry)
        ? 'This promotion record could not be verified. It will not be overwritten.' : '';
      entry[kind] = entry.errors[kind] ? null : record;
      if (kind === 'request' && !entry.errors[kind]
        && (record || !entry.saving && !attemptedPromotions.has(entry.requestId))) entry.message = '';
    }
    renderPromotions();
  }

  function renderPromotions() {
    if (closed) return;
    const labels = { QUEUED: 'Queued', PLANNING: 'Planning…', SELECTING: 'Selecting sources…', RESEARCHING: 'Researching…', SYNTHESIZING: 'Synthesizing…', WRITING: 'Writing report…', COMPLETE: 'Research complete', BLOCKED: 'Research blocked' };
    promotions.forEach(entry => {
      const attempted = attemptedPromotions.has(entry.requestId);
      const problem = entry.errors.request || entry.errors.receipt;
      const receipt = entry.receipt;
      const request = entry.request;
      let label = 'Promote → research';
      let status = 'One click requests this exact idea: approved public research and a private report only.';
      let badge = 'IDEA · NOT RUNNING';
      if (receipt) {
        label = labels[receipt.phase];
        status = `${entry.receiptReady ? '' : 'Cached receipt · '}${receipt.phase} · ${workReason(receipt.reason, receipt.errorCode)}`;
        badge = `PROMOTED · ${receipt.phase}`;
      } else if (request) {
        label = request.state === 'REJECTED' ? 'Request rejected' : 'Research requested';
        status = `${entry.requestReady ? '' : 'Cached request · '}${request.state === 'PENDING'
          ? 'Request saved. Waiting for the host receipt; research is not yet claimed.'
          : request.state === 'RECEIVED' ? 'Host received this exact idea. Waiting for its research receipt.'
            : workReason(request.reason) || 'The host rejected this request. It will not be resubmitted.'}`;
        badge = `PROMOTION · ${request.state}`;
      } else if (attempted) {
        label = 'Verify request';
        status = 'A save was attempted but is not yet verified. Refresh checks the same request; it will not send it again.';
        badge = 'PROMOTION · UNVERIFIED';
      } else if (!promotionReady()) {
        status = navigator.onLine === false ? 'Offline. Reconnect before promoting.'
          : !workspaceReady() ? 'Resume learning and finish saving settings before promoting.'
            : busy ? 'Finish saving your reply before promoting.'
              : fromCache || error ? 'A fresh, verified server record is needed. Refresh before promoting.'
                : staleDiscovery(value) ? 'The host record is stale. Wait for a fresh check-in before promoting.'
                  : 'Wait for discovery to finish reflecting, or resume it, before promoting.';
      } else if (!entry.requestReady || !entry.receiptReady) {
        status = 'Checking the server for an existing promotion and research receipt…';
      }
      if (entry.saving) { label = 'Saving request…'; status = 'Checking and saving this exact research request…'; }
      if (entry.message) status = entry.message;
      if (problem) { label = 'Verification needed'; status = problem; }
      entry.button.disabled = !promotionReady() || promotionBusy || !entry.requestReady || !entry.receiptReady
        || !!problem || !!request || !!receipt || attempted || entry.ideaIndex > 3;
      entry.button.textContent = label;
      entry.status.textContent = status;
      entry.badge.textContent = badge;
      entry.status.dataset.state = problem || attempted && !request && !receipt || receipt?.phase === 'BLOCKED' || request?.state === 'REJECTED' ? 'attention' : 'normal';
    });
  }

  function renderIdeas() {
    // No heartbeat fields: keep cards, details and focused controls mounted until the actual ideas change.
    const key = JSON.stringify(value && [value.conversationId, value.question?.id, value.workIdeas, value.history]);
    if (key === renderedIdeas) return;
    renderedIdeas = key;
    clearPromotions();
    const ideas = byId('discovery-work');
    ideas.replaceChildren();
    if (!value?.workIdeas.length) ideas.append(element('p', 'discovery-empty', 'Useful work will appear here as your direction becomes clearer.'));
    value?.workIdeas.forEach((idea, ideaIndex) => {
      const card = element('article', 'discovery-work-idea');
      const badge = element('span', 'discovery-draft', 'IDEA · NOT RUNNING');
      card.append(badge, element('h3', '', idea.title), element('p', '', idea.why), element('p', 'discovery-first-step', `First step: ${idea.firstStep}`), evidence(idea.sourceAnswerIds));
      const button = element('button', 'button primary discovery-promote', 'Promote → research');
      button.type = 'button'; button.disabled = true;
      const status = element('p', 'discovery-status');
      status.setAttribute('role', 'status'); status.setAttribute('aria-live', 'polite');
      const turnId = value.question?.id;
      card.append(element('p', 'discovery-help', 'Research only: no trades, spending, posts, workspace edits or account access.'), button, status);
      ideas.append(card);
      if (!questionId(turnId) || ideaIndex > 3) { status.textContent = 'No eligible completed discovery turn is available for this idea.'; return; }
      const id = promotionId(turnId, ideaIndex);
      status.id = `${id}-status`; button.setAttribute('aria-describedby', status.id);
      const entry = { requestId: id, conversationId: value.conversationId, turnId, ideaIndex,
        idea: JSON.parse(JSON.stringify(idea)), button, status, badge, request: null, receipt: null,
        requestReady: false, receiptReady: false, errors: {}, message: '', saving: false, dispose: () => {} };
      promotions.set(id, entry);
      const promote = () => promoteIdea(entry);
      button.addEventListener('click', promote);
      const unsubscribers = ['request', 'receipt'].map(kind => onSnapshot(doc(db, `cct_work_${kind}s`, id), { includeMetadataChanges: true },
        snapshot => consumePromotion(entry, kind, snapshot), () => {
          if (!activePromotion(entry)) return;
          entry[`${kind}Ready`] = false;
          entry.errors[kind] = 'Research request readback is unavailable. Refresh to verify; nothing will be resent.';
          renderPromotions();
        }));
      entry.dispose = () => { button.removeEventListener('click', promote); unsubscribers.forEach(fn => fn()); };
    });
  }

  async function promoteIdea(entry) {
    if (!activePromotion(entry) || entry.button.disabled || promotionBusy || !promotionReady()) return;
    promotionBusy = true; entry.saving = true; entry.message = '';
    render();
    const ref = doc(db, 'cct_work_requests', entry.requestId);
    try {
      const [current, prior, workspace] = await Promise.all([
        getDocFromServer(stateRef), getDocFromServer(ref), getDocFromServer(doc(db, 'cct_workspace', 'current')),
      ]);
      if (!activePromotion(entry)) return;
      if (![current, prior, workspace].every(fresh)) throw Error('UNVERIFIED');
      if (prior.exists()) {
        if (!validWorkRequest(prior.data(), ownerUid, entry)) throw Error('REQUEST_CONFLICT');
        consumePromotion(entry, 'request', prior);
        return;
      }
      const latest = current.exists() ? current.data() : null;
      if (!validDiscovery(latest, ownerUid) || latest.phase !== 'AWAITING_INPUT' || staleDiscovery(latest)
        || latest.conversationId !== entry.conversationId || latest.question?.id !== entry.turnId
        || !sameIdea(latest.workIdeas[entry.ideaIndex], entry.idea)
        || !workspace.exists() || !validateWorkspace(workspace.data(), ownerUid) || !workspace.data().learningEnabled
        || !promotionReady() || value?.question?.id !== entry.turnId) throw Error('IDEA_CHANGED');
      if (attemptedPromotions.has(entry.requestId)) throw Error('UNVERIFIED');
      const payload = { schemaVersion: 'cct.work_request.v1', ownerUid, conversationId: entry.conversationId,
        turnId: entry.turnId, ideaIndex: entry.ideaIndex, idea: entry.idea,
        scope: 'PUBLIC_RESEARCH_PRIVATE_REPORT', state: 'PENDING', createdAt: serverTimestamp() };
      attemptedPromotions.add(entry.requestId);
      await setDoc(ref, payload);
      const readback = await getDocFromServer(ref);
      if (!activePromotion(entry)) return;
      if (!readback.exists() || !fresh(readback) || !validWorkRequest(readback.data(), ownerUid, entry)) throw Error('UNVERIFIED');
      consumePromotion(entry, 'request', readback);
    } catch (failure) {
      if (activePromotion(entry)) {
        const attempted = attemptedPromotions.has(entry.requestId);
        if (!attempted) entry.requestReady = false;
        entry.message = attempted
          ? entry.request && entry.requestReady ? '' : 'The save outcome needs verification. Refresh reads this exact request; do not submit it again.'
          : failure.message === 'IDEA_CHANGED' ? 'The idea, discovery turn or settings changed. Refresh before choosing an idea again.'
            : failure.message === 'REQUEST_CONFLICT' ? 'A different record already uses this request ID. It has not been overwritten.'
              : 'Could not verify current server state. Nothing was sent. Refresh before promoting.';
      }
    } finally {
      promotionBusy = false;
      if (activePromotion(entry)) entry.saving = false;
      if (!closed) render();
    }
  }

  function render() {
    if (closed) return;
    const view = getWorkspace();
    const id = value?.question?.id || null;
    if (id !== displayedId) {
      input.value = id ? drafts.read(id).record.text : '';
      displayedId = id;
      if (!busy) feedback.textContent = '';
    }
    const answerState = id ? answerSaver.state(id) : null;
    saved = answerState?.saved || null;
    const answerBusy = busy || !!answerState?.busy;
    const existing = answerState?.existing || null;
    const differentDraft = !!existing || !!saved && !!answerState?.record.text && answerState.record.text !== saved.text;
    if (saved && !differentDraft) input.value = '';
    if (answerState?.message) feedback.textContent = `${answerState.message}${saved && !differentDraft ? '' : ` ${draftRetention(answerState)}`}`;
    const offline = navigator.onLine === false;
    const stale = value && staleDiscovery(value);
    const phase = value?.phase;
    let status = !value ? 'Connecting your discovery conversation…' : {
      AWAITING_INPUT: 'Your turn. Share as much or as little as you like.',
      THINKING: 'CCT is reflecting on what you shared…',
      PAUSED: 'Discovery is paused.', BLOCKED: 'CCT needs attention before it can continue.',
    }[phase];
    if (saved?.questionId === id) status = 'Your reply is saved. CCT will build on it next.';
    if (existing) status = 'This question already has a different reply. Your local draft has not been sent.';
    if (stale) status = 'CCT has not checked in recently. A saved reply will wait for it.';
    if (fromCache) status = 'Reconnecting. Showing the last available conversation.';
    if (error) status = error;
    if (offline) status = `You’re offline. ${id ? draftRetention(answerState) : 'Reconnect to load the conversation.'}`;
    if (view.ready && !view.workspace.learningEnabled) status = 'Discovery is paused. Resume whenever you’re ready.';
    byId('discovery-status').textContent = status;
    byId('discovery-status').dataset.state = error || offline || phase === 'BLOCKED' ? 'attention' : 'normal';
    byId('discovery-question').textContent = value?.question?.text || (phase === 'THINKING' ? 'Making sense of your last reply.' : 'Your next question will appear here.');
    byId('discovery-progress').textContent = value ? `${value.answersConsumed} ${value.answersConsumed === 1 ? 'reply' : 'replies'} incorporated` : 'No learning claimed yet';
    byId('discovery-ideas-link').hidden = !value?.workIdeas.length;
    byId('discovery-ideas-link').textContent = value?.workIdeas.length ? `See ${value.workIdeas.length} possible ${value.workIdeas.length === 1 ? 'piece' : 'pieces'} of work →` : 'See possible work';
    byId('discovery-reason').textContent = value?.reason || '';
    byId('discovery-reason').hidden = !value?.reason || phase === 'AWAITING_INPUT';
    byId('discovery-form').hidden = !id || phase !== 'AWAITING_INPUT' || !!saved && !differentDraft;
    input.disabled = answerBusy;
    input.readOnly = !!answerState?.locked || !!saved || !!existing;
    // An ambiguous write exposes a READ-ONLY verification action, never a blind retry.
    submit.disabled = answerBusy || promotionBusy || offline || !id || !!saved || !!existing
      || (!answerState?.locked && (!workspaceReady() || fromCache || !!error));
    submit.textContent = answerBusy ? 'Checking / saving…' : answerState?.locked ? 'Check saved reply' : 'Continue';
    byId('discovery-resume').hidden = !view.ready || view.workspace.learningEnabled;
    byId('discovery-resume').disabled = view.busy || offline;
    byId('discovery-pause').hidden = !view.ready || !view.workspace.learningEnabled;
    byId('discovery-pause').disabled = view.busy || offline;
    byId('discovery-saved-reply').hidden = !saved && !existing;
    byId('discovery-saved-reply').textContent = saved || existing ? `Saved reply: ${(saved || existing).text}` : '';
    byId('discovery-learning-source').textContent = value
      ? `${value.answersConsumed} ${value.answersConsumed === 1 ? 'reply' : 'replies'} incorporated · ${fromCache ? 'cached record' : 'server-read record'}. Interpretations, not execution permissions.`
      : 'Nothing learned is claimed until the host publishes an evidence-linked record.';
    byId('discovery-host-detail').textContent = value ? `Host: ${phase} · revision ${value.revision} · last check ${new Date(value.updatedAt).toLocaleString()}` : 'No host record received.';
    renderLearning();
    renderIdeas();
    renderPromotions();
  }

  async function refresh() {
    const id = displayedId;
    await Promise.all([
      (async () => {
        try { consume(await answerStage('refreshing the conversation', () => getDocFromServer(stateRef))); }
        catch (failure) { fail(failure); }
      })(),
      id ? answerSaver.verify(id) : Promise.resolve(),
    ]);
    if (closed) return;
    await Promise.all([...promotions.values()].map(async entry => {
      await Promise.all(['request', 'receipt'].map(async kind => {
        try {
          const snapshot = await answerStage('refreshing the research receipt', () => getDocFromServer(doc(db, `cct_work_${kind}s`, entry.requestId)));
          consumePromotion(entry, kind, snapshot);
        } catch {
          if (!activePromotion(entry)) return;
          entry[`${kind}Ready`] = false;
          entry.errors[kind] = 'Could not verify the research request or receipt. Nothing has been resent.';
          renderPromotions();
        }
      }));
    }));
  }

  listen(byId('discovery-form'), 'submit', async (event) => {
    event.preventDefault();
    if (submit.disabled || busy) return;
    const id = displayedId;
    if (answerSaver.state(id).locked) { await answerSaver.verify(id); return; }
    const answer = input.value;
    if (!questionId(id) || !text(answer)) { feedback.textContent = 'Share a thought in 1–4,000 characters.'; return; }
    drafts.edit(id, answer);
    busy = true;
    feedback.textContent = 'Saving your reply…';
    render();
    try { await answerSaver.save(id); }
    finally { if (!closed) { busy = false; render(); } }
  });
  listen(input, 'input', () => {
    if (!displayedId || input.disabled || input.readOnly) return;
    feedback.textContent = draftRetention(drafts.edit(displayedId, input.value));
  });
  listen(byId('discovery-refresh'), 'click', refresh);
  listen(byId('discovery-resume'), 'click', () => saveLearning(true));
  listen(byId('discovery-pause'), 'click', () => saveLearning(false));
  listen(byId('owner-settings-button'), 'click', () => { byId('context-settings').open = true; byId('context-settings').scrollIntoView({behavior:'smooth',block:'start'}); });
  const showTab = (tab) => {
    const inside = tab === 'learning';
    byId('discovery-wizard').hidden = inside;
    byId('discovery-backend').hidden = !inside;
    byId('discovery-tab').setAttribute('aria-selected', String(!inside));
    byId('learning-tab').setAttribute('aria-selected', String(inside));
  };
  listen(byId('discovery-tab'), 'click', () => showTab('discover'));
  listen(byId('learning-tab'), 'click', () => showTab('learning'));
  listen(byId('discovery-ideas-link'), 'click', () => { showTab('learning'); byId('discovery-work').scrollIntoView({behavior:'smooth',block:'start'}); });
  listen(byId('discovery-correct'), 'click', () => { showTab('discover'); input.scrollIntoView({behavior:'smooth',block:'center'}); if (!input.disabled && !byId('discovery-form').hidden) input.focus({preventScroll:true}); });
  listen(window, 'offline', render);
  listen(window, 'online', refresh);
  const unsubscribeWork = mountOwnerWork(db, ownerUid);
  const unsubscribe = onSnapshot(stateRef, { includeMetadataChanges: true }, consume, fail);
  const timer = window.setInterval(render, 10_000);
  render();
  return { render, refresh, stop() { closed = true; clearPromotions(); attemptedPromotions.clear(); unsubscribeWork(); byId('owner-work').replaceChildren(); unsubscribe(); unsubscribeAnswer?.(); disposers.forEach((fn)=>fn()); window.clearInterval(timer); drafts.forget(); input.value = ''; ['discovery-learning','discovery-work','discovery-history','discovery-saved-reply','discovery-question','discovery-feedback','discovery-reason'].forEach((id)=>byId(id).replaceChildren()); } };
}
