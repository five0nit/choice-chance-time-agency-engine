import assert from 'node:assert/strict';
import test from 'node:test';
import {
  defaultWorkspace, validateWorkspace, applyWorkspaceAction, questionsFor,
  recommendationsFor, learningSummary, runtimeStatus, snapshotCardId, PERMISSION_KEYS,
} from '../src/workspace-model.js';
const owner = 'qa-owner';
const blank = () => defaultWorkspace(owner);
const act = (workspace, type, fields = {}) => applyWorkspaceAction(workspace, { type, ...fields });

test('unsaved workspace defaults all authority off and needs saved revision', () => {
  const w = blank();
  assert.equal(validateWorkspace(w, owner), false);
  assert.equal(validateWorkspace(w, owner, { allowUnsaved: true }), true);
  assert.equal(Object.keys(w.permissions).length, 6);
  assert.equal(Object.values(w.permissions).every(value => value === false), true);
  assert.equal(w.autonomyMode, 'supervised');
  assert.equal(w.autonomyAcknowledged, false);
});

test('strict workspace schema rejects extra fields, owner mismatch, coercion and unknown answers', () => {
  const good = { ...blank(), revision: 1 };
  assert.equal(validateWorkspace(good, owner), true);
  for (const change of [{ revision: true }, { ownerUid: 'outsider' }, { extra: true },
    { autonomyMode: 'full' }, { learningEnabled: 'true' }, { permissions: { ...good.permissions, payments: 1 } },
    { answers: { ...good.answers, focus: 'anything' } }, { decisions: { good: 'execute' } }]) {
    assert.equal(validateWorkspace({ ...good, ...change }, owner), false, JSON.stringify(change));
  }
});

test('one permission intent is immutable and cannot turn on other fields', () => {
  const w = blank();
  const changed = act(w, 'permission', { key: 'credentialAccess', value: true });
  assert.equal(w.permissions.credentialAccess, false);
  assert.equal(changed.permissions.credentialAccess, true);
  assert.equal(PERMISSION_KEYS.filter(key => changed.permissions[key]).length, 1);
  assert.equal(changed.autonomyMode, 'supervised');
  assert.throws(() => act(w, 'permission', { key: 'payments', value: 'true' }), /PERMISSION_INVALID/);
  assert.throws(() => act(w, 'permission', { key: '__proto__', value: true }), /PERMISSION_INVALID/);
});

test('full autonomy needs explicit confirmation and never broadens permission intent', () => {
  const w = act(blank(), 'permission', { key: 'webResearch', value: true });
  for (const confirmed of [undefined, false, 1, 'true']) {
    assert.throws(() => act(w, 'autonomy', { value: 'full', confirmed }), /AUTONOMY_CONFIRMATION_REQUIRED/);
  }
  const full = act(w, 'autonomy', { value: 'full', confirmed: true });
  assert.deepEqual(full.permissions, w.permissions);
  assert.equal(full.autonomyAcknowledged, true);
  const supervised = act(full, 'autonomy', { value: 'supervised' });
  assert.equal(supervised.autonomyAcknowledged, false);
});

test('question order adapts to selected focus and experimental risk', () => {
  assert.equal(questionsFor(blank())[0].id, 'focus');
  const systems = act(blank(), 'answer', { key: 'focus', value: 'systems' });
  assert.equal(questionsFor(systems).find(q => !q.answer).id, 'nextStep');
  const revenue = act(blank(), 'answer', { key: 'focus', value: 'revenue' });
  assert.equal(questionsFor(revenue).find(q => !q.answer).id, 'success');
  const experimental = act(systems, 'answer', { key: 'risk', value: 'experimental' });
  assert.equal(questionsFor(experimental).find(q => !q.answer).id, 'interruptions');
});

test('matching preferences produce an explainable ranked next step', () => {
  let w = act(blank(), 'answer', { key: 'focus', value: 'systems' });
  w = act(w, 'answer', { key: 'nextStep', value: 'repair' });
  const top = recommendationsFor(w)[0];
  assert.equal(top.id, 'seed-system-repair');
  assert.equal(top.score, 11);
  assert.match(top.reasons.join(' '), /Systems.*Repair/);
  assert.equal(top.source, 'onboarding');
});

test('decision feedback updates related ranking but grants no authority', () => {
  const w = act(blank(), 'decision', { id: 'seed-career-evidence', value: 'approve' });
  assert.equal(recommendationsFor(w)[0].id, 'seed-career-evidence');
  assert.match(recommendationsFor(w)[0].reasons.join(' '), /approve feedback/);
  assert.deepEqual(w.permissions, blank().permissions);
  assert.equal(w.autonomyMode, 'supervised');
});

test('learning pause retains answers and feedback but removes their ranking effects', () => {
  let w = act(blank(), 'answer', { key: 'focus', value: 'creative' });
  w = act(w, 'decision', { id: 'seed-creative-prototype', value: 'approve' });
  w = act(w, 'learning', { value: false });
  assert.equal(w.answers.focus, 'creative');
  assert.deepEqual(recommendationsFor(w).map(x => [x.id, x.score]), recommendationsFor(blank()).map(x => [x.id, x.score]));
  assert.equal(questionsFor(w)[1].id, 'horizon');
  assert.equal(learningSummary(w).enabled, false);
});

test('reset answers preserves permission, autonomy and separately editable feedback', () => {
  let w = act(blank(), 'answer', { key: 'focus', value: 'systems' });
  w = act(w, 'permission', { key: 'credentialAccess', value: true });
  w = act(w, 'autonomy', { value: 'full', confirmed: true });
  w = act(w, 'decision', { id: 'seed-system-repair', value: 'later' });
  const reset = act(w, 'resetAnswers');
  assert.deepEqual(reset.answers, blank().answers);
  assert.deepEqual(reset.permissions, w.permissions);
  assert.deepEqual(reset.decisions, w.decisions);
  assert.equal(reset.autonomyMode, 'full');
});

test('bounded feedback map rejects overfill but permits editing an existing decision', () => {
  let w = blank();
  for (let i = 0; i < 60; i++) w = act(w, 'decision', { id: `card-${i}`, value: 'later' });
  assert.throws(() => act(w, 'decision', { id: 'new-card', value: 'approve' }), /DECISION_LIMIT/);
  assert.equal(act(w, 'decision', { id: 'card-0', value: 'reject' }).decisions['card-0'], 'reject');
  assert.throws(() => act(w, 'decision', { id: 'invalid/key', value: 'approve' }), /DECISION_INVALID/);
});

test('runtime goals and requests stay separate from onboarding suggestions', () => {
  const cards = recommendationsFor(blank(), { goals: [{ goal_id: 'g1', title: 'Reported goal', status: 'active' }],
    approvals: [{ request_id: 'r1', state: 'ACTION_REQUIRED' }] });
  const actual = cards.filter(card => card.source === 'snapshot');
  assert.equal(actual.length, 2);
  assert.equal(actual[0].title, 'Reported goal');
  assert.match(actual[1].summary, /Runtime diagnostics/);
  assert.match(actual[1].reasons[0], /does not approve/);
  assert.equal(cards.filter(card => card.source === 'onboarding').length, 8);
  assert.equal(snapshotCardId('goal', 'g1'), actual[0].id);
});

test('missing or malformed runtime arrays do not fabricate CCT thoughts', () => {
  for (const snapshot of [null, {}, { goals: 'bad', approvals: 1 }, { goals: [null, {}], approvals: [null, {}] }]) {
    assert.equal(recommendationsFor(blank(), snapshot).every(card => card.source === 'onboarding'), true);
  }
});

test('runtime status cannot be turned effective by a forged snapshot or full request', () => {
  assert.equal(runtimeStatus({ enforcementActive: true }).effective, false);
  assert.equal(runtimeStatus().state, 'NOT_CONNECTED');
});

test('newest-state actions preserve unrelated concurrent fields', () => {
  const newest = act(blank(), 'answer', { key: 'horizon', value: 'week' });
  const merged = act(newest, 'answer', { key: 'focus', value: 'career' });
  assert.equal(merged.answers.horizon, 'week');
  assert.equal(merged.answers.focus, 'career');
  assert.equal(learningSummary(merged).answered, 2);
  assert.throws(() => act(merged, 'unknown'), /WORKSPACE_ACTION_INVALID/);
});
