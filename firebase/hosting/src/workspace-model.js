// Deterministic, inspectable preference learning. Never an authority grant.
export const WORKSPACE_SCHEMA = 'cct.owner_workspace.v1';
export const PERMISSION_KEYS = Object.freeze(['credentialAccess', 'webResearch', 'workspaceRead', 'workspaceWrite', 'externalMessages', 'payments']);
export const ANSWER_CHOICES = Object.freeze({
  focus: ['revenue', 'career', 'systems', 'creative'],
  horizon: ['today', 'week', 'month'],
  risk: ['conservative', 'balanced', 'experimental'],
  interruptions: ['always', 'milestones', 'blockers'],
  success: ['revenue', 'shipped', 'learning', 'timeSaved'],
  nextStep: ['research', 'build', 'repair', 'review'],
});
export const CHOICE_LABELS = Object.freeze({
  revenue: 'Revenue', career: 'Career', systems: 'Systems', creative: 'Creative work',
  today: 'Today', week: 'This week', month: 'This month',
  conservative: 'Protect the downside', balanced: 'Balanced', experimental: 'Small experiments',
  always: 'Every decision', milestones: 'At milestones', blockers: 'Only blockers',
  shipped: 'Something shipped', learning: 'New understanding', timeSaved: 'Time saved',
  research: 'Research first', build: 'Build something', repair: 'Repair what exists', review: 'Review the evidence',
});
const exactKeys = (object, keys) => object && typeof object === 'object' && !Array.isArray(object)
  && Object.keys(object).length === keys.length && keys.every((key) => Object.hasOwn(object, key));
const cleanText = (value, max = 160) => typeof value === 'string' ? value.replace(/[\u0000-\u001f\u007f]/g, ' ').slice(0, max) : '';

export function defaultWorkspace(ownerUid = '') {
  return {
    schemaVersion: WORKSPACE_SCHEMA, ownerUid, revision: 0, updatedAt: null,
    learningEnabled: true,
    permissions: Object.fromEntries(PERMISSION_KEYS.map((key) => [key, false])),
    autonomyMode: 'supervised', autonomyAcknowledged: false,
    answers: Object.fromEntries(Object.keys(ANSWER_CHOICES).map((key) => [key, ''])),
    decisions: {},
  };
}

export function validateWorkspace(value, ownerUid, { allowUnsaved = false } = {}) {
  const keys = Object.keys(defaultWorkspace());
  if (!exactKeys(value, keys) || value.schemaVersion !== WORKSPACE_SCHEMA || value.ownerUid !== ownerUid) return false;
  if (!Number.isSafeInteger(value.revision) || value.revision < (allowUnsaved ? 0 : 1) || value.revision > 2147483647) return false;
  if (typeof value.learningEnabled !== 'boolean' || typeof value.autonomyAcknowledged !== 'boolean') return false;
  if (!['supervised', 'full'].includes(value.autonomyMode) || (value.autonomyMode === 'full' && value.autonomyAcknowledged !== true)) return false;
  if (!exactKeys(value.permissions, PERMISSION_KEYS) || !PERMISSION_KEYS.every((key) => typeof value.permissions[key] === 'boolean')) return false;
  if (!exactKeys(value.answers, Object.keys(ANSWER_CHOICES)) || !Object.entries(ANSWER_CHOICES).every(([key, choices]) => value.answers[key] === '' || choices.includes(value.answers[key]))) return false;
  if (!value.decisions || typeof value.decisions !== 'object' || Array.isArray(value.decisions) || Object.keys(value.decisions).length > 60) return false;
  return Object.entries(value.decisions).every(([id, answer]) => /^[a-zA-Z0-9_-]{1,80}$/.test(id) && ['approve', 'reject', 'later'].includes(answer));
}

// Apply a single explicit intent to the newest transaction read, not a stale form.
export function applyWorkspaceAction(workspace, action) {
  if (!validateWorkspace(workspace, workspace?.ownerUid, { allowUnsaved: true })) throw new Error('WORKSPACE_INVALID');
  const next = { ...workspace, permissions: { ...workspace.permissions }, answers: { ...workspace.answers }, decisions: { ...workspace.decisions } };
  switch (action?.type) {
    case 'answer':
      if (!Object.hasOwn(ANSWER_CHOICES, action.key) || !ANSWER_CHOICES[action.key].includes(action.value)) throw new Error('ANSWER_INVALID');
      next.answers[action.key] = action.value;
      break;
    case 'permission':
      if (!PERMISSION_KEYS.includes(action.key) || typeof action.value !== 'boolean') throw new Error('PERMISSION_INVALID');
      next.permissions[action.key] = action.value;
      break;
    case 'learning':
      if (typeof action.value !== 'boolean') throw new Error('LEARNING_INVALID');
      next.learningEnabled = action.value;
      break;
    case 'resetAnswers':
      next.answers = defaultWorkspace().answers;
      break;
    case 'decision':
      if (!/^[a-zA-Z0-9_-]{1,80}$/.test(action.id || '') || !['approve', 'reject', 'later'].includes(action.value)) throw new Error('DECISION_INVALID');
      if (!Object.hasOwn(next.decisions, action.id) && Object.keys(next.decisions).length >= 60) throw new Error('DECISION_LIMIT');
      next.decisions = { ...next.decisions, [action.id]: action.value };
      break;
    case 'autonomy':
      if (!['supervised', 'full'].includes(action.value) || (action.value === 'full' && action.confirmed !== true)) throw new Error('AUTONOMY_CONFIRMATION_REQUIRED');
      next.autonomyMode = action.value;
      next.autonomyAcknowledged = action.value === 'full';
      break;
    default: throw new Error('WORKSPACE_ACTION_INVALID');
  }
  return next;
}

const QUESTION_COPY = {
  focus: ['What deserves your attention?', 'Start with the area you want CCT to prioritise.'],
  horizon: ['How far ahead should we plan?', 'This changes the size and order of suggested next steps.'],
  risk: ['How much uncertainty is useful?', 'A preference for experiments is not permission to take risks on your behalf.'],
  interruptions: ['When should CCT check in?', 'This records a communication preference, not permission to send messages.'],
  success: ['What would a good outcome look like?', 'Choose the result that matters, rather than just staying busy.'],
  nextStep: ['What kind of next step feels right?', 'Your answer moves matching suggestions up the board.'],
};
export function questionsFor(workspace = defaultWorkspace()) {
  const answers = workspace.learningEnabled ? workspace.answers : defaultWorkspace().answers;
  let order = ['focus', 'horizon', 'risk', 'success', 'nextStep', 'interruptions'];
  let reason = 'Start with focus, then choose a planning horizon.';
  if (answers.focus === 'systems') {
    order = ['focus', 'nextStep', 'success', 'horizon', 'risk', 'interruptions'];
    reason = 'Systems selected: establish whether to repair, build, or review next.';
  } else if (answers.focus === 'revenue') {
    order = ['focus', 'success', 'horizon', 'risk', 'nextStep', 'interruptions'];
    reason = 'Revenue selected: define a useful outcome before choosing a tactic.';
  } else if (answers.focus === 'career') {
    order = ['focus', 'horizon', 'success', 'nextStep', 'risk', 'interruptions'];
    reason = 'Career selected: establish the time window before the deliverable.';
  } else if (answers.focus === 'creative') {
    order = ['focus', 'risk', 'nextStep', 'horizon', 'success', 'interruptions'];
    reason = 'Creative work selected: establish room for experimentation first.';
  }
  if (answers.risk === 'experimental' && !answers.interruptions) {
    order = order.filter((key) => key !== 'interruptions');
    order.splice(1, 0, 'interruptions');
    reason = 'Experiments selected: clarify check-ins before the next step.';
  }
  return order.map((id) => ({ id, title: QUESTION_COPY[id][0], detail: QUESTION_COPY[id][1], reason,
    options: ANSWER_CHOICES[id].map((value) => ({ value, label: CHOICE_LABELS[value] })),
    answer: workspace.answers[id] || '',
  }));
}

const SEEDS = [
  { id: 'seed-system-review', title: 'Find the highest-friction workflow', summary: 'Review one recurring workflow and identify a small, reversible improvement.', tags: { focus: 'systems', horizon: 'today', risk: 'conservative', success: 'timeSaved', nextStep: 'review' } },
  { id: 'seed-system-repair', title: 'Repair one thing before adding more', summary: 'Turn a known failure into a bounded repair brief, with a checkable success condition.', tags: { focus: 'systems', horizon: 'week', risk: 'conservative', success: 'timeSaved', nextStep: 'repair' } },
  { id: 'seed-revenue-research', title: 'Find a problem someone will pay to solve', summary: 'Draft a short research brief around an audience, a costly problem, and evidence to look for.', tags: { focus: 'revenue', horizon: 'week', risk: 'balanced', success: 'revenue', nextStep: 'research' } },
  { id: 'seed-revenue-test', title: 'Design a small offer experiment', summary: 'Outline one offer and a low-cost validation step. No spending or outreach is authorised.', tags: { focus: 'revenue', horizon: 'today', risk: 'experimental', success: 'revenue', nextStep: 'build' } },
  { id: 'seed-career-evidence', title: 'Make one piece of career evidence stronger', summary: 'Choose a real project and plan a concise case study showing your role and the result.', tags: { focus: 'career', horizon: 'week', risk: 'conservative', success: 'shipped', nextStep: 'build' } },
  { id: 'seed-career-research', title: 'Define the next career opportunity', summary: 'Write criteria for a worthwhile role and a research plan. Nothing is submitted or messaged.', tags: { focus: 'career', horizon: 'month', risk: 'balanced', success: 'learning', nextStep: 'research' } },
  { id: 'seed-creative-prototype', title: 'Give a creative idea a small first form', summary: 'Scope a rough prototype with a clear stopping point instead of an open-ended project.', tags: { focus: 'creative', horizon: 'today', risk: 'experimental', success: 'shipped', nextStep: 'build' } },
  { id: 'seed-creative-study', title: 'Study a reference, then choose a direction', summary: 'Plan a focused reference study and name what to borrow, avoid, and test.', tags: { focus: 'creative', horizon: 'month', risk: 'balanced', success: 'learning', nextStep: 'research' } },
];

// Hash is only a bounded stable UI identifier, never an integrity/auth digest.
export function snapshotCardId(kind, value) {
  let hash = 2166136261;
  for (const char of String(value)) hash = Math.imul(hash ^ char.charCodeAt(0), 16777619) >>> 0;
  return `snapshot-${kind}-${hash.toString(16)}`;
}

export function recommendationsFor(workspace = defaultWorkspace(), snapshot = null) {
  const answers = workspace.learningEnabled ? workspace.answers : {};
  const feedback = workspace.learningEnabled ? workspace.decisions : {};
  const seeds = SEEDS.map((seed, index) => {
    let score = 0;
    const reasons = [];
    for (const [key, value] of Object.entries(seed.tags)) {
      if (answers[key] === value) {
        score += key === 'focus' ? 8 : 3;
        reasons.push(`${key === 'nextStep' ? 'Next step' : key[0].toUpperCase() + key.slice(1)}: ${CHOICE_LABELS[value]}`);
      }
    }
    for (const previous of SEEDS) {
      if (!feedback[previous.id] || previous.tags.focus !== seed.tags.focus) continue;
      const effect = feedback[previous.id] === 'approve' ? 2 : feedback[previous.id] === 'reject' ? -3 : -1;
      score += effect;
      reasons.push(`${feedback[previous.id] === 'approve' ? 'More' : 'Less'} ${CHOICE_LABELS[seed.tags.focus].toLowerCase()} from your ${feedback[previous.id]} feedback`);
    }
    if (feedback[seed.id] === 'reject') score -= 8;
    if (feedback[seed.id] === 'later') score -= 4;
    return { ...seed, source: 'onboarding', sourceLabel: 'Onboarding suggestion', kind: 'idea', score, index,
      feedback: workspace.decisions[seed.id] || '',
      reasons: reasons.length ? [...new Set(reasons)] : [workspace.learningEnabled ? 'Starting suggestion · no matching preferences yet' : 'Learning paused · default order'],
    };
  }).sort((a, b) => b.score - a.score || a.index - b.index);
  const actual = [];
  const goals = Array.isArray(snapshot?.goals) ? snapshot.goals.slice(0, 20) : [];
  for (const goal of goals) {
    if (!goal || typeof goal.goal_id !== 'string') continue;
    const id = snapshotCardId('goal', goal.goal_id);
    actual.push({ id, title: cleanText(goal.title || goal.goal_id, 140), summary: `Goal ${cleanText(goal.goal_id, 100)} · reported status: ${cleanText(goal.status || 'unknown', 40)}.`, source: 'snapshot', sourceLabel: 'CCT snapshot · goal', kind: 'goal', status: cleanText(goal.status, 40), feedback: workspace.decisions[id] || '', reasons: ['Read-only runtime projection; feedback here does not change the goal.'] });
  }
  const approvals = Array.isArray(snapshot?.approvals) ? snapshot.approvals.slice(0, 20) : [];
  for (const approval of approvals) {
    if (!approval || typeof approval.request_id !== 'string') continue;
    const id = snapshotCardId('approval', approval.request_id);
    actual.push({ id, title: `Review request ${cleanText(approval.request_id, 90)}`, summary: `Reported state: ${cleanText(approval.state || 'unknown', 40)}. Review the original request in Runtime diagnostics before taking any execution action.`, source: 'snapshot', sourceLabel: 'CCT snapshot · request', kind: 'approval', status: cleanText(approval.state, 40), feedback: workspace.decisions[id] || '', reasons: ['This card records preference feedback only. It does not approve the runtime request.'] });
  }
  return [...actual, ...seeds];
}

export function learningSummary(workspace = defaultWorkspace()) {
  const entries = Object.entries(workspace.answers).filter(([, value]) => value);
  return {
    enabled: workspace.learningEnabled,
    answered: entries.length,
    total: Object.keys(ANSWER_CHOICES).length,
    feedbackCount: Object.keys(workspace.decisions).length,
    facts: entries.map(([key, value]) => `${key === 'nextStep' ? 'Next step' : key[0].toUpperCase() + key.slice(1)}: ${CHOICE_LABELS[value]}`),
    explanation: workspace.learningEnabled
      ? 'Exact answer matches rank suggestions: focus +8, other matches +3. Related approve feedback +2, reject −3, later −1; rejected cards −8 and deferred cards −4. No model retraining.'
      : 'Answers and feedback are retained, but not used for ranking or follow-up order. Permissions and autonomy are unchanged.',
  };
}

// No executor is shipped in this release. Cloud observation is not acknowledgement.
export function runtimeStatus() {
  return { state: 'NOT_CONNECTED', effective: false, detail: 'Saved intent only. A compatible runtime must acknowledge the exact policy revision before it can become effective.' };
}
