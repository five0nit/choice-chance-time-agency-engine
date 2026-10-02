import { doc, onSnapshot } from 'firebase/firestore';

const node = (tag, cls, text) => {
  const el = document.createElement(tag);
  if (cls) el.className = cls;
  if (text !== undefined) el.textContent = text;
  return el;
};
const text = (s, max = 4000) => typeof s === 'string' && s.length <= max;
const list = (a, fn, max = 20) => Array.isArray(a) && a.length <= max && a.every(fn);
const url = (s) => {
  try {
    const u = new URL(s);
    return u.protocol === 'https:' && !u.username && !u.password && !u.port
      && ['docs.dexscreener.com', 'solana.com', 'docs.coingecko.com', 'api.kraken.com'].includes(u.hostname);
  } catch { return false; }
};

export const WORK_PHASES = ['QUEUED', 'PLANNING', 'SELECTING', 'RESEARCHING', 'SYNTHESIZING', 'WRITING', 'COMPLETE', 'BLOCKED'];
const requestId = s => typeof s === 'string' && /^promote-[a-f0-9]{32}-[0-3]$/.test(s);
const promotedIdea = idea => idea && text(idea.title, 500) && idea.title.trim().length > 0
  && text(idea.why, 2000) && text(idea.firstStep, 2000) && idea.readiness === 'DRAFT_ONLY'
  && list(idea.sourceAnswerIds, id => typeof id === 'string' && /^(q|msg)-[a-f0-9]{32}$/.test(id), 100)
  && idea.sourceAnswerIds.length > 0;
export const workReason = (reason, errorCode) => errorCode === 'WORK_NO_SUITABLE_SOURCE' || reason === 'WORK_NO_SUITABLE_SOURCE'
  ? 'The approved public-source catalog has no suitable source for this idea. Arbitrary web search is not available yet; no research result is claimed.'
  : reason || '';

export function validOwnerWork(value, uid) {
  if (!value || value.schemaVersion !== 'cct.owner_work.v1' || value.ownerUid !== uid
    || value.scope !== 'PUBLIC_RESEARCH_PRIVATE_REPORT' || value.financialExecutionEnabled !== false
    || !Number.isFinite(Date.parse(value.updatedAt)) || !text(value.reason, 2000)
    || !['WAITING', ...WORK_PHASES, 'PAUSED'].includes(value.phase)) return false;
  if (value.trigger !== undefined && value.trigger !== 'OWNER_PROMOTION') return false;
  if (value.queue !== undefined && (!list(value.queue, item => item && /^work-[a-f0-9]{24}$/.test(item.id)
    && requestId(item.requestId) && text(item.title, 500) && WORK_PHASES.includes(item.phase)
    && Number.isFinite(Date.parse(item.createdAt)), 20)
    || !Number.isSafeInteger(value.queuedCount) || value.queuedCount < value.queue.length)) return false;
  if (value.queuedCount !== undefined && (!Number.isSafeInteger(value.queuedCount) || value.queuedCount < 0)) return false;
  const j = value.job;
  if (j === null) return value.phase !== 'COMPLETE';
  if (!j || !/^work-[a-f0-9]{24}$/.test(j.id) || !text(j.reason, 2000)
    || (j.phase !== undefined && !WORK_PHASES.includes(j.phase))
    || (j.errorCode !== undefined && j.errorCode !== null && !text(j.errorCode, 120))
    || (j.requestId !== undefined && j.requestId !== null && !requestId(j.requestId))
    || (j.promotedIdea !== undefined && j.promotedIdea !== null && !promotedIdea(j.promotedIdea))
    || !list(j.sources, s => text(s?.id, 80) && text(s.title, 300) && url(s.url) && typeof s.ok === 'boolean', 6)
    || !list(j.ownerEvidence, a => text(a?.questionId, 80) && text(a.question) && text(a.answer), 3)) return false;
  if (j.selection && (!text(j.selection.title, 120) || !text(j.selection.objective, 800) || !text(j.selection.doneWhen, 600))) return false;
  if (j.executionPlan && !list(j.executionPlan, s => ['public_get', 'synthesize_cited_report', 'write_private_report'].includes(s?.action)
    && ['PENDING', 'COMPLETE', 'UNAVAILABLE'].includes(s.status), 8)) return false;
  if (!j.report) return value.phase !== 'COMPLETE';
  return text(j.report.summary, 1600)
    && list(j.report.findings, f => text(f?.claim, 700) && text(f.quote, 2000) && j.sources.some(s => s.id === f.sourceId && s.ok), 8)
    && list(j.report.nextSteps, s => text(s?.title, 120) && text(s.deliverable, 600) && text(s.doneWhen, 600) && s.requiresApproval === true, 6)
    && list(j.report.ownerDecisions, s => text(s, 400), 6) && list(j.report.limitations, s => text(s, 500), 8);
}

export function renderOwnerWork(root, value, cached = false) {
  root.replaceChildren();
  root.append(node('span', 'discovery-draft', 'SEPARATE RESEARCH WORKER · PUBLIC RESEARCH + PRIVATE REPORTS'));
  root.append(node('h2', '', 'Owner-promoted research.'));
  if (!value) {
    root.append(node('p', '', 'Waiting for the host’s research record. No completed work claimed.'));
    return;
  }
  const j = value.job;
  root.append(node('p', 'discovery-status', `${cached ? 'Cached receipt · ' : ''}${value.phase} · ${workReason(value.reason, j?.errorCode)}`));
  root.append(node('p', 'discovery-help', 'Promote an exact idea above to request public research and a private report. One job runs at a time, with up to six approved public sources and two model calls per job. Pause above stops new work at the next action boundary. No trades, spending, posts, workspace edits or account access.'));
  const queuedCount = value.queuedCount ?? 0;
  root.append(node('p', 'discovery-first-step', `${queuedCount} ${queuedCount === 1 ? 'idea' : 'ideas'} queued`));
  if (value.queue?.length) {
    const queue = node('ol', 'discovery-work-queue');
    value.queue.forEach(item => queue.append(node('li', '', `${item.title} · ${item.phase}`)));
    root.append(queue);
    if (queuedCount > value.queue.length) root.append(node('small', '', `Showing the first ${value.queue.length} queued ideas.`));
  }
  if (!j) return;
  if (j.promotedIdea) {
    root.append(node('span', 'discovery-draft', 'OWNER-PROMOTED · RESEARCH ONLY'), node('h3', '', j.promotedIdea.title));
    const provenance = node('details', 'discovery-evidence');
    provenance.append(node('summary', '', 'Exact promoted idea + provenance'), node('p', '', j.promotedIdea.why),
      node('p', '', `Original first step (not execution authority): ${j.promotedIdea.firstStep}`),
      node('small', '', `Request ${j.requestId || 'not provided'} · Source answers: ${j.promotedIdea.sourceAnswerIds.join(', ')}`));
    if (j.requestId) {
      const parts = j.requestId.split('-');
      provenance.append(node('p', 'microcopy', `Discovery turn q-${parts[1]} · idea index ${parts[2]}. The archived idea is retained even when discovery moves on.`));
    }
    root.append(provenance);
  }
  if (j.reason || j.errorCode) root.append(node('p', 'discovery-reason', workReason(j.reason, j.errorCode)));
  if (j.selection) {
    root.append(node('h3', '', j.selection.title), node('p', '', j.selection.objective));
    root.append(node('p', 'discovery-first-step', `Done when: ${j.selection.doneWhen}`));
  }
  const evidence = node('details', 'discovery-evidence');
  evidence.append(node('summary', '', 'Why this work · your original answers'));
  j.ownerEvidence.forEach(a => {
    const quote = node('blockquote');
    quote.append(node('small', '', a.question), node('p', '', a.answer));
    evidence.append(quote);
  });
  root.append(evidence);
  const plan = node('details', 'discovery-evidence');
  plan.append(node('summary', '', 'Saved execution plan + receipts'));
  (j.executionPlan || []).forEach(s => plan.append(node('p', '', `${s.status} · ${s.sourceId || s.action.replaceAll('_', ' ')}`)));
  plan.append(node('small', '', `Run ${j.id} · ${j.webAttempts} source attempts · ${j.modelCalls} model calls`));
  root.append(plan);
  if (j.report) {
    root.append(node('h3', '', 'What the research found'), node('p', '', j.report.summary));
    j.report.findings.forEach(f => {
      const source = j.sources.find(s => s.id === f.sourceId);
      const card = node('article', 'discovery-fact');
      card.append(node('p', '', f.claim));
      const proof = node('details', 'discovery-evidence');
      proof.append(node('summary', '', `Source: ${source.title}`), node('blockquote', '', f.quote));
      const link = node('a', 'text-button', 'Open public source ↗');
      link.href = source.url; link.target = '_blank'; link.rel = 'noopener noreferrer';
      proof.append(link, node('small', '', ` Retrieved ${source.fetchedAt} · ${source.textTruncated ? 'excerpt' : 'text'}`));
      card.append(proof); root.append(card);
    });
    if (j.calculations?.available === true) {
      const math = node('details', 'discovery-evidence');
      math.append(node('summary', '', 'Fee arithmetic · assumptions included'));
      const code = node('pre', '', JSON.stringify(j.calculations, null, 2));
      code.style.cssText = 'white-space:pre-wrap;overflow-wrap:anywhere;font-size:12px';
      math.append(code); root.append(math);
    }
    root.append(node('h3', '', 'Concrete next plan · not executed'));
    j.report.nextSteps.forEach(s => {
      const card = node('article', 'discovery-work-idea');
      card.append(node('span', 'discovery-draft', 'PROPOSED · NEEDS SCOPE / APPROVAL'), node('h4', '', s.title),
        node('p', '', `Deliverable: ${s.deliverable}`), node('p', '', `Done when: ${s.doneWhen}`));
      root.append(card);
    });
    const limits = node('details', 'discovery-evidence');
    limits.append(node('summary', '', 'Open decisions + evidence gaps'));
    j.report.ownerDecisions.forEach(s => limits.append(node('p', '', `You decide: ${s}`)));
    j.report.limitations.forEach(s => limits.append(node('p', '', s)));
    j.sources.filter(s => !s.ok).forEach(s => limits.append(node('p', '', `Source unavailable: ${s.title} (${s.errorCode || s.errorType}). Not treated as evidence.`)));
    root.append(limits);
    if (j.artifactName) root.append(node('p', 'microcopy', `Private report saved: ${j.artifactName}`));
  }
  root.append(node('small', '', `Host checked ${new Date(value.updatedAt).toLocaleString()}. Results are retained evidence, not a promise of profit.`));
}

export function mountOwnerWork(db, uid) {
  const root = document.getElementById('owner-work');
  if (!root) return () => {};
  let key = '';
  let closed = false;
  const unsubscribe = onSnapshot(doc(db, 'cct_owner_work', 'current'), { includeMetadataChanges: true }, snapshot => {
    if (closed) return;
    const value = snapshot.exists() ? snapshot.data() : null;
    if (value && !validOwnerWork(value, uid)) {
      root.replaceChildren(node('p', 'discovery-status', 'The research receipt could not be verified. No execution authority granted.'));
      key = ''; return;
    }
    const cached = snapshot.metadata.fromCache || snapshot.metadata.hasPendingWrites;
    const nextKey = JSON.stringify([value?.phase, value?.reason, value?.trigger, value?.queue, value?.queuedCount, value?.job, cached]);
    if (key === nextKey) return;
    key = nextKey;
    renderOwnerWork(root, value, cached);
  }, () => {
    if (closed) return;
    key = '';
    root.replaceChildren(node('p', 'discovery-status', 'Research readback unavailable. Discovery remains separate; no completed work claimed.'));
  });
  return () => { closed = true; unsubscribe(); };
}
