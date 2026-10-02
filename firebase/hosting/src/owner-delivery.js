import './owner-delivery.css';
import { doc, onSnapshot } from 'firebase/firestore';
import {
  configuredDeliveryMode, deliveryCapabilityCounts, deliveryReadback,
  receiptJson, validOwnerDelivery,
} from './owner-delivery-model.js';

const node = (tag, className, text) => {
  const el = document.createElement(tag);
  if (className) el.className = className;
  if (text !== undefined) el.textContent = text;
  return el;
};
const detail = (list, label, value, code = false) => {
  const row = node('div');
  const entry = node('dd');
  entry.append(node(code ? 'code' : 'span', '', value));
  row.append(node('dt', '', label), entry);
  list.append(row);
};

export function renderOwnerDelivery(root, value, { workspace, readback, error = '' } = {}) {
  // Retain evidence expansion across heartbeat and metadata-only updates.
  const open = new Set([...root.querySelectorAll('details[open]')].map(el => el.dataset.deliveryDetail));
  const evidence = (id, title) => {
    const section = node('details', 'discovery-evidence');
    section.dataset.deliveryDetail = id;
    section.open = open.has(id);
    section.append(node('summary', '', title));
    return section;
  };
  root.replaceChildren();
  root.append(node('span', 'discovery-draft', 'AUTOMATIC DELIVERY · PRIVATE LOCAL SANDBOX'));
  const heading = node('h2', '', 'What CCT is delivering.');
  heading.id = 'owner-delivery-title';
  root.append(heading);
  const mode = node('p', 'delivery-mode', configuredDeliveryMode(workspace));
  root.append(mode, node('p', 'discovery-help', 'Configured full mode is a selection trigger, not unlimited execution authority. This lane reports only host-authorized private local sandbox work. Research promotion below is a separate worker.'));
  const source = node('p', 'discovery-status', error || readback?.label || 'No host delivery projection received.');
  source.setAttribute('role', 'status');
  source.setAttribute('aria-live', 'polite');
  source.dataset.state = error || (readback && !readback.current) ? 'attention' : 'ok';
  root.append(source);
  if (!value || error) {
    root.append(node('p', '', 'No selected idea, running process, artifact or authorization is inferred from settings alone.'));
    return;
  }

  const job = value.job;
  const progress = node('dl', 'delivery-facts');
  detail(progress, 'Worker phase (recorded)', value.phase, true);
  detail(progress, 'Last host update', value.updatedAt, true);
  detail(progress, 'Bounded delivery scope', value.scope, true);
  root.append(progress, node('p', 'discovery-reason', value.reason));
  const counts = node('div', 'delivery-counts');
  for (const [key, label] of [['queued', 'Queued'], ['complete', 'Complete'], ['blocked', 'Blocked'], ['retry', 'Retry']]) {
    const metric = node('div');
    metric.append(node('strong', '', String(value.counts[key])), node('span', '', label));
    counts.append(metric);
  }
  counts.setAttribute('aria-label', 'Host-recorded delivery job counts');
  root.append(counts);

  const selected = node('article', 'delivery-selected');
  selected.append(node('span', 'section-kicker', 'SELECTED CANONICAL IDEA'));
  if (job) {
    selected.append(node('h3', '', job.title));
    const facts = node('dl', 'delivery-facts');
    for (const [label, key] of [['Idea ID', 'ideaId'], ['Source turn ID', 'turnId'], ['Job ID', 'id'], ['Job phase (recorded)', 'phase']]) {
      detail(facts, label, job[key], true);
    }
    detail(facts, 'Attempts recorded', String(job.attempts));
    if (job.retryAt !== null && job.retryAt !== undefined) detail(facts, 'Earliest recorded retry (UTC)', new Date(job.retryAt * 1000).toISOString(), true);
    if (job.reportIds?.length) detail(facts, 'Linked source report IDs', job.reportIds.join('\n'), true);
    selected.append(facts);
    if (job.reason) selected.append(node('p', 'discovery-reason', job.reason));
  } else {
    selected.append(node('p', '', 'No canonical idea selected in the host record.'));
  }
  const next = node('div', 'delivery-next');
  next.append(node('strong', '', 'Durable next step / retry'), node('p', '', job?.nextAction || value.nextAction || 'No durable next step recorded.'));
  if (job?.nextAction && value.nextAction && job.nextAction !== value.nextAction) next.append(node('p', 'microcopy', `Worker continuation: ${value.nextAction}`));
  selected.append(next);
  root.append(selected);

  const capabilities = value.capabilities || [];
  const tally = deliveryCapabilityCounts(capabilities);
  const summary = node('p', 'delivery-capability-summary', capabilities.length
    ? `${tally.implemented}/${capabilities.length} implemented · ${tally.configured}/${capabilities.length} configured · ${tally.authorized}/${capabilities.length} host-authorized · ${tally.readVerified}/${capabilities.length} read-verified`
    : 'No capability evidence reported.');
  root.append(node('h3', '', 'Capability evidence'), summary);
  root.append(node('p', 'microcopy', `${readback?.current ? 'Host-reported flags' : 'Historical flags only'}; an authorized capability is not proof of a running job. “Read-verified” is the worker’s receipt flag, not a browser permission grant.`));
  if (capabilities.length) {
    const section = evidence('capabilities', 'Inspect each capability and its limiting reason');
    const list = node('div', 'delivery-capabilities');
    for (const capability of capabilities) {
      const card = node('article', 'delivery-capability');
      card.append(node('h4', '', capability.id));
      const flags = node('dl', 'delivery-flags');
      for (const [key, label] of [['implemented', 'Implemented'], ['configured', 'Configured'], ['authorized', 'Authorized'], ['readVerified', 'Read-verified']]) {
        detail(flags, label, capability[key] ? 'Yes' : 'No');
      }
      for (const [key, label] of [['requiresExactTicket', 'Exact ticket required'], ['rootPolicyEnabled', 'Root policy enabled'], ['ticketAuthorityBound', 'Ticket authority bound']]) {
        if (typeof capability[key] === 'boolean') detail(flags, label, capability[key] ? 'Yes' : 'No');
      }
      card.append(flags, node('p', '', capability.reason || capability.reasonCode || 'No limiting reason recorded.'));
      if (capability.reason && capability.reasonCode) card.append(node('p', 'microcopy', capability.reasonCode));
      if (capability.lastEvidence) {
        const prior = evidence(`capability-${capability.id}`, 'Historical service evidence · not current authority');
        prior.append(node('pre', 'delivery-receipt', receiptJson(capability.lastEvidence)));
        card.append(prior);
      }
      list.append(card);
    }
    section.append(list);
    root.append(section);
  }

  root.append(node('h3', '', 'Artifact receipts'));
  if (job?.artifactRoot) {
    const location = node('dl', 'delivery-facts');
    detail(location, 'Worker-recorded artifact root', job.artifactRoot, true);
    root.append(location, node('p', 'microcopy', 'A local path is not a download URL or proof of a completed artifact.'));
  }
  if (job?.verification && Object.keys(job.verification).length) {
    const verification = evidence('verification', 'Inspect exact verification receipt · paths, hashes and checks');
    verification.append(node('pre', 'delivery-receipt', receiptJson(job.verification)));
    root.append(verification);
  } else {
    root.append(node('p', '', 'No artifact verification receipt recorded. Completion is not independently established here.'));
  }
  if (job?.review) {
    const review = evidence('review', 'Inspect independent model acceptance review · not external outcome proof');
    review.append(node('pre', 'delivery-receipt', receiptJson(job.review)));
    root.append(review);
  }
  // The v1 worker contract has no authenticated artifact-serving route. Never
  // invent links from private paths, hash strings or arbitrary receipt URLs.
  root.append(node('p', 'microcopy', 'Artifact download unavailable: this projection does not provide a verified private download route. Local artifact paths and host receipts are read-only evidence.'));
  if (value.lastOutcome !== null && value.lastOutcome !== '') {
    const outcome = evidence('outcome', 'Last durable outcome');
    outcome.append(node(typeof value.lastOutcome === 'string' ? 'p' : 'pre', 'delivery-receipt',
      typeof value.lastOutcome === 'string' ? value.lastOutcome : receiptJson(value.lastOutcome)));
    root.append(outcome);
  }
}

export function mountOwnerDelivery(db, uid, initialWorkspace, onReadback = () => {}) {
  const root = document.getElementById('owner-delivery');
  if (!root) return { setWorkspace() {}, stop() {} };
  let closed = false;
  let value = null;
  let workspace = initialWorkspace;
  let metadata = { fromCache: true, hasPendingWrites: false };
  let error = '';
  let lastKey = '';
  const render = () => {
    if (closed) return;
    const readback = deliveryReadback(value, { ...metadata, offline: navigator.onLine === false });
    onReadback(value, { fromCache: metadata.fromCache, hasPendingWrites: metadata.hasPendingWrites, error });
    const key = JSON.stringify([value, configuredDeliveryMode(workspace), readback.state, error]);
    if (key === lastKey) return;
    lastKey = key;
    renderOwnerDelivery(root, value, { workspace, readback, error });
  };
  render();
  const unsubscribe = onSnapshot(doc(db, 'cct_owner_delivery', 'current'), { includeMetadataChanges: true }, snapshot => {
    if (closed) return;
    const incoming = snapshot.exists() ? snapshot.data() : null;
    metadata = snapshot.metadata;
    error = incoming && !validOwnerDelivery(incoming, uid) ? 'Delivery projection rejected: identity or data contract did not verify.' : '';
    // Pending browser data is never a worker receipt, including forged COMPLETE.
    if (metadata.hasPendingWrites) error = 'Pending local delivery data ignored. Only host-written server receipts are accepted.';
    value = error ? null : incoming;
    render();
  }, () => {
    if (closed) return;
    value = null;
    error = 'Delivery readback unavailable. No current execution or completion claimed.';
    render();
  });
  window.addEventListener('offline', render);
  window.addEventListener('online', render);
  const timer = window.setInterval(render, 10_000);
  return {
    setWorkspace(next) { workspace = next; render(); },
    stop() {
      closed = true;
      unsubscribe();
      window.clearInterval(timer);
      window.removeEventListener('offline', render);
      window.removeEventListener('online', render);
      value = null;
      workspace = null;
      onReadback(null, { fromCache: true, hasPendingWrites: false, error: 'Delivery subscription stopped.' });
      root.replaceChildren();
    },
  };
}
