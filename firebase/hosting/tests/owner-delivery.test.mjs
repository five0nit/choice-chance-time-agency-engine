import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';
import vm from 'node:vm';
import * as model from '../src/owner-delivery-model.js';

const uid = 'owner-fixture';
const now = Date.parse('2026-09-14T08:00:00Z');
const fixture = (changes = {}) => ({
  schemaVersion: model.DELIVERY_SCHEMA, ownerUid: uid,
  updatedAt: new Date(now).toISOString(), phase: 'RETRY', reason: 'Fixture retry record',
  trigger: 'AUTO_FULL_MODE', scope: model.DELIVERY_SCOPE,
  job: { id: 'delivery-fixture', ideaId: 'canonical-idea-fixture', turnId: 'q-fixture',
    title: 'Fixture local CLI', phase: 'RETRY', attempts: 1, artifactRoot: '/private/fixture/artifacts',
    verification: { status: 'blocked', readback: true, tests: false, semanticCompletion: false },
    reason: 'Fixture tests failed', nextAction: 'Retry the saved job at the next worker tick.' },
  counts: { queued: 0, complete: 0, blocked: 0, retry: 1 },
  capabilities: [{ id: 'local.delivery', implemented: true, configured: true, authorized: true,
    readVerified: false, reason: 'Fixture readback not complete' },
  { id: 'external.publish', implemented: false, configured: false, authorized: false,
    readVerified: false, reason: 'Not authorized by this sandbox lane' }],
  nextAction: 'Continue the durable queue.', lastOutcome: null, ...changes,
});
const workspace = { exists: true, verified: true, busy: false,
  workspace: { autonomyMode: 'full', autonomyAcknowledged: true } };

test('delivery contract preserves exact canonical IDs and separates capability flags', () => {
  const value = fixture();
  assert.equal(model.validOwnerDelivery(value, uid), true);
  assert.equal(value.job.ideaId, 'canonical-idea-fixture');
  assert.deepEqual(model.deliveryCapabilityCounts(value.capabilities), {
    implemented: 1, configured: 1, authorized: 1, readVerified: 0,
  });
  assert.equal(model.validOwnerDelivery(fixture({ job: null }), uid), true);
  assert.equal(model.validOwnerDelivery(fixture({ lastOutcome: { reason: 'Retained outcome' } }), uid), true);
});

test('delivery rejects wrong owner, lane, schema, malformed job and capability evidence', () => {
  for (const change of [{ ownerUid: 'other' }, { schemaVersion: 'cct.owner_work.v1' },
    { scope: 'UNRESTRICTED' }, { trigger: 'OWNER_PROMOTION' }, { updatedAt: 'yesterday' },
    { updatedAt: '2026-09-14T08:00:00' }, { phase: '<script>' }, { reason: null },
    { job: {} }, { job: { ...fixture().job, ideaId: '' } },
    { job: { ...fixture().job, attempts: -1 } }, { job: { ...fixture().job, verification: 'passed' } },
    { counts: { queued: 0, complete: 0, blocked: 0, retry: '1' } },
    { capabilities: [{ ...fixture().capabilities[0], authorized: 'true' }] },
    { capabilities: [fixture().capabilities[0], fixture().capabilities[0]] },
    { lastOutcome: [] }, { lastOutcome: { content: 'x'.repeat(80_001) } }]) {
    assert.equal(model.validOwnerDelivery(fixture(change), uid), false, JSON.stringify(change).slice(0, 180));
  }
  assert.equal(model.validOwnerDelivery(null, uid), false);
  assert.equal(model.validOwnerDelivery(fixture(), ''), false);
});

test('cache, pending writes, offline, stale and future receipts do not establish current execution', () => {
  const value = fixture();
  assert.equal(model.deliveryReadback(value, { now }).state, 'SERVER_READ');
  for (const [options, expected] of [
    [{ fromCache: true }, 'CACHED'], [{ hasPendingWrites: true }, 'UNCONFIRMED'],
    [{ offline: true }, 'CACHED'], [{ now: now + model.DELIVERY_FRESHNESS_MS + 1 }, 'STALE'],
    [{ now: now - 60_001 }, 'STALE'],
  ]) {
    const result = model.deliveryReadback(value, { now, ...options });
    assert.equal(result.state, expected);
    assert.equal(result.current, false);
  }
  assert.equal(model.deliveryReadback(null).state, 'WAITING');
});

test('configured full mode comes from saved workspace, not the delivery trigger', () => {
  assert.match(model.configuredDeliveryMode(workspace), /Full mode configured · Server-verified setting/);
  assert.match(model.configuredDeliveryMode({ ...workspace, verified: false }), /unconfirmed/);
  assert.match(model.configuredDeliveryMode({ ...workspace, busy: true }), /unconfirmed/);
  assert.match(model.configuredDeliveryMode({ exists: false }), /No saved mode verified/);
  assert.match(model.configuredDeliveryMode({ ...workspace, workspace: { autonomyMode: 'supervised' } }), /Supervised configured/);
});

class Element {
  constructor(tag) { this.tagName = tag; this.children = []; this.dataset = {}; this.attributes = {}; this.ownText = ''; }
  set textContent(value) { this.ownText = String(value); this.children = []; }
  get textContent() { return this.ownText + this.children.map(c => c.textContent).join('\n'); }
  append(...children) { this.children.push(...children); }
  replaceChildren(...children) { this.ownText = ''; this.children = children; }
  setAttribute(key, value) { this.attributes[key] = value; }
  querySelectorAll(selector) {
    return this.children.flatMap(child => [
      ...(selector === 'details[open]' ? child.tagName === 'details' && child.open : child.tagName === selector) ? [child] : [],
      ...child.querySelectorAll(selector),
    ]);
  }
}

async function harness() {
  const root = new Element('section');
  const document = { createElement: tag => new Element(tag), getElementById: id => id === 'owner-delivery' ? root : null };
  let consume, fail, reference, unsubscribed = false, timerCleared = false;
  const listeners = new Map();
  const context = vm.createContext({ ...model, document, navigator: { onLine: true },
    window: { addEventListener: (name, fn) => listeners.set(name, fn),
      removeEventListener: name => listeners.delete(name), setInterval: () => 1,
      clearInterval: () => { timerCleared = true; } },
    doc: (_db, collection, id) => ({ collection, id }),
    onSnapshot: (ref, options, onValue, onError) => {
      reference = ref; consume = onValue; fail = onError;
      assert.equal(options.includeMetadataChanges, true);
      return () => { unsubscribed = true; };
    },
  });
  const source = await readFile(new URL('../src/owner-delivery.js', import.meta.url), 'utf8');
  vm.runInContext(source.replace(/^import[\s\S]*?;\n/gm, '').replaceAll('export function ', 'function '), context);
  return { root, context, source, listeners,
    emit: (value, metadata = {}) => consume({ exists: () => value !== null, data: () => value,
      metadata: { fromCache: false, hasPendingWrites: false, ...metadata } }),
    fail: () => fail(), getReference: () => reference,
    isStopped: () => unsubscribed && timerCleared,
  };
}

test('delivery UI shows real identifiers, next retry, distinct capability flags and exact receipts without authority controls', async () => {
  const h = await harness();
  h.context.renderOwnerDelivery(h.root, fixture(), { workspace, readback: model.deliveryReadback(fixture(), { now }) });
  for (const text of ['canonical-idea-fixture', 'q-fixture', 'delivery-fixture', 'RETRY',
    'Retry the saved job', '1/2 host-authorized', '0/2 read-verified', '/private/fixture/artifacts',
    '"semanticCompletion": false', 'Artifact download unavailable', 'separate worker']) assert.ok(h.root.textContent.includes(text), text);
  assert.equal(h.root.querySelectorAll('button').length, 0);
  assert.equal(h.root.querySelectorAll('a').length, 0);
  assert.doesNotMatch(h.source, /\b(setDoc|updateDoc|deleteDoc|fetch)\s*\(|innerHTML/);
});

test('no missing receipt is replaced by a synthetic success, file link or URL from data', async () => {
  const h = await harness();
  const value = fixture({ job: { ...fixture().job, title: '<img src=x onerror=alert(1)>',
    artifactRoot: 'file:///private/fixture', verification: null } });
  h.context.renderOwnerDelivery(h.root, value, { workspace });
  assert.ok(h.root.textContent.includes('<img src=x onerror=alert(1)>'));
  assert.match(h.root.textContent, /No artifact verification receipt recorded/);
  assert.equal(h.root.querySelectorAll('img').length, 0);
  assert.equal(h.root.querySelectorAll('a').length, 0);
  h.context.renderOwnerDelivery(h.root, null, { workspace });
  assert.match(h.root.textContent, /No selected idea, running process, artifact or authorization is inferred/);
});

test('subscription rejects pending and malformed data, handles read failures and clears private state on stop', async () => {
  const h = await harness();
  const forwarded = [];
  const mounted = h.context.mountOwnerDelivery({}, uid, workspace, (value, metadata) => forwarded.push({ value, metadata }));
  assert.equal(h.getReference().collection, 'cct_owner_delivery');
  assert.equal(h.getReference().id, 'current');
  h.emit(fixture({ updatedAt: new Date().toISOString() }));
  assert.match(h.root.textContent, /canonical-idea-fixture/);
  h.emit(fixture(), { fromCache: true });
  assert.match(h.root.textContent, /Cached receipt/);
  h.emit(fixture(), { hasPendingWrites: true });
  assert.match(h.root.textContent, /Pending local delivery data ignored/);
  assert.doesNotMatch(h.root.textContent, /canonical-idea-fixture/);
  h.emit(fixture({ ownerUid: 'another-owner' }));
  assert.match(h.root.textContent, /Delivery projection rejected/);
  h.fail();
  assert.match(h.root.textContent, /Delivery readback unavailable/);
  h.emit(fixture());
  mounted.stop();
  assert.equal(h.root.textContent, '');
  assert.equal(h.listeners.size, 0);
  assert.equal(h.isStopped(), true);
  assert.equal(forwarded.at(-1).value, null);
  assert.equal(forwarded.at(-1).metadata.fromCache, true);
  assert.equal(forwarded.at(-1).metadata.error, 'Delivery subscription stopped.');
  h.emit(fixture());
  assert.equal(h.root.textContent, '');
});

test('delivery sits inside the authenticated shell and owns an independent lifecycle from research', async () => {
  const html = await readFile(new URL('../index.template.html', import.meta.url), 'utf8');
  const workspaceSource = await readFile(new URL('../src/workspace-ui.js', import.meta.url), 'utf8');
  assert.ok(html.indexOf('id="owner-delivery"') > html.indexOf('id="app-shell"'));
  assert.ok(html.indexOf('id="owner-delivery"') < html.indexOf('id="discovery-wizard"'));
  assert.match(workspaceSource, /delivery = mountOwnerDelivery\(db, ownerUid, view, \(value, metadata\) => builds\?\.setDelivery\(value, metadata\)\)/);
  assert.ok(workspaceSource.indexOf('builds = mountOwnerBuilds') < workspaceSource.indexOf('delivery = mountOwnerDelivery'));
  assert.match(workspaceSource, /delivery\?\.stop\(\)/);
  assert.match(html, /SEPARATE RESEARCH WORKER/);
});


test('real queued and building projections omit receipts until the host produces them', () => {
  const value = fixture();
  delete value.job.verification;
  delete value.job.artifactRoot;
  value.phase = value.job.phase = 'BUILDING';
  assert.equal(model.validOwnerDelivery(value, uid), true);
});

test('service dispatcher reasonCode capabilities are accepted without invented reason strings', () => {
  const value = fixture();
  const service = { ...value.capabilities[0], id: 'github.issue.create',
    reasonCode: 'SERVICE_EXACT_TICKET_REQUIRED', requiresExactTicket: true,
    rootPolicyEnabled: true, ticketAuthorityBound: false, lastEvidence: null };
  delete service.reason;
  value.capabilities = [service];
  assert.equal(model.validOwnerDelivery(value, uid), true);
});

test('missing capability projection stays visible without inventing capability flags', async () => {
  const h = await harness();
  for (const capabilities of [undefined, null, []]) {
    const value = fixture({ capabilities });
    assert.equal(model.validOwnerDelivery(value, uid), true);
    h.context.renderOwnerDelivery(h.root, value, { workspace });
    assert.match(h.root.textContent, /No capability evidence reported/);
    assert.match(h.root.textContent, /canonical-idea-fixture/);
    assert.doesNotMatch(h.root.textContent, /0\/0|NaN|undefined/);
  }
});

test('retry time, source reports, independent review and service limits remain exact read-only evidence', async () => {
  const h = await harness();
  const value = fixture();
  value.job.retryAt = now / 1000;
  value.job.reportIds = ['report-fixture'];
  value.job.review = { accepted: false, reason: 'Fixture acceptance failed' };
  value.capabilities[0].reasonCode = 'SERVICE_EXACT_TICKET_REQUIRED';
  value.capabilities[0].requiresExactTicket = true;
  value.capabilities[0].rootPolicyEnabled = true;
  value.capabilities[0].ticketAuthorityBound = false;
  delete value.capabilities[0].reason;
  h.context.renderOwnerDelivery(h.root, value, { workspace });
  for (const text of ['2026-09-14T08:00:00.000Z', 'report-fixture', 'Fixture acceptance failed',
    'SERVICE_EXACT_TICKET_REQUIRED', 'Exact ticket required', 'Ticket authority bound']) {
    assert.ok(h.root.textContent.includes(text), text);
  }
  assert.equal(h.root.querySelectorAll('button').length, 0);
  assert.equal(h.root.querySelectorAll('a').length, 0);
});

test('optional worker evidence rejects malformed types rather than crashing a readback', () => {
  for (const change of [{ retryAt: 'tomorrow' }, { retryAt: Infinity }, { review: 'accepted' },
    { reportIds: [''] }, { reportIds: 'report' }]) {
    assert.equal(model.validOwnerDelivery(fixture({ job: { ...fixture().job, ...change } }), uid), false);
  }
});
