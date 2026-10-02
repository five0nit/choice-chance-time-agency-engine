import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { buildControl, canonicalControl, controlHash, runtimeStatus, runtimeAcknowledged, verifyControl, validRun } from '../src/executor-model.js';
import { createExecutorStore } from '../src/executor-store.js';
const uid = 'owner-test'; const projectId = 'cct-test'; const now = Date.now();
const timestamp = { seconds: Math.floor(now / 1000), nanoseconds: 123456000 };
const control = (overrides = {}) => ({ schemaVersion: 'cct.executor_control.v1', ownerUid: uid, revision: 2, updatedAt: timestamp, enabled: false, runNonce: 'a'.repeat(32), task: 'project-audit', maxRuns: 3, intervalSeconds: 300, ...overrides });
const runtime = (overrides = {}) => ({ schemaVersion: 'cct.executor_runtime.v1', ownerUid: uid, projectId, scope: 'BOUNDED_TEST_EXECUTOR', state: 'OFF', updatedAt: new Date(now).toISOString(), revision: 2, runNonce: 'a'.repeat(32), ...overrides });
const context = { ownerUid: uid, projectId, now };
const snapshot = (value, overrides = {}) => ({ exists: () => value !== null, data: () => value, metadata: { fromCache: false, hasPendingWrites: false, ...overrides } });
function harness(options = {}) {
  let stored = options.initial === null ? null : control(); let view; let writes = 0; let runtimeReads = 0; let callbacks = [];
  const api = { doc: (_db, collection) => collection, collection: (_db, c) => c, orderBy: () => '', limit: () => '', query: (c) => c,
    serverTimestamp: () => timestamp, onSnapshot: (ref, _meta, cb, fail) => { callbacks.push([ref, cb, fail]); return () => {}; },
    getDocsFromServer: async () => ({ docs: [], metadata: { fromCache: false, hasPendingWrites: false } }),
    getDocFromServer: async () => snapshot(options.mismatch ? control({ revision: 999 }) : stored, { fromCache: !!options.cached }),
    runTransaction: async (_db, fn) => fn({ get: async (ref) => {
      if (options.beforeRead) await options.beforeRead();
      if (ref === 'cct_executor_runtime') { runtimeReads++; if (options.runtimeError) throw new Error('offline'); return snapshot(options.runtime || runtime()); }
      return snapshot(stored);
    }, set: (_ref, payload) => { writes++; stored = payload; } }),
  };
  const store = createExecutorStore({}, uid, projectId, (next) => { view = next; }, api);
  return { store, get view() { return view; }, get writes() { return writes; }, get runtimeReads() { return runtimeReads; }, callbacks };
}
test('canonical control uses sorted exact fields and six microseconds', async () => {
  const c = control(); const text = canonicalControl(c);
  assert.match(text, /\.123456\+00:00/);
  assert.equal(await controlHash(c), createHash('sha256').update(text).digest('hex'));
  assert.equal(verifyControl(c, c, uid), true);
  for (const change of [{ revision: 3 }, { task: 'public-docs-check' }, { runNonce: 'b'.repeat(32) }, { enabled: true }, { extra: true }, { updatedAt: null }]) assert.equal(verifyControl(control(change), c, uid), false);
});
test('ON fails closed on absent, stale, future, cached or wrong-owner host proof', () => {
  assert.equal(runtimeStatus(runtime(), context).ready, true);
  for (const r of [null, runtime({ ownerUid: 'other' }), runtime({ projectId: 'other' }), runtime({ hostEnabled: false }), runtime({ updatedAt: new Date(now - 180001).toISOString() }), runtime({ updatedAt: new Date(now + 1).toISOString() }), runtime({ state: 'BLOCKED' })]) assert.equal(runtimeStatus(r, context).ready, false);
  for (const extra of [{ fromCache: true }, { pending: true }, { offline: true }]) assert.equal(runtimeStatus(runtime(), { ...context, ...extra }).ready, false);
});
test('ack requires exact revision, nonce, digest, identity and fresh server state', async () => {
  const c = control(); const digest = await controlHash(c); const r = runtime({ controlSha256: digest });
  assert.equal(runtimeAcknowledged(r, c, digest, context), true);
  for (const extra of [{ revision: 3 }, { runNonce: 'b'.repeat(32) }, { controlSha256: '0'.repeat(64) }]) assert.equal(runtimeAcknowledged({ ...r, ...extra }, c, digest, context), false);
  assert.equal(runtimeAcknowledged(r, c, digest, { ...context, fromCache: true }), false);
});
test('bounded transitions rotate ON nonce, force once=1, preserve OFF policy', () => {
  const opts = { ownerUid: uid, task: 'project-audit', maxRuns: 3, intervalSeconds: 60, runNonce: 'b'.repeat(32), updatedAt: timestamp };
  const once = buildControl(control(), { ...opts, action: 'once' }); assert.equal(once.maxRuns, 1); assert.equal(once.revision, 3); assert.equal(once.enabled, true);
  assert.deepEqual(buildControl(control(), { ownerUid: uid, action: 'stop', updatedAt: timestamp }), control({ revision: 3 }));
  assert.throws(() => buildControl(null, { ...opts, action: 'start' }), /BOOTSTRAP_OFF/);
  assert.equal(buildControl(null, { ...opts, action: 'stop' }).enabled, false);
  for (const extra of [{ maxRuns: 4 }, { maxRuns: 1.5 }, { intervalSeconds: 59 }, { intervalSeconds: 3601 }, { task: 'shell' }, { runNonce: 'a'.repeat(32) }]) assert.throws(() => buildControl(control(), { ...opts, action: 'start', ...extra }));
});
test('Stop is writable with unavailable runtime and initial bootstrap stays OFF', async () => {
  const h = harness({ runtimeError: true }); assert.equal(await h.store.save('stop'), true); assert.equal(h.runtimeReads, 0); assert.equal(h.writes, 1); assert.equal(h.view.controlVerified, true);
  const first = harness({ initial: null }); assert.equal(await first.store.save('stop'), true); assert.equal(first.view.control.revision, 1); assert.equal(first.view.control.enabled, false);
});
test('ON requires transactional host proof; saves have exact server readback', async () => {
  const good = harness(); assert.equal(await good.store.save('once'), true); assert.equal(good.view.control.maxRuns, 1); assert.equal(good.runtimeReads, 1);
  for (const options of [{ runtime: runtime({ hostEnabled: false }) }, { runtimeError: true }]) { const h = harness(options); assert.equal(await h.store.save('start'), false); assert.equal(h.writes, 0); }
  for (const options of [{ cached: true }, { mismatch: true }]) { const h = harness(options); assert.equal(await h.store.save('stop'), false); assert.equal(h.view.controlVerified, false); assert.match(h.view.message, /unverified/); }
});
test('signed-out in-flight reads cannot write or emit; late subscriptions ignored', async () => {
  let release; const gate = new Promise((resolve) => { release = resolve; });
  const h = harness({ beforeRead: () => gate }); h.store.start();
  const pending = h.store.save('start'); h.store.stop(); const prior = h.view; release();
  assert.equal(await pending, false); assert.equal(h.writes, 0); assert.equal(h.view, prior);
  for (const [, callback, failure] of h.callbacks) { callback(snapshot(control())); failure(); }
  assert.equal(h.view, prior); assert.equal(await h.store.save('stop'), false);
});
test('receipt identifiers and bounds validated; rendering is text-only and prominent', async () => {
  const id = `run-${'a'.repeat(32)}`; const receipt = { schemaVersion: 'cct.executor_run.v1', ownerUid: uid, runId: id, runNonce: 'a'.repeat(32), revision: 1, task: 'project-audit', state: 'COMPLETED', startedAt: new Date(now).toISOString(), reportText: '<img onerror=alert(1)>', reasonCode: 'OK', artifactSha256: 'a'.repeat(64) };
  assert.equal(validRun(receipt, uid, id), true); assert.equal(validRun({ ...receipt, reportText: 'a'.repeat(12001) }, uid, id), false); assert.equal(validRun(receipt, 'other', id), false);
  const ui = await readFile(new URL('../src/executor-ui.js', import.meta.url), 'utf8'); assert.ok(!ui.includes('innerHTML')); assert.match(ui, /report.textContent = run.reportText/);
  const html = await readFile(new URL('../index.template.html', import.meta.url), 'utf8'); assert.ok(html.indexOf('id="executor"') > html.indexOf('id="runtime-diagnostics"')); assert.match(html, /old full-autonomy request does not arm/);
});
