import assert from 'node:assert/strict';
import test from 'node:test';
import { readFile } from 'node:fs/promises';
import { buildOwnerReply, canReplyToMessage, validateOwnerMessage, validateRuntimeStatus, verifyOwnerReply } from '../src/owner-connection-model.js';
import { createOwnerConnection } from '../src/owner-connection.js';

const uid = 'owner-test';
const projectId = 'cct-test';
const id = `msg-${'a'.repeat(32)}`;
const sha = 'a'.repeat(64);
const now = Date.parse('2026-09-13T10:00:00Z');
const context = { ownerUid: uid, projectId, workspaceRevision: 3, workspaceVerified: true, now };
const runtime = (overrides = {}) => ({ schemaVersion: 'cct.owner_runtime.v1', ownerUid: uid, projectId,
  state: 'CONNECTED', updatedAt: new Date(now).toISOString(), revision: 3, policySha256: sha, workspaceSha256: sha,
  effectivePolicy: { ownerMessages: true, autonomyMode: 'supervised' }, unsupportedPermissions: ['payments'],
  scope: 'OWNER_MESSAGES_ONLY', reasonCode: 'OK', ...overrides });
const message = (overrides = {}) => ({ schemaVersion: 'cct.owner_message.v1', ownerUid: uid, messageId: id,
  kind: 'ask', text: 'What matters next?', state: 'SENT', createdAt: new Date(now - 1000).toISOString(),
  expiresAt: new Date(now + 60_000).toISOString(), revision: 3, policySha256: sha, telegramMessageId: '12', answer: null, ...overrides });

 test('only a fresh exact-owner runtime attestation establishes a scoped connection', () => {
  assert.equal(validateRuntimeStatus(null, context).state, 'NOT_CONNECTED');
  assert.equal(validateRuntimeStatus({ generated_at: new Date(now).toISOString(), ownerUid: uid }, context).state, 'INVALID');
  assert.deepEqual(validateRuntimeStatus(runtime(), context).effectivePolicy, { ownerMessages: true, autonomyMode: 'supervised' });
  assert.equal(validateRuntimeStatus(runtime(), context).state, 'CONNECTED');
  assert.equal(validateRuntimeStatus(runtime({ updatedAt: '2026-09-13T10:00:00.000000+00:00' }), context).state, 'CONNECTED', 'host microsecond UTC format');
  for (const changes of [{ fromCache: true }, { hasPendingWrites: true }, { now: now + 180_001 }, { now: now - 60_001 }]) {
    assert.equal(validateRuntimeStatus(runtime(), { ...context, ...changes }).state, 'STALE');
  }
  for (const changes of [{ now: now + 180_000 }, { now: now - 60_000 }]) assert.equal(validateRuntimeStatus(runtime(), { ...context, ...changes }).state, 'CONNECTED');
  for (const changes of [{ workspaceRevision: 4 }, { workspaceRevision: 2 }, { workspaceVerified: false }]) {
    assert.equal(validateRuntimeStatus(runtime(), { ...context, ...changes }).state, 'SYNC_PENDING');
  }
});

test('runtime schema, identity, bounded reason and digest fail closed', () => {
  for (const change of [{ ownerUid: 'other' }, { projectId: 'other' }, { schemaVersion: 'cct.observer.v1' },
    { scope: 'ALL' }, { state: 'OK' }, { policySha256: 'a'.repeat(63) }, { workspaceSha256: 'A'.repeat(64) },
    { revision: 3.5 }, { revision: null }, { policySha256: null }, { workspaceSha256: null },
    { updatedAt: 'yesterday' }, { updatedAt: '2026-02-30T10:00:00Z' }, { updatedAt: '2026-09-13T10:00:00' }, { reasonCode: 'x'.repeat(100) },
    { effectivePolicy: { ownerMessages: true, autonomyMode: 'full' } },
    { effectivePolicy: { ownerMessages: true, autonomyMode: 'supervised', payments: true } }, { unsupportedPermissions: [true] }]) {
    assert.equal(validateRuntimeStatus(runtime(change), context).state, 'INVALID', JSON.stringify(change));
  }
  assert.equal(validateRuntimeStatus(runtime(), { ...context, ownerUid: '' }).state, 'INVALID');
  assert.equal(validateRuntimeStatus(runtime({ state: 'DISABLED', revision: null, policySha256: null, workspaceSha256: null }), context).state, 'DISABLED');
  assert.equal(validateRuntimeStatus(runtime({ state: 'INVALID' }), context).effectivePolicy.ownerMessages, false);
  assert.equal(validateRuntimeStatus(runtime({ effectivePolicy: { ownerMessages: false, autonomyMode: 'supervised' } }), context).effectivePolicy.ownerMessages, false);
});

test('messages bind host IDs and only unexpired SENT asks accept answers', () => {
  assert.equal(validateOwnerMessage(message(), uid, id), true);
  assert.equal(canReplyToMessage(message(), now), true);
  for (const change of [{ ownerUid: 'other' }, { messageId: `msg-${'A'.repeat(32)}` }, { kind: 'execute' },
    { policySha256: null }, { text: '' }, { revision: 0 }, { createdAt: 'today' }, { answer: {} }]) {
    assert.equal(validateOwnerMessage(message(change), uid, id), false);
  }
  for (const state of ['QUEUED', 'SENDING', 'ANSWERED', 'DENIED', 'UNKNOWN']) assert.equal(canReplyToMessage(message({ state }), now), false);
  assert.equal(canReplyToMessage(message({ kind: 'send' }), now), false);
  assert.equal(canReplyToMessage(message({ answer: 'Done' }), now), false);
  assert.equal(canReplyToMessage(message({ expiresAt: new Date(now).toISOString() }), now), false);
  assert.equal(validateOwnerMessage(message({ text: '<img src=x onerror=alert(1)>' }), uid, id), true, 'message content is text, not HTML');
});

test('reply payload is exact trimmed answer data with timestamp readback', () => {
  const expected = buildOwnerReply(uid, id, '  An answer  ', 'server-timestamp');
  assert.deepEqual(Object.keys(expected).sort(), ['createdAt', 'messageId', 'ownerUid', 'schemaVersion', 'text']);
  assert.equal(expected.text, 'An answer');
  for (const text of ['', '  ', 'a'.repeat(2001), null]) assert.throws(() => buildOwnerReply(uid, id, text, null), /REPLY_INVALID/);
  assert.equal(buildOwnerReply(uid, id, 'a'.repeat(2000), null).text.length, 2000);
  const readback = { ...expected, createdAt: { toMillis: () => now } };
  assert.equal(verifyOwnerReply(readback, expected), true);
  for (const change of [{ text: 'wrong' }, { ownerUid: 'other' }, { createdAt: null }, { permissions: { payments: true } }]) assert.equal(verifyOwnerReply({ ...readback, ...change }, expected), false);
});

const snap = (value, metadata = {}) => ({ exists: () => value !== null, data: () => value, metadata: { fromCache: false, hasPendingWrites: false, ...metadata } });
function harness({ corruptReadback = false, denied = false, existing = null, runtimeChange = {}, messageChange = {} } = {}) {
  const callbacks = [];
  const writes = [];
  const emitted = [];
  let stopped = 0;
  let saved = existing;
  const liveNow = Date.now();
  const liveRuntime = runtime({ updatedAt: new Date(liveNow).toISOString(), ...runtimeChange });
  const liveMessage = message({ createdAt: new Date(liveNow - 1000).toISOString(), expiresAt: new Date(liveNow + 60_000).toISOString(), ...messageChange });
  const api = {
    doc: (_db, ...parts) => parts.join('/'), collection: (_db, name) => name,
    orderBy: (...args) => ({ orderBy: args }), limit: (count) => ({ limit: count }), query: (...parts) => parts,
    onSnapshot: (ref, options, success, failure) => { callbacks.push({ ref, options, success, failure }); return () => { stopped++; }; },
    serverTimestamp: () => 'SERVER_TIMESTAMP',
    getDocFromServer: async (ref) => {
      if (ref === 'cct_owner_runtime/current') return snap(liveRuntime);
      if (ref.startsWith('cct_owner_messages/')) return snap(liveMessage);
      return snap(saved && corruptReadback ? { ...saved, text: 'changed' } : saved);
    },
    getDocsFromServer: async () => ({ docs: [], metadata: { fromCache: false, hasPendingWrites: false } }),
    setDoc: async (ref, value) => {
      if (denied) throw Object.assign(new Error('denied'), { code: 'permission-denied' });
      writes.push({ ref, value });
      saved = { ...value, createdAt: { toMillis: () => liveNow } };
    },
  };
  const store = createOwnerConnection({}, uid, projectId, () => ({ workspaceRevision: 3, workspaceVerified: true }), (state) => emitted.push(state), api);
  return { store, callbacks, writes, emitted, stopped: () => stopped, liveMessage };
}

test('subscribes runtime and recent twenty messages with cache metadata and stops both', async () => {
  const h = harness();
  h.store.start();
  h.store.start();
  assert.equal(h.callbacks.length, 2);
  assert.equal(h.callbacks[0].ref, 'cct_owner_runtime/current');
  assert.deepEqual(h.callbacks[1].ref, ['cct_owner_messages', { orderBy: ['createdAt', 'desc'] }, { limit: 20 }]);
  assert.equal(h.callbacks[0].options.includeMetadataChanges, true);
  h.callbacks[0].success(snap(runtime(), { fromCache: true }));
  assert.equal(h.emitted.at(-1).runtimeFromCache, true);
  h.callbacks[1].success({ docs: [{ id, data: () => h.liveMessage }, { id: 'bad', data: () => h.liveMessage }], metadata: { fromCache: false, hasPendingWrites: false } });
  assert.equal(h.emitted.at(-1).messages.length, 1);
  assert.match(h.emitted.at(-1).messagesError, /unsupported schema/);
  h.callbacks[0].failure(new Error('denied'));
  assert.equal(h.emitted.at(-1).runtime, null);
  h.store.stop();
  assert.equal(h.stopped(), 2);
  const count = h.emitted.length;
  h.callbacks[0].success(snap(runtime()));
  assert.equal(h.emitted.length, count);
  assert.equal(await h.store.reply(id, 'Answer'), false);
});

test('reply write is create-only scoped and exact readback verified', async () => {
  const h = harness();
  assert.equal(await h.store.reply(id, '  Answer  '), true);
  assert.equal(h.writes.length, 1);
  assert.equal(h.writes[0].ref, `cct_owner_replies/${id}`);
  assert.deepEqual(h.writes[0].value, buildOwnerReply(uid, id, 'Answer', 'SERVER_TIMESTAMP'));
  assert.equal(h.emitted.at(-1).replies[id].verified, true);
  assert.equal(await h.store.reply(id, 'Answer'), true, 'same exact existing answer is safe recovery');
  assert.equal(h.writes.length, 1, 'retries never overwrite');
  assert.equal(await h.store.reply(id, 'Different'), false);
  assert.match(h.emitted.at(-1).replies[id].message, /create-only/);
});

test('reply busy guard and invalid/denied/stale/mismatched/unverified paths fail closed', async () => {
  const h = harness();
  const pending = h.store.reply(id, 'Answer');
  assert.equal(h.emitted.at(-1).replies[id].busy, true);
  assert.equal(await h.store.reply(id, 'Duplicate'), false);
  assert.equal(await pending, true);
  for (const options of [{ denied: true }, { corruptReadback: true }, { runtimeChange: { revision: 4 } },
    { runtimeChange: { updatedAt: '2000-01-01T00:00:00Z' } }, { messageChange: { state: 'ANSWERED' } },
    { messageChange: { policySha256: 'b'.repeat(64) } }, { messageChange: { kind: 'send' } }]) {
    const invalid = harness(options);
    assert.equal(await invalid.store.reply(id, 'Answer'), false, JSON.stringify(options));
    assert.equal(invalid.emitted.at(-1).replies[id].verified, false);
    assert.equal(invalid.emitted.at(-1).replies[id].busy, false);
    assert.equal(invalid.emitted.at(-1).replies[id].error, true);
    if (!options.corruptReadback) assert.equal(invalid.writes.length, 0);
  }
});

test('UI preserves mounted drafts, uses textContent and keeps old auth/diagnostics', async () => {
  const ui = await readFile(new URL('../src/workspace-ui.js', import.meta.url), 'utf8');
  const html = await readFile(new URL('../index.template.html', import.meta.url), 'utf8');
  assert.match(ui, /row\.text\.textContent = message\.text/);
  assert.match(ui, /row\.answer\.textContent/);
  assert.doesNotMatch(ui, /innerHTML|insertAdjacentHTML/);
  assert.match(ui, /messageRows\.get\(message\.messageId\)/);
  assert.match(ui, /connection\.stop\(\)/);
  assert.match(ui, /renderOwnerConnection\(\);\s*\}, 10_000\)/);
  assert.doesNotMatch(ui, /runtimeStatus\(/);
  assert.match(html, /Replies are answer data, not execution approvals/);
  assert.match(html, /id="runtime-diagnostics"/);
  assert.match(html, /id="app-shell" class="shell(?: [^"]+)?" hidden/);
});
