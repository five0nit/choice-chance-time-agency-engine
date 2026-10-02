import assert from 'node:assert/strict';
import test from 'node:test';
import vm from 'node:vm';
import { readFile } from 'node:fs/promises';
import * as save from '../src/discovery-answer-save.js';
import { defaultWorkspace, validateWorkspace } from '../src/workspace-model.js';

const uid = 'owner-fixture';
const id = `q-${'a'.repeat(32)}`;
const nextId = `q-${'b'.repeat(32)}`;
const answer = 'An exact draft.\n  Whitespace stays. ';
const stamp = { toMillis: () => 1000 };
const record = (text = answer, ownerUid = uid) => ({ schemaVersion: 'cct.discovery_answer.v1', ownerUid, questionId: id, text, createdAt: stamp });
const snap = (value = null, metadata = {}) => ({ exists: () => value !== null, data: () => value,
  metadata: { fromCache: false, hasPendingWrites: false, ...metadata } });
const failure = code => Object.assign(new Error(code), { code });
const deferred = () => { let resolve, reject; const promise = new Promise((yes, no) => { resolve = yes; reject = no; }); return { promise, resolve, reject }; };
const flush = () => new Promise(resolve => setImmediate(resolve));
function storage() {
  const data = new Map();
  return { data, getItem: key => data.get(key) ?? null, setItem: (key, value) => data.set(key, value), removeItem: key => data.delete(key) };
}
function fixture(options = {}) {
  const disk = options.disk || storage();
  const drafts = save.createAnswerDraftStore(uid, () => disk);
  if (!options.reloaded) drafts.edit(id, answer);
  const events = [];
  let server = null;
  const saver = save.createAnswerSaver({ ownerUid: uid, drafts, timeoutMs: 8,
    readAnswer: async () => { events.push('read'); return snap(server); },
    checkContext: async () => { events.push('context'); },
    writeAnswer: async (_id, text) => { events.push('write'); server = record(text); }, ...options });
  return { disk, drafts, saver, events, server: value => { server = value; } };
}

test('drafts survive new store instances, retain exact text, and isolate owner plus question', () => {
  const disk = storage();
  const a = save.createAnswerDraftStore(uid, () => disk);
  a.edit(id, answer); a.edit(nextId, 'next question draft'); a.forget();
  const reload = save.createAnswerDraftStore(uid, () => disk);
  assert.equal(reload.read(id).record.text, answer);
  assert.equal(reload.read(nextId).record.text, 'next question draft');
  assert.equal(reload.read(id).durable, true);
  assert.match(save.draftRetention(reload.read(id)), /survives reload/);
  const other = save.createAnswerDraftStore('another/owner', () => disk);
  assert.equal(other.read(id).record.text, '');
  other.edit(id, 'private other owner');
  assert.equal(reload.read(id).record.text, answer);
  assert.equal(disk.data.size, 3);
});

test('unavailable, throwing, full and silently failing storage never claims durable retention', () => {
  for (const provider of [() => undefined, () => { throw Error('SecurityError'); },
    () => ({ getItem: () => null, setItem: () => { throw Error('QuotaExceededError'); } }),
    () => ({ getItem: () => null, setItem: () => {} })]) {
    const drafts = save.createAnswerDraftStore(uid, provider);
    const result = drafts.edit(id, answer);
    assert.equal(result.durable, false);
    assert.equal(drafts.read(id).record.text, answer);
    assert.match(save.draftRetention(result), /only in this tab/);
  }
});

test('forged cross-owner and malformed persisted drafts fail closed without displaying text', () => {
  for (const value of ['{broken', JSON.stringify({ version: 1, ownerUid: 'other', questionId: id, text: 'SECRET', attempt: null })]) {
    const disk = storage(); disk.data.set(`cct.discovery-draft.v1:${uid}:${id}`, value);
    const draft = save.createAnswerDraftStore(uid, () => disk).read(id);
    assert.equal(draft.record.text, ''); assert.equal(draft.blocked, true);
  }
});

test('exact server readback alone clears the draft and schema stays at five fields', async () => {
  const h = fixture();
  await h.saver.save(id);
  assert.deepEqual(h.events, ['read', 'context', 'write', 'read']);
  assert.equal(h.saver.state(id).saved.text, answer);
  assert.equal(h.drafts.read(id).record.text, ''); assert.equal(h.disk.data.size, 0);
  assert.equal(save.validAnswer(record(), uid, id), true);
  assert.equal(save.validAnswer({ ...record(), extra: true }, uid, id), false);
  assert.equal(save.validAnswer(record(answer, 'other'), uid, id), false);
});

test('429 and offline read errors stay visible and never launch a write', async () => {
  for (const code of ['resource-exhausted', 'firestore/resource-exhausted', '429', 'unavailable']) {
    const h = fixture({ readAnswer: async () => { throw failure(code); } });
    await h.saver.save(id);
    assert.deepEqual(h.events, []);
    assert.equal(h.saver.state(id).busy, false);
    assert.equal(h.saver.state(id).saved, null);
    assert.match(h.saver.state(id).message, code === 'unavailable' ? /offline/ : /429/);
    assert.equal(h.drafts.read(id).record.text, answer);
  }
});

test('every save stage bounds a hanging promise and late prerequisite reads cannot write', async () => {
  for (const stage of ['prior', 'context', 'write', 'readback']) {
    const wait = deferred(); let reads = 0, writes = 0;
    const h = fixture({
      readAnswer: async () => { reads++; return stage === 'prior' || stage === 'readback' && reads > 1 ? wait.promise : snap(); },
      checkContext: () => stage === 'context' ? wait.promise : Promise.resolve(),
      writeAnswer: () => { writes++; return stage === 'write' ? wait.promise : Promise.resolve(); },
    });
    await h.saver.save(id);
    assert.equal(h.saver.state(id).busy, false, stage);
    assert.match(h.saver.state(id).message, /Timed out/, stage);
    assert.equal(writes, stage === 'prior' || stage === 'context' ? 0 : 1, stage);
    assert.equal(h.saver.state(id).saved, null, stage);
    wait.resolve(snap()); await flush();
    assert.equal(writes, stage === 'prior' || stage === 'context' ? 0 : 1, `late ${stage}`);
  }
});

test('acknowledged write with failed readback remains verify-only across reload', async () => {
  let reads = 0, writes = 0;
  const h = fixture({ readAnswer: async () => { if (++reads > 1) throw failure('resource-exhausted'); return snap(); },
    writeAnswer: async () => { writes++; } });
  await h.saver.save(id);
  assert.match(h.saver.state(id).message, /429/);
  assert.equal(h.saver.state(id).locked, true);
  assert.equal(h.saver.state(id).saved, null);
  const reload = fixture({ disk: h.disk, reloaded: true, writeAnswer: async () => { writes++; } });
  assert.equal(reload.saver.state(id).locked, true);
  assert.equal(reload.drafts.read(id).record.text, answer);
  await reload.saver.save(id); // Even direct programmatic submit cannot resend.
  assert.equal(writes, 1);
  reload.server(record()); await reload.saver.verify(id);
  assert.equal(reload.saver.state(id).saved.text, answer);
});

test('pending late write cannot be edited, duplicated, or unlocked by absent readback/reload', async () => {
  const pending = deferred(); let writes = 0;
  const h = fixture({ writeAnswer: () => { writes++; return pending.promise; } });
  await h.saver.save(id);
  h.drafts.edit(id, 'different answer');
  assert.equal(h.drafts.read(id).record.text, answer);
  await h.saver.save(id); await h.saver.verify(id);
  const reloaded = fixture({ disk: h.disk, reloaded: true, writeAnswer: () => { writes++; } });
  await reloaded.saver.save(id);
  assert.equal(writes, 1);
  assert.equal(reloaded.saver.state(id).locked, true);
  pending.resolve(); await flush();
  assert.equal(reloaded.saver.state(id).record.attempt.state, 'acknowledged');
  await reloaded.saver.save(id); assert.equal(writes, 1);
  reloaded.server(record()); await reloaded.saver.verify(id);
  assert.equal(reloaded.saver.state(id).saved.text, answer);
});

test('definite rejection can retry, but MUST read before writing; unknown rejection stays locked', async () => {
  let rejected = true;
  const h = fixture({ writeAnswer: async (_id, text) => {
    h.events.push('write'); if (rejected) throw failure('resource-exhausted'); h.server(record(text));
  } });
  await h.saver.save(id);
  assert.equal(h.saver.state(id).locked, false);
  assert.match(h.saver.state(id).message, /429/);
  rejected = false;
  await h.saver.save(id);
  assert.deepEqual(h.events, ['read', 'context', 'write', 'read', 'context', 'write', 'read']);
  const unknown = fixture({ writeAnswer: async () => { throw failure('unavailable'); } });
  await unknown.saver.save(id);
  assert.equal(unknown.saver.state(id).locked, true);
});

test('retry sees an existing reply and never overwrites; conflict keeps different local draft', async () => {
  const h = fixture({ writeAnswer: async () => { h.events.push('write'); throw failure('resource-exhausted'); } });
  await h.saver.save(id);
  h.server(record('existing immutable reply'));
  await h.saver.save(id);
  assert.deepEqual(h.events, ['read', 'context', 'write', 'read']);
  assert.equal(h.saver.state(id).saved, null);
  assert.equal(h.saver.state(id).existing.text, 'existing immutable reply');
  assert.equal(h.drafts.read(id).record.text, answer);
});

test('cache, pending metadata, wrong-owner or wrong-text readbacks cannot verify this draft', async () => {
  for (const snapshot of [snap(record(), { fromCache: true }), snap(record(), { hasPendingWrites: true }),
    snap(record(answer, 'other')), snap(record('not the submitted draft'))]) {
    let reads = 0;
    const h = fixture({ readAnswer: async () => ++reads === 1 ? snap() : snapshot, writeAnswer: async () => {} });
    await h.saver.save(id);
    assert.equal(h.saver.state(id).saved, null);
    assert.equal(h.drafts.read(id).record.text, answer);
  }
});

test('session closure before context completes prevents writes and double submit stays single', async () => {
  const wait = deferred(); let active = true, writes = 0;
  const h = fixture({ isActive: () => active, checkContext: () => wait.promise, writeAnswer: () => { writes++; } });
  const one = h.saver.save(id); await flush();
  await h.saver.save(id); active = false; wait.resolve(); await one;
  assert.equal(writes, 0);
});

test('no write is sent when the durable intent cannot be persisted', async () => {
  const disk = storage(); const h = fixture({ disk });
  disk.setItem = () => { throw Error('QuotaExceededError'); };
  await h.saver.save(id);
  assert.deepEqual(h.events, ['read', 'context']);
  assert.match(h.saver.state(id).message, /no reply was sent/);
  assert.equal(h.saver.state(id).durable, false);
});

class Element {
  constructor() { this.value = ''; this.textContent = ''; this.children = []; this.dataset = {}; this.listeners = new Map(); }
  append(...children) { this.children.push(...children); }
  replaceChildren(...children) { this.textContent = ''; this.children = children; }
  setAttribute() {}
  addEventListener(name, fn) { this.listeners.set(name, fn); }
  removeEventListener(name) { this.listeners.delete(name); }
  scrollIntoView() {}
  focus() {}
  emit(name) { return this.listeners.get(name)?.({ preventDefault() {} }); }
}
const discovery = ownerUid => ({ schemaVersion: 'cct.discovery.v1', ownerUid, conversationId: 'fixture', revision: 1,
  updatedAt: new Date().toISOString(), executionEnabled: false, phase: 'AWAITING_INPUT', reason: '',
  question: { id, text: 'Fixture question' }, answersConsumed: 0, history: [], unknowns: [],
  learning: { wants: [], frustrations: [], constraints: [], delegation: [] }, workIdeas: [] });
async function ui({ disk = storage(), ownerUid = uid, read, write, elements = new Map() } = {}) {
  const node = id => { if (!elements.has(id)) elements.set(id, new Element()); return elements.get(id); };
  const subscriptions = new Map(); const workspace = { ...defaultWorkspace(ownerUid), revision: 1 };
  const payloads = [];
  const context = vm.createContext({ ...save, validateWorkspace,
    createAnswerDraftStore: owner => save.createAnswerDraftStore(owner, () => disk),
    createAnswerSaver: options => save.createAnswerSaver({ ...options, timeoutMs: 8 }),
    answerStage: (stage, action) => save.answerStage(stage, action, 8),
    document: { getElementById: node, createElement: () => new Element() }, navigator: { onLine: true },
    window: Object.assign(new Element(), { setInterval: () => 1, clearInterval() {} }),
    mountOwnerWork: () => () => {}, WORK_PHASES: [], workReason: text => text,
    doc: (_db, collection, id) => ({ collection, id }), serverTimestamp: () => stamp,
    onSnapshot: (ref, _opts, next, fail) => { subscriptions.set(ref.collection, { next, fail }); return () => subscriptions.delete(ref.collection); },
    getDocFromServer: async ref => read ? read(ref) : snap(ref.collection === 'cct_discovery' ? discovery(ownerUid) : ref.collection === 'cct_workspace' ? workspace : null),
    setDoc: async (ref, payload) => { payloads.push(payload); return write?.(ref, payload); },
  });
  const source = await readFile(new URL('../src/discovery.js', import.meta.url), 'utf8');
  vm.runInContext(source.replace(/^import[\s\S]*?;\n/gm, '').replaceAll('export function ', 'function '), context);
  const mount = context.mountDiscovery({}, ownerUid, () => ({ ready: true, exists: true, verified: true, busy: false, workspace }), () => {});
  subscriptions.get('cct_discovery').next(snap(discovery(ownerUid)));
  return { node, context, disk, elements, subscriptions, mount, payloads,
    type(text) { node('discovery-input').value = text; node('discovery-input').emit('input'); },
    submit: () => node('discovery-form').emit('submit') };
}

test('mounted UI restores drafts after reload and never exposes one owner to another', async () => {
  const h = await ui(); h.type(answer); h.mount.stop();
  assert.equal(h.node('discovery-input').value, '');
  const other = await ui({ disk: h.disk, elements: h.elements, ownerUid: 'another' });
  assert.equal(other.node('discovery-input').value, ''); other.mount.stop();
  const reload = await ui({ disk: h.disk, elements: h.elements });
  assert.equal(reload.node('discovery-input').value, answer); reload.mount.stop();
});

test('mounted UI surfaces quota read failure without losing draft or sending a write', async () => {
  const h = await ui({ read: async () => { throw failure('resource-exhausted'); } });
  h.type(answer); await h.submit();
  assert.match(h.node('discovery-feedback').textContent, /429/);
  assert.match(h.node('discovery-feedback').textContent, /survives reload/);
  assert.equal(h.node('discovery-input').value, answer);
  assert.equal(h.payloads.length, 0); h.mount.stop();
});

test('mounted UI releases spinner after hung write, then offers read-only verification, including refresh', async () => {
  const pending = deferred(); const h = await ui({ write: () => pending.promise });
  h.type(answer); await h.submit();
  assert.equal(h.node('discovery-input').disabled, false);
  assert.equal(h.node('discovery-input').readOnly, true);
  assert.equal(h.node('discovery-submit').textContent, 'Check saved reply');
  assert.match(h.node('discovery-feedback').textContent, /Timed out/);
  await h.submit(); await h.mount.refresh();
  assert.equal(h.payloads.length, 1);
  assert.deepEqual(Object.keys(h.payloads[0]).sort(), ['createdAt', 'ownerUid', 'questionId', 'schemaVersion', 'text']);
  assert.equal(h.payloads[0].text, answer);
  pending.resolve(); await flush();
  h.subscriptions.get('cct_discovery_answers').next(snap(record()));
  assert.equal(h.node('discovery-form').hidden, true);
  assert.match(h.node('discovery-feedback').textContent, /Saved and verified/);
  assert.equal(h.disk.data.size, 0); h.mount.stop();
});

test('mounted UI reports tab-only storage fallback accurately and does not silently send', async () => {
  const h = await ui({ disk: { getItem: () => null, setItem: () => { throw Error('QuotaExceededError'); } } });
  h.type(answer);
  assert.match(h.node('discovery-feedback').textContent, /only in this tab/);
  await h.submit(); assert.equal(h.payloads.length, 0);
  assert.match(h.node('discovery-feedback').textContent, /only in this tab/); h.mount.stop();
});
