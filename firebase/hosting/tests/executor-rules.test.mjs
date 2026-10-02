import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test, { after, before, beforeEach } from 'node:test';
import {
  assertFails,
  assertSucceeds,
  initializeTestEnvironment,
} from '@firebase/rules-unit-testing';
import {
  collection,
  collectionGroup,
  deleteDoc,
  deleteField,
  doc,
  documentId,
  getDocFromServer,
  getDocsFromServer,
  limit,
  orderBy,
  query,
  serverTimestamp,
  setDoc,
  Timestamp,
  updateDoc,
  where,
  writeBatch,
} from 'firebase/firestore';

// This suite only connects to an already-running local emulator. Its own demo
// project prevents clearFirestore() from racing the legacy rules test suites.
const projectId = 'demo-cctae-executor';
const ownerUid = 'replace-with-owner-firebase-uid';
const ownerEmail = 'owner@example.invalid';
const nonceA = 'activation_A_0001';
const nonceB = 'activation_B_0002';
const nonceC = 'activation_C_0003';
const runId = `run-${'a'.repeat(32)}`;
const maxRevision = 2147483647;
const controlPath = 'cct_executor_control/current';
const runtimePath = 'cct_executor_runtime/current';
const runPath = `cct_executor_runs/${runId}`;
const epoch = Timestamp.fromMillis(0);
let env;

function claims() {
  return {
    email: ownerEmail,
    email_verified: true,
    firebase: { sign_in_provider: 'google.com' },
  };
}

function owner() {
  return env.authenticatedContext(ownerUid, claims()).firestore();
}

function control(overrides = {}) {
  return {
    schemaVersion: 'cct.executor_control.v1',
    ownerUid,
    revision: 1,
    updatedAt: serverTimestamp(),
    enabled: false,
    runNonce: nonceA,
    task: 'project-audit',
    maxRuns: 1,
    intervalSeconds: 60,
    ...overrides,
  };
}

function activation(overrides = {}) {
  return control({ revision: 2, enabled: true, runNonce: nonceB, ...overrides });
}

function runtime(overrides = {}) {
  return {
    schemaVersion: 'cct.executor_runtime.v1',
    ownerUid,
    projectId: 'demo-cctae',
    revision: 1,
    controlSha256: null,
    updatedAt: '2000-01-01T00:00:00Z',
    state: 'OFF',
    reasonCode: 'CONTROL_OFF',
    task: 'project-audit',
    runNonce: nonceA,
    completedRuns: 0,
    maxRuns: 1,
    lastRunId: null,
    nextRunAt: null,
    scope: 'BOUNDED_TEST_EXECUTOR',
    ...overrides,
  };
}

function runReceipt(id = runId) {
  return {
    schemaVersion: 'cct.executor_run.v1',
    ownerUid,
    runId: id,
    runNonce: nonceA,
    revision: 1,
    task: 'project-audit',
    state: 'COMPLETED',
    startedAt: '2000-01-01T00:00:00Z',
    finishedAt: '2000-01-01T00:00:01Z',
    reportText: 'Emulator fixture: bounded project-audit report.',
    artifactSha256: null,
    reasonCode: 'COMPLETED',
  };
}

async function seed(entries) {
  // Rules-disabled fixture writes model host/Admin transport, not browser auth.
  await env.withSecurityRulesDisabled(async (context) => {
    const batch = writeBatch(context.firestore());
    for (const [path, value] of entries) batch.set(doc(context.firestore(), path), value);
    await batch.commit();
  });
}

before(async () => {
  env = await initializeTestEnvironment({
    projectId,
    firestore: {
      host: '127.0.0.1',
      port: 8080,
      rules: await readFile(new URL('../../../firestore.rules', import.meta.url), 'utf8'),
    },
  });
});
beforeEach(async () => env.clearFirestore());
after(async () => env?.cleanup());

test('exact Google owner can bootstrap OFF and reload resolved server timestamp', async () => {
  const db = owner();
  for (const path of [controlPath, runtimePath, runPath]) {
    assert.equal((await assertSucceeds(getDocFromServer(doc(db, path)))).exists(), false);
  }
  await assertSucceeds(setDoc(doc(db, controlPath), control()));
  const saved = (await assertSucceeds(getDocFromServer(doc(owner(), controlPath)))).data();
  assert.deepEqual(Object.keys(saved).sort(), Object.keys(control()).sort());
  assert.deepEqual({ ...saved, updatedAt: null }, { ...control(), updatedAt: null });
  assert.ok(saved.updatedAt instanceof Timestamp);
  assert.ok(saved.updatedAt.toMillis() > 0);
  assert.equal((await getDocFromServer(doc(db, runtimePath))).exists(), false);
});

test('create is OFF-only and requires revision exactly one', async () => {
  const db = owner();
  await assertFails(setDoc(doc(db, controlPath), control({ enabled: true })));
  for (const revision of [2, maxRevision]) {
    await assertFails(setDoc(doc(db, controlPath), control({ revision })));
  }
  await assertSucceeds(setDoc(doc(db, controlPath), control()));
  // A repeated bootstrap is an update, not a second revision-one create.
  await assertFails(setDoc(doc(db, controlPath), control()));
});

test('fresh-nonce run-once, bounded restart and policy-preserving OFF are accepted', async () => {
  const db = owner();
  const ref = doc(db, controlPath);
  await assertSucceeds(setDoc(ref, control()));
  await assertSucceeds(setDoc(ref, activation()));
  const once = (await getDocFromServer(ref)).data();
  assert.equal(once.enabled, true);
  assert.equal(once.maxRuns, 1);
  assert.equal(once.runNonce, nonceB);
  const restart = activation({
    revision: 3, runNonce: nonceC, task: 'public-docs-check', maxRuns: 3, intervalSeconds: 3600,
  });
  await assertSucceeds(setDoc(ref, restart));
  // A merge-style stop needs only these fields and does not reset policy.
  await assertSucceeds(updateDoc(ref, { enabled: false, revision: 4, updatedAt: serverTimestamp() }));
  const stopped = (await getDocFromServer(ref)).data();
  assert.deepEqual({ ...stopped, updatedAt: null }, { ...restart, enabled: false, revision: 4, updatedAt: null });
  assert.ok(stopped.updatedAt instanceof Timestamp);
  await assertSucceeds(setDoc(ref, { ...stopped, revision: 5, updatedAt: serverTimestamp() }));
  assert.equal((await getDocFromServer(ref)).data().revision, 5);
});

for (const [label, runNonce] of [
  ['minimum length and mixed ASCII', 'Aa0_'.repeat(4)],
  ['maximum length', 'Z'.repeat(80)],
  ['ASCII letters, digits, underscore and hyphen', 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-'],
]) {
  test(`nonce accepts ${label}`, async () => {
    const db = owner();
    await assertSucceeds(setDoc(doc(db, controlPath), control({ runNonce })));
    await assertSucceeds(setDoc(doc(db, controlPath), activation()));
  });
}

test('interior run and interval bounds also permit an explicit fresh activation', async () => {
  const ref = doc(owner(), controlPath);
  await assertSucceeds(setDoc(ref, control({ maxRuns: 2, intervalSeconds: 300 })));
  await assertSucceeds(setDoc(ref, activation({ maxRuns: 2, intervalSeconds: 300 })));
  const saved = (await getDocFromServer(ref)).data();
  assert.equal(saved.maxRuns, 2);
  assert.equal(saved.intervalSeconds, 300);
});

test('same-nonce activation, refresh, policy mutation and post-OFF replay are denied', async () => {
  const db = owner();
  const ref = doc(db, controlPath);
  await assertSucceeds(setDoc(ref, control()));
  await assertFails(setDoc(ref, activation({ runNonce: nonceA })));
  await assertSucceeds(setDoc(ref, activation()));
  for (const overrides of [{}, { maxRuns: 3 }, { intervalSeconds: 300 }, { task: 'public-docs-check' }]) {
    await assertFails(setDoc(ref, activation({ revision: 3, ...overrides })));
  }
  await assertSucceeds(updateDoc(ref, { revision: 3, enabled: false, updatedAt: serverTimestamp() }));
  await assertFails(setDoc(ref, activation({ revision: 4 })));
  await assertSucceeds(setDoc(ref, activation({ revision: 4, runNonce: nonceC })));
  assert.equal((await getDocFromServer(ref)).data().runNonce, nonceC);
  // Historical consumed-nonce tracking beyond the previous document is a host
  // invariant; these rules prevent immediate reuse, not unlimited nonce history.
});

test('OFF cannot mutate nonce or policy, even when the proposed values are valid', async () => {
  const db = owner();
  const ref = doc(db, controlPath);
  await assertSucceeds(setDoc(ref, control()));
  await assertSucceeds(setDoc(ref, activation()));
  for (const overrides of [
    { runNonce: nonceC }, { task: 'public-docs-check' }, { maxRuns: 3 }, { intervalSeconds: 300 },
  ]) {
    await assertFails(setDoc(ref, activation({ revision: 3, enabled: false, ...overrides })));
  }
  await assertSucceeds(setDoc(ref, activation({ revision: 3, enabled: false })));
  await assertFails(setDoc(ref, activation({ revision: 4, enabled: false, maxRuns: 2 })));
});

for (const [label, receipt] of [
  ['missing', null],
  ['stale RUNNING for another revision and nonce', runtime({ state: 'RUNNING', revision: 999, runNonce: nonceC })],
  ['INVALID with a mismatched owner', runtime({ state: 'INVALID', ownerUid: 'other-owner', revision: null })],
]) {
  test(`owner can turn OFF when runtime is ${label}`, async () => {
    const entries = [[controlPath, activation({ revision: 7, updatedAt: epoch })]];
    if (receipt) entries.push([runtimePath, receipt]);
    await seed(entries);
    const db = owner();
    await assertSucceeds(updateDoc(doc(db, controlPath), {
      revision: 8, enabled: false, updatedAt: serverTimestamp(),
    }));
    const saved = (await getDocFromServer(doc(db, controlPath))).data();
    assert.equal(saved.enabled, false);
    assert.equal(saved.revision, 8);
    assert.equal(saved.runNonce, nonceB);
    assert.equal(saved.task, 'project-audit');
    assert.equal(saved.maxRuns, 1);
    assert.equal(saved.intervalSeconds, 60);
    const actualRuntime = await getDocFromServer(doc(db, runtimePath));
    assert.equal(actualRuntime.exists(), receipt !== null);
    if (receipt) assert.deepEqual(actualRuntime.data(), receipt);
  });
}

test('revision must advance exactly once, rejecting stale and skipped ON and OFF writes', async () => {
  await seed([[controlPath, activation({ revision: 7, updatedAt: epoch })]]);
  const ref = doc(owner(), controlPath);
  for (const revision of [1, 6, 7, 9]) {
    await assertFails(setDoc(ref, activation({ revision, runNonce: nonceC })));
    await assertFails(setDoc(ref, activation({ revision, enabled: false })));
  }
  await assertSucceeds(setDoc(ref, activation({ revision: 8, enabled: false })));
});

test('upper revision bound accepts the final increment and rejects overflow', async () => {
  await seed([[controlPath, activation({ revision: maxRevision - 1, updatedAt: epoch })]]);
  const ref = doc(owner(), controlPath);
  await assertSucceeds(setDoc(ref, activation({ revision: maxRevision, enabled: false })));
  assert.equal((await getDocFromServer(ref)).data().revision, maxRevision);
  await assertFails(setDoc(ref, activation({ revision: maxRevision + 1, runNonce: nonceC })));
  await assertFails(setDoc(ref, activation({ revision: maxRevision + 1, enabled: false })));
});

const invalidFields = {
  schemaVersion: ['cct.executor_control.v2', '', 1, true, null, [], {}],
  ownerUid: ['other-owner', ownerEmail, '', 1, true, null, [], {}],
  revision: [0, -1, maxRevision + 1, 1.5, true, '1', null, [], {}, NaN, Infinity],
  updatedAt: [epoch, Timestamp.fromDate(new Date('2100-01-01T00:00:00Z')), '2000-01-01T00:00:00Z', 0, true, null, [], { seconds: 0, nanoseconds: 0 }],
  enabled: ['true', 'false', 0, 1, null, [], {}],
  runNonce: ['', 'a'.repeat(15), 'a'.repeat(81), 'a'.repeat(16) + '\n', '\n' + 'a'.repeat(16),
    'a'.repeat(15) + ' ', 'a'.repeat(15) + '.', 'a'.repeat(15) + '/', 'a'.repeat(15) + 'é',
    'a'.repeat(15) + 'Ａ', 'a'.repeat(15) + '\u200b', 'a'.repeat(15) + '\u0000', 123, true, null, [], {}],
  task: ['', 'PROJECT-AUDIT', 'project-audit ', 'arbitrary-shell', 'https://example.com', 1, true, null, [], {}],
  maxRuns: [0, -1, 4, 1.5, true, '1', null, [], {}, NaN, Infinity],
  intervalSeconds: [0, -1, 59, 3601, 60.5, true, '60', null, [], {}, NaN, Infinity],
};

for (const [field, invalidValues] of Object.entries(invalidFields)) {
  test(`control rejects malformed ${field} on both create and enabled update`, async () => {
    const ref = doc(owner(), controlPath);
    for (const value of invalidValues) {
      await assertFails(setDoc(ref, control({ [field]: value })));
    }
    await assertSucceeds(setDoc(ref, control()));
    for (const value of invalidValues) {
      await assertFails(setDoc(ref, activation({ [field]: value })));
    }
    assert.equal((await getDocFromServer(ref)).data().revision, 1);
  });
}

for (const field of Object.keys(control())) {
  test(`control requires ${field} on create and update, including field deletion`, async () => {
    const ref = doc(owner(), controlPath);
    const missingCreate = control();
    delete missingCreate[field];
    await assertFails(setDoc(ref, missingCreate));
    await assertSucceeds(setDoc(ref, control()));
    const missingUpdate = activation();
    delete missingUpdate[field];
    await assertFails(setDoc(ref, missingUpdate));
    await assertFails(updateDoc(ref, { ...activation(), [field]: deleteField() }));
  });
}

test('extra authority, credentials, arbitrary commands and nested fields are denied', async () => {
  const ref = doc(owner(), controlPath);
  const extras = [
    { unexpected: true }, { idToken: 'emulator-fixture-not-a-token' },
    { command: 'fixture-command' }, { url: 'https://example.com' },
    { permissions: { workspaceWrite: true } }, { runtime: { state: 'READY' } },
  ];
  for (const extra of extras) await assertFails(setDoc(ref, control(extra)));
  await assertSucceeds(setDoc(ref, control()));
  for (const extra of extras) await assertFails(setDoc(ref, activation(extra)));
  await assertFails(setDoc(ref, { ...activation(), extra: {} }, { merge: true }));
  await assertFails(updateDoc(ref, { ...activation(), 'extra.grant': true }));
  assert.deepEqual(Object.keys((await getDocFromServer(ref)).data()).sort(), Object.keys(control()).sort());
});

test('resolved old timestamps cannot be retained or replayed for ON or OFF', async () => {
  await seed([[controlPath, control({ updatedAt: epoch })]]);
  const ref = doc(owner(), controlPath);
  await assertFails(updateDoc(ref, { enabled: true, revision: 2, runNonce: nonceB }));
  await assertFails(updateDoc(ref, { enabled: false, revision: 2 }));
  await assertFails(setDoc(ref, activation({ updatedAt: epoch })));
  await assertSucceeds(setDoc(ref, activation()));
  assert.ok((await getDocFromServer(ref)).data().updatedAt instanceof Timestamp);
});

const rejectedIdentities = [
  ['unauthenticated', null],
  ['wrong UID only', { uid: 'other-owner' }],
  ['wrong email only', { claims: { email: 'other@example.com' } }],
  ['case-changed email', { claims: { email: 'Costea.Michael@gmail.com' } }],
  ['unverified email', { claims: { email_verified: false } }],
  ['string verification claim', { claims: { email_verified: 'true' } }],
  ['numeric verification claim', { claims: { email_verified: 1 } }],
  ['password provider', { claims: { firebase: { sign_in_provider: 'password' } } }],
  ['custom provider', { claims: { firebase: { sign_in_provider: 'custom' } } }],
  ['anonymous provider', { claims: { firebase: { sign_in_provider: 'anonymous' } } }],
  ['missing provider claim', { claims: { firebase: {} } }],
  ['missing email claim', { omit: 'email' }],
  ['missing verification claim', { omit: 'email_verified' }],
];

for (const [label, identity] of rejectedIdentities) {
  test(`${label} cannot read executor data, create control, activate, stop or forge receipts`, async () => {
    const token = { ...claims(), ...identity?.claims };
    if (identity?.omit) delete token[identity.omit];
    const db = identity === null ? env.unauthenticatedContext().firestore()
      : env.authenticatedContext(identity.uid ?? ownerUid, token).firestore();
    for (const path of [controlPath, runtimePath, runPath]) {
      await assertFails(getDocFromServer(doc(db, path)));
    }
    await assertFails(setDoc(doc(db, controlPath), control()));
    await assertFails(setDoc(doc(db, runtimePath), runtime()));
    await assertFails(setDoc(doc(db, runPath), runReceipt()));
    await seed([
      [controlPath, control({ updatedAt: epoch })],
      [runtimePath, runtime()], [runPath, runReceipt()],
    ]);
    for (const path of [controlPath, runtimePath, runPath]) {
      await assertFails(getDocFromServer(doc(db, path)));
      await assertFails(deleteDoc(doc(db, path)));
    }
    await assertFails(getDocsFromServer(query(collection(db, 'cct_executor_runs'), limit(20))));
    await assertFails(setDoc(doc(db, controlPath), activation()));
    await assertFails(updateDoc(doc(db, controlPath), { enabled: false, revision: 2, updatedAt: serverTimestamp() }));
    await assertFails(updateDoc(doc(db, runtimePath), { state: 'READY' }));
    await assertFails(updateDoc(doc(db, runPath), { reportText: 'forged fixture' }));
  });
}

test('control and runtime are get-only fixed documents; lists, alternate docs and subcollections are denied', async () => {
  const db = owner();
  await assertSucceeds(setDoc(doc(db, controlPath), control()));
  await seed([[runtimePath, runtime()]]);
  for (const name of ['cct_executor_control', 'cct_executor_runtime']) {
    await assertSucceeds(getDocFromServer(doc(db, name, 'current')));
    await assertFails(getDocsFromServer(collection(db, name)));
    await assertFails(getDocsFromServer(query(collection(db, name), limit(1))));
    await assertFails(getDocsFromServer(query(collection(db, name), where(documentId(), '==', 'current'), limit(1))));
    await assertFails(deleteDoc(doc(db, name, 'current')));
    for (const path of [`${name}/other`, `${name}/CURRENT`, `${name}/current/private/detail`]) {
      await assertFails(setDoc(doc(db, path), control()));
      await seed([[path, control({ updatedAt: epoch })]]);
      await assertFails(getDocFromServer(doc(db, path)));
      await assertFails(updateDoc(doc(db, path), { revision: 2, updatedAt: serverTimestamp() }));
      await assertFails(deleteDoc(doc(db, path)));
    }
  }
});

test('owner may get valid run IDs and list at most twenty host receipts', async () => {
  const db = owner();
  // Limits are required even when the collection is empty.
  await assertFails(getDocsFromServer(collection(db, 'cct_executor_runs')));
  await assertFails(getDocsFromServer(query(collection(db, 'cct_executor_runs'), limit(21))));
  assert.equal((await assertSucceeds(getDocsFromServer(query(collection(db, 'cct_executor_runs'), limit(20))))).size, 0);
  const ids = Array.from({ length: 21 }, (_, i) => `run-${i.toString(16).padStart(32, '0')}`);
  await seed(ids.map((id) => [`cct_executor_runs/${id}`, runReceipt(id)]));
  for (const id of [ids[0], ids[20]]) {
    const saved = await assertSucceeds(getDocFromServer(doc(db, 'cct_executor_runs', id)));
    assert.deepEqual(saved.data(), runReceipt(id));
  }
  for (const maximum of [1, 20]) {
    const result = await assertSucceeds(getDocsFromServer(query(
      collection(db, 'cct_executor_runs'), orderBy('startedAt', 'desc'), limit(maximum),
    )));
    assert.equal(result.size, maximum);
    assert.ok(result.docs.every((snapshot) => /^run-[0-9a-f]{32}$/.test(snapshot.id)));
  }
  await assertFails(getDocsFromServer(collection(db, 'cct_executor_runs')));
  await assertFails(getDocsFromServer(query(collection(db, 'cct_executor_runs'), limit(21))));
  await assertFails(getDocsFromServer(query(collection(db, 'cct_executor_runs'), limit(100))));
});

test('malformed run IDs and nested receipt documents cannot be read or written by clients', async () => {
  const db = owner();
  const invalidIds = [
    'current', `RUN-${'a'.repeat(32)}`, `run-${'A'.repeat(32)}`,
    `run-${'a'.repeat(31)}`, `run-${'a'.repeat(33)}`, `run-${'g'.repeat(32)}`,
    `run-${'a'.repeat(31)}_`, `run-${'a'.repeat(32)}\n`,
  ];
  for (const id of invalidIds) {
    const ref = doc(db, 'cct_executor_runs', id);
    await assertFails(setDoc(ref, runReceipt(id)));
    await seed([[`cct_executor_runs/${id}`, runReceipt(id)]]);
    await assertFails(getDocFromServer(ref));
    await assertFails(updateDoc(ref, { state: 'COMPLETED' }));
    await assertFails(deleteDoc(ref));
  }
  for (const path of [`${runPath}/private/detail`, `unrelated/current/cct_executor_runs/${runId}`]) {
    await seed([[path, runReceipt()]]);
    await assertFails(getDocFromServer(doc(db, path)));
    await assertFails(setDoc(doc(db, path), runReceipt()));
    await assertFails(deleteDoc(doc(db, path)));
  }
  await assertFails(getDocsFromServer(query(collectionGroup(db, 'cct_executor_runs'), limit(20))));
});

test('runtime and run receipts are host-only for creates, replacements, merges, updates and deletes', async () => {
  const db = owner();
  const receipts = [[runtimePath, runtime()], [runPath, runReceipt()]];
  for (const [path, value] of receipts) {
    await assertFails(setDoc(doc(db, path), value));
    await assertFails(setDoc(doc(db, path), value, { merge: true }));
  }
  await seed(receipts);
  for (const [path, value] of receipts) {
    const ref = doc(db, path);
    assert.deepEqual((await assertSucceeds(getDocFromServer(ref))).data(), value);
    await assertFails(setDoc(ref, value));
    await assertFails(setDoc(ref, value, { merge: true }));
    await assertFails(updateDoc(ref, { state: 'RUNNING' }));
    await assertFails(deleteDoc(ref));
    assert.deepEqual((await getDocFromServer(ref)).data(), value);
  }
  const privilegedClaimDb = env.authenticatedContext(ownerUid, { ...claims(), admin: true, host: true }).firestore();
  await assertFails(setDoc(doc(privilegedClaimDb, runtimePath), runtime()));
  await assertFails(setDoc(doc(privilegedClaimDb, runPath), runReceipt()));
});

test('a valid activation cannot smuggle a forged receipt in an atomic batch', async () => {
  const db = owner();
  const ref = doc(db, controlPath);
  await assertSucceeds(setDoc(ref, control()));
  for (const [path, value] of [[runtimePath, runtime({ state: 'READY' })], [runPath, runReceipt()]]) {
    const batch = writeBatch(db);
    batch.set(ref, activation());
    batch.set(doc(db, path), value);
    await assertFails(batch.commit());
    const saved = (await getDocFromServer(ref)).data();
    assert.equal(saved.enabled, false);
    assert.equal(saved.revision, 1);
    assert.equal((await getDocFromServer(doc(db, path))).exists(), false);
  }
});
