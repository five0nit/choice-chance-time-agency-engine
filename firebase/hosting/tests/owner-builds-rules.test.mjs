import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test, { before, beforeEach, after } from 'node:test';
import { assertFails, assertSucceeds, initializeTestEnvironment } from '@firebase/rules-unit-testing';
import { collection, collectionGroup, deleteDoc, doc, getDocFromServer, getDocsFromServer,
  limit, query, serverTimestamp, setDoc, Timestamp, updateDoc, where, writeBatch } from 'firebase/firestore';

// Strictly local emulator. Synthetic identities and private artifacts only.
const ownerUid = 'replace-with-owner-firebase-uid';
const controlPath = 'cct_owner_build_controls/current';
const statusPath = 'cct_owner_build_controls_status/current';
const buildId = 'delivery-fixture';
const buildPath = `cct_owner_builds/${buildId}`;
const requestId = 'request-fixture';
const requestPath = `cct_owner_build_requests/${requestId}`;
const receiptPath = `cct_owner_build_request_status/${requestId}`;
const digest = 'a'.repeat(64);
const claims = () => ({ email: 'owner@example.invalid', email_verified: true,
  firebase: { sign_in_provider: 'google.com' } });
const workspace = (changes = {}) => ({ schemaVersion: 'cct.owner_workspace.v1', ownerUid,
  learningEnabled: true, autonomyMode: 'full', autonomyAcknowledged: true,
  permissions: { workspaceRead: true, workspaceWrite: true }, ...changes });
const host = (changes = {}) => ({ schemaVersion: 'cct.owner_build_controls_status.v1', ownerUid,
  requestedRevision: 0, effectiveRevision: 0, state: 'READY', reason: 'Fixture',
  effective: { maxDailyJobs: 1, maxDailyProviderCalls: 12, maxDailyToolCalls: 4 },
  ceilings: { maxDailyJobs: 4, maxDailyProviderCalls: 20, maxDailyToolCalls: 12 },
  usage: { jobs: 1, providerCalls: 4, toolCalls: 1 }, ...changes });
const build = (changes = {}) => ({ schemaVersion: 'cct.owner_build.v1', ownerUid,
  buildId, rootBuildId: buildId, parentBuildId: '', action: 'build', status: 'COMPLETE',
  title: 'Private fixture', bundleDigest: digest, archived: false, files: [], ...changes });
const control = (changes = {}) => ({ schemaVersion: 'cct.owner_build_controls.v1', ownerUid,
  revision: 1, maxDailyJobs: 2, maxDailyProviderCalls: 14, maxDailyToolCalls: 5,
  updatedAt: serverTimestamp(), ...changes });
const request = (changes = {}) => ({ schemaVersion: 'cct.owner_build_request.v1', ownerUid,
  requestId, parentBuildId: buildId, parentDigest: digest, action: 'upgrade',
  instructions: 'Improve the fixture output.', maxProviderCalls: 6, maxToolCalls: 2,
  createdAt: serverTimestamp(), expiresAt: Timestamp.fromMillis(Date.now() + 3600000),
  controlRevision: 0, ...changes });
let env;
const owner = () => env.authenticatedContext(ownerUid, claims()).firestore();
const seed = async entries => env.withSecurityRulesDisabled(async context => {
  const batch = writeBatch(context.firestore());
  for (const [path, value] of entries) batch.set(doc(context.firestore(), path), value);
  await batch.commit();
});
const seedReady = async () => seed([[statusPath, host()], [buildPath, build()],
  ['cct_workspace/current', workspace()]]);
before(async () => {
  env = await initializeTestEnvironment({ projectId: 'demo-cctae-owner-builds',
    firestore: { host: '127.0.0.1', port: 8080,
      rules: await readFile(new URL('../../../firestore.rules', import.meta.url), 'utf8') } });
});
beforeEach(async () => env.clearFirestore());
after(async () => env?.cleanup());

test('owner reads absent intent/readback/request receipts before first use', async () => {
  for (const path of [controlPath, statusPath, requestPath, receiptPath]) {
    const snapshot = await assertSucceeds(getDocFromServer(doc(owner(), path)));
    assert.equal(snapshot.exists(), false);
  }
});

test('owner reads host-owned artifacts and bounded owner-filtered collections', async () => {
  await seedReady();
  await seed([[requestPath, request({ createdAt: Timestamp.now() })],
    [receiptPath, { ownerUid, requestId, state: 'QUEUED' }]]);
  assert.equal((await assertSucceeds(getDocFromServer(doc(owner(), buildPath)))).data().title, 'Private fixture');
  for (const name of ['cct_owner_builds', 'cct_owner_build_requests', 'cct_owner_build_request_status']) {
    const db = owner();
    const rows = await assertSucceeds(getDocsFromServer(query(collection(db, name), where('ownerUid', '==', ownerUid), limit(100))));
    assert.equal(rows.size, 1);
    await assertFails(getDocsFromServer(collection(db, name)));
    await assertFails(getDocsFromServer(query(collection(db, name), limit(100))));
    await assertFails(getDocsFromServer(query(collection(db, name), where('ownerUid', '==', ownerUid), limit(101))));
    await assertFails(getDocsFromServer(query(collectionGroup(db, name), where('ownerUid', '==', ownerUid), limit(20))));
  }
});

test('runtime artifacts, usage, archive state and request outcomes cannot be forged', async () => {
  await seedReady();
  await seed([[receiptPath, { ownerUid, requestId, state: 'QUEUED' }]]);
  for (const [path, value] of [[buildPath, build()], [statusPath, host()],
    [receiptPath, { ownerUid, state: 'COMPLETE' }]]) {
    await assertFails(setDoc(doc(owner(), path), value));
    await assertFails(updateDoc(doc(owner(), path), { archived: true, state: 'COMPLETE' }));
    await assertFails(deleteDoc(doc(owner(), path)));
  }
  await assertFails(setDoc(doc(owner(), 'cct_owner_builds/new-fixture'), build()));
  await assertFails(setDoc(doc(owner(), 'cct_owner_build_request_status/new-request'), { ownerUid, state: 'COMPLETE' }));
});

for (const [name, identity] of [
  ['anonymous', null], ['wrong UID', { uid: 'another-owner' }],
  ['wrong email', { token: { email: 'other@example.com' } }],
  ['unverified email', { token: { email_verified: false } }],
  ['password provider', { token: { firebase: { sign_in_provider: 'password' } } }],
  ['missing provider', { token: { firebase: {} } }],
]) test(`${name} cannot read private builds or mutate owner intent`, async () => {
  await seedReady();
  const db = identity === null ? env.unauthenticatedContext().firestore()
    : env.authenticatedContext(identity.uid || ownerUid, { ...claims(), ...identity.token }).firestore();
  for (const path of [buildPath, statusPath, controlPath, requestPath, receiptPath])
    await assertFails(getDocFromServer(doc(db, path)));
  await assertFails(setDoc(doc(db, controlPath), control()));
  await assertFails(setDoc(doc(db, requestPath), request()));
});

test('owner cannot read a projection assigned to foreign or missing UID', async () => {
  for (const uid of ['another-owner', null]) {
    await seed([[buildPath, build({ ownerUid: uid })], [statusPath, host({ ownerUid: uid })],
      [requestPath, { ownerUid: uid }], [receiptPath, { ownerUid: uid }]]);
    for (const path of [buildPath, statusPath, requestPath, receiptPath])
      await assertFails(getDocFromServer(doc(owner(), path)));
  }
});

test('budget intents increment revision; duplicates, stale updates and delete fail', async () => {
  await seedReady();
  const db = owner();
  await assertSucceeds(setDoc(doc(db, controlPath), control()));
  await assertFails(setDoc(doc(db, controlPath), control()));
  await assertFails(setDoc(doc(db, controlPath), control({ revision: 3 })));
  await assertSucceeds(setDoc(doc(db, controlPath), control({ revision: 2, maxDailyProviderCalls: 20 })));
  await assertFails(setDoc(doc(db, controlPath), control({ revision: 1 })));
  await assertFails(deleteDoc(doc(db, controlPath)));
  assert.equal((await getDocFromServer(doc(db, controlPath))).data().revision, 2);
});

for (const [name, delta] of [
  ['wrong schema', { schemaVersion: 'other' }], ['wrong owner', { ownerUid: 'other' }],
  ['initial non-one revision', { revision: 2 }], ['boolean revision', { revision: true }],
  ['zero jobs', { maxDailyJobs: 0 }], ['jobs over ceiling', { maxDailyJobs: 5 }],
  ['fractional jobs', { maxDailyJobs: 1.5 }], ['boolean jobs', { maxDailyJobs: true }],
  ['zero provider calls', { maxDailyProviderCalls: 0 }], ['provider over ceiling', { maxDailyProviderCalls: 21 }],
  ['boolean provider calls', { maxDailyProviderCalls: false }], ['zero tool calls', { maxDailyToolCalls: 0 }],
  ['tools over ceiling', { maxDailyToolCalls: 13 }], ['string tools', { maxDailyToolCalls: '4' }],
  ['forged usage', { usage: { providerCalls: 0 } }], ['forged status', { state: 'APPLIED' }],
  ['client timestamp', { updatedAt: Timestamp.fromMillis(1) }],
]) test(`invalid budget intent rejected: ${name}`, async () => {
  await seedReady();
  await assertFails(setDoc(doc(owner(), controlPath), control(delta)));
});

test('missing runtime, foreign runtime and stricter host ceiling block budget edits', async () => {
  await assertFails(setDoc(doc(owner(), controlPath), control()));
  await seed([[statusPath, host({ ownerUid: 'foreign' })]]);
  await assertFails(setDoc(doc(owner(), controlPath), control()));
  await seed([[statusPath, host({ ceilings: { maxDailyJobs: 1, maxDailyProviderCalls: 12, maxDailyToolCalls: 4 } })]]);
  await assertFails(setDoc(doc(owner(), controlPath), control()));
});

for (const action of ['upgrade', 'steer', 'discover', 'archive', 'restore'])
  test(`confirmed ${action} request accepted once and immutable`, async () => {
    await seedReady();
    const db = owner();
    await assertSucceeds(setDoc(doc(db, requestPath), request({ action })));
    const saved = (await getDocFromServer(doc(db, requestPath))).data();
    assert.equal(saved.action, action);
    await assertFails(setDoc(doc(db, requestPath), request({ action })));
    await assertFails(updateDoc(doc(db, requestPath), { instructions: 'Different instruction' }));
    await assertFails(deleteDoc(doc(db, requestPath)));
  });

for (const [name, delta] of [
  ['wrong schema', { schemaVersion: 'other' }], ['wrong owner', { ownerUid: 'other' }],
  ['mismatched id', { requestId: 'another-request' }], ['unknown parent', { parentBuildId: 'not-found' }],
  ['different digest', { parentDigest: 'b'.repeat(64) }], ['uppercase digest', { parentDigest: 'A'.repeat(64) }],
  ['invalid action', { action: 'run-shell' }], ['empty steer', { action: 'steer', instructions: '' }],
  ['whitespace steer', { action: 'steer', instructions: ' \n\t ' }],
  ['oversize instructions', { instructions: 'x'.repeat(2001) }],
  ['zero provider', { maxProviderCalls: 0 }], ['oversize provider', { maxProviderCalls: 21 }],
  ['fractional provider', { maxProviderCalls: 1.25 }], ['zero tools', { maxToolCalls: 0 }],
  ['oversize tools', { maxToolCalls: 13 }], ['boolean tools', { maxToolCalls: true }],
  ['forged created time', { createdAt: Timestamp.fromMillis(1) }],
  ['expired', { expiresAt: Timestamp.fromMillis(1) }],
  ['too long expiry', { expiresAt: Timestamp.fromMillis(Date.now() + 8 * 86400000) }],
  ['wrong revision', { controlRevision: 1 }], ['boolean revision', { controlRevision: false }],
  ['forged outcome', { state: 'COMPLETE' }], ['forged effect permission', { financial: true }],
]) test(`invalid request rejected: ${name}`, async () => {
  await seedReady();
  await assertFails(setDoc(doc(owner(), requestPath), request(delta)));
});

test('unfinished, foreign, mismatched-ID and wrong-schema parents rejected', async () => {
  await seedReady();
  for (const delta of [{ status: 'BUILDING' }, { ownerUid: 'foreign' },
    { buildId: 'not-the-path' }, { schemaVersion: 'unknown' }]) {
    await seed([[buildPath, build(delta)]]);
    await assertFails(setDoc(doc(owner(), requestPath), request()));
  }
});

for (const [name, delta] of [
  ['paused', { learningEnabled: false }], ['not full mode', { autonomyMode: 'assisted' }],
  ['no acknowledgement', { autonomyAcknowledged: false }], ['foreign workspace', { ownerUid: 'foreign' }],
  ['no read', { permissions: { workspaceRead: false, workspaceWrite: true } }],
  ['no write', { permissions: { workspaceRead: true, workspaceWrite: false } }],
]) test(`workspace gate blocks follow-up: ${name}`, async () => {
  await seedReady();
  await seed([['cct_workspace/current', workspace(delta)]]);
  await assertFails(setDoc(doc(owner(), requestPath), request()));
});

test('new budget intent blocks old requests until exact host-applied readback', async () => {
  await seedReady();
  const db = owner();
  await assertSucceeds(setDoc(doc(db, controlPath), control()));
  await assertFails(setDoc(doc(db, requestPath), request({ controlRevision: 0 })));
  await assertFails(setDoc(doc(db, requestPath), request({ controlRevision: 1 })));
  await seed([[statusPath, host({ requestedRevision: 1, effectiveRevision: 1 })]]);
  await assertSucceeds(setDoc(doc(db, requestPath), request({ controlRevision: 1 })));
});

test('atomic budget edit cannot submit a request against the previous intent revision', async () => {
  await seedReady();
  const db = owner();
  const batch = writeBatch(db);
  batch.set(doc(db, controlPath), control());
  batch.set(doc(db, requestPath), request({ controlRevision: 0 }));
  await assertFails(batch.commit());
  assert.equal((await getDocFromServer(doc(db, controlPath))).exists(), false);
  assert.equal((await getDocFromServer(doc(db, requestPath))).exists(), false);
});

test('budgets cannot be combined with a forged host receipt to bypass acknowledgement', async () => {
  await seedReady();
  const db = owner();
  const batch = writeBatch(db);
  batch.set(doc(db, controlPath), control());
  batch.set(doc(db, statusPath), host({ effectiveRevision: 1 }));
  batch.set(doc(db, requestPath), request({ controlRevision: 1 }));
  await assertFails(batch.commit());
  assert.equal((await getDocFromServer(doc(db, controlPath))).exists(), false);
});

test('alternate control documents, nested paths and unbounded status lists denied', async () => {
  const db = owner();
  for (const path of ['cct_owner_build_controls/other', 'cct_owner_build_controls_status/other',
    `${buildPath}/files/app.py`, `${requestPath}/private/detail`]) {
    await assertFails(setDoc(doc(db, path), { ownerUid }));
    await assertFails(getDocFromServer(doc(db, path)));
  }
  for (const name of ['cct_owner_build_controls', 'cct_owner_build_controls_status'])
    await assertFails(getDocsFromServer(query(collection(db, name), limit(1))));
});
