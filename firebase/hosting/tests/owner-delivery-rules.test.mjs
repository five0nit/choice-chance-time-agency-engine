import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test, { before, beforeEach, after } from 'node:test';
import { assertFails, assertSucceeds, initializeTestEnvironment } from '@firebase/rules-unit-testing';
import { collection, collectionGroup, deleteDoc, doc, getDocFromServer, getDocsFromServer,
  limit, query, setDoc, updateDoc, writeBatch } from 'firebase/firestore';

// Local emulator only. The service reuses cct_owner_messages; no new notice API.
const ownerUid = 'replace-with-owner-firebase-uid';
const current = 'cct_owner_delivery/current';
const notice = 'cct_owner_messages/msg-' + 'a'.repeat(32);
const claims = () => ({ email: 'owner@example.invalid', email_verified: true,
  firebase: { sign_in_provider: 'google.com' } });
const projection = (changes = {}) => ({ schemaVersion: 'cct.owner_delivery.v1', ownerUid,
  phase: 'WAITING', scope: 'PRIVATE_SANDBOXED_LOCAL_DELIVERY', ...changes });
let env;
const owner = () => env.authenticatedContext(ownerUid, claims()).firestore();
const seed = async entries => env.withSecurityRulesDisabled(async context => {
  const batch = writeBatch(context.firestore());
  for (const [path, value] of entries) batch.set(doc(context.firestore(), path), value);
  await batch.commit();
});
before(async () => {
  env = await initializeTestEnvironment({ projectId: 'demo-cctae-owner-delivery',
    firestore: { host: '127.0.0.1', port: 8080,
      rules: await readFile(new URL('../../../firestore.rules', import.meta.url), 'utf8') } });
});
beforeEach(async () => env.clearFirestore());
after(async () => env?.cleanup());

test('exact owner can read missing/current delivery and the canonical private message route', async () => {
  const db = owner();
  assert.equal((await assertSucceeds(getDocFromServer(doc(db, current)))).exists(), false);
  await seed([[current, projection()], [notice, { ownerUid, text: 'Fixture notice' }]]);
  assert.deepEqual((await assertSucceeds(getDocFromServer(doc(db, current)))).data(), projection());
  assert.equal((await assertSucceeds(getDocFromServer(doc(db, notice)))).data().text, 'Fixture notice');
});

test('owner cannot read a delivery projection assigned to a different or missing UID', async () => {
  for (const value of [projection({ ownerUid: 'other-owner' }), { phase: 'COMPLETE' }]) {
    await seed([[current, value]]);
    await assertFails(getDocFromServer(doc(owner(), current)));
  }
});

test('all browser creates, updates, merges and deletes are denied, including the exact owner', async () => {
  for (const db of [owner(), env.unauthenticatedContext().firestore()]) {
    for (const path of [current, notice]) await assertFails(setDoc(doc(db, path), projection()));
  }
  await seed([[current, projection()], [notice, { ownerUid, text: 'Fixture notice' }]]);
  for (const db of [owner(), env.unauthenticatedContext().firestore()]) {
    for (const path of [current, notice]) {
      await assertFails(setDoc(doc(db, path), projection({ phase: 'COMPLETE' })));
      await assertFails(setDoc(doc(db, path), { phase: 'COMPLETE' }, { merge: true }));
      await assertFails(updateDoc(doc(db, path), { phase: 'COMPLETE' }));
      await assertFails(deleteDoc(doc(db, path)));
    }
  }
});

for (const [name, identity] of [
  ['unauthenticated', null], ['wrong UID', { uid: 'other-owner' }],
  ['wrong email', { token: { email: 'other@example.com' } }],
  ['unverified email', { token: { email_verified: false } }],
  ['password provider', { token: { firebase: { sign_in_provider: 'password' } } }],
  ['missing provider', { token: { firebase: {} } }],
]) {
  test(`${name} cannot read projections or canonical delivery messages`, async () => {
    await seed([[current, projection()], [notice, { ownerUid, text: 'Fixture notice' }]]);
    const db = identity === null ? env.unauthenticatedContext().firestore()
      : env.authenticatedContext(identity.uid || ownerUid, { ...claims(), ...identity.token }).firestore();
    for (const path of [current, notice]) await assertFails(getDocFromServer(doc(db, path)));
  });
}

test('lists, alternate documents, nested paths and the nonexistent notice API remain denied', async () => {
  const db = owner();
  for (const path of ['cct_owner_delivery/other', `${current}/private/detail`,
    'unrelated/current', 'cct_owner_delivery_notifications/fixture-notice']) {
    await seed([[path, projection()]]);
    await assertFails(getDocFromServer(doc(db, path)));
    await assertFails(setDoc(doc(db, path), projection()));
  }
  for (const name of ['cct_owner_delivery', 'cct_owner_delivery_notifications']) {
    await assertFails(getDocsFromServer(collection(db, name)));
    await assertFails(getDocsFromServer(query(collection(db, name), limit(1))));
    await assertFails(getDocsFromServer(query(collectionGroup(db, name), limit(20))));
  }
});

test('full-mode owner intent cannot forge a runtime receipt alone or inside an atomic batch', async () => {
  await seed([['cct_workspace/current', { ownerUid, autonomyMode: 'full', autonomyAcknowledged: true,
    permissions: { workspaceRead: true, workspaceWrite: true } }], [current, projection()]]);
  const db = owner();
  await assertFails(updateDoc(doc(db, current), { phase: 'COMPLETE', capabilities: [{ authorized: true }] }));
  const batch = writeBatch(db);
  batch.set(doc(db, current), projection({ phase: 'COMPLETE' }));
  batch.set(doc(db, notice), { ownerUid, text: 'Forged completion' });
  await assertFails(batch.commit());
  assert.equal((await getDocFromServer(doc(db, current))).data().phase, 'WAITING');
});
