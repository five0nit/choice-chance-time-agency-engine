import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test, { before, after, beforeEach } from 'node:test';
import { initializeTestEnvironment, assertFails, assertSucceeds } from '@firebase/rules-unit-testing';
import { doc, getDoc, getDocs, collection, setDoc, deleteDoc, serverTimestamp, Timestamp, runTransaction, query, limit } from 'firebase/firestore';

const ownerUid = 'replace-with-owner-firebase-uid';
const email = 'owner@example.invalid';
let env;
function owner(uid = ownerUid, claims = {}) {
  return env.authenticatedContext(uid, {
    email, email_verified: true, firebase: { sign_in_provider: 'google.com' }, ...claims,
  }).firestore();
}
function value(revision = 1) {
  return {
    schemaVersion: 'cct.owner_workspace.v1', ownerUid, revision,
    updatedAt: serverTimestamp(), learningEnabled: true,
    permissions: { credentialAccess: false, webResearch: false, workspaceRead: false, workspaceWrite: false, externalMessages: false, payments: false },
    autonomyMode: 'supervised', autonomyAcknowledged: false,
    answers: { focus: '', horizon: '', risk: '', interruptions: '', success: '', nextStep: '' },
    decisions: {},
  };
}
const ref = (db) => doc(db, 'cct_workspace', 'current');
before(async () => {
  env = await initializeTestEnvironment({
    projectId: 'demo-cctae-workspace', firestore: { host: '127.0.0.1', port: 8080,
      rules: await readFile(new URL('../../../firestore.rules', import.meta.url), 'utf8') },
  });
});
beforeEach(async () => env.clearFirestore());
after(async () => env.cleanup());

test('owner can read missing state, create, update and reload exact saved answers', async () => {
  const db = owner();
  assert.equal((await assertSucceeds(getDoc(ref(db)))).exists(), false);
  await assertSucceeds(setDoc(ref(db), value()));
  const next = value(2); next.answers.focus = 'systems'; next.permissions.credentialAccess = true;
  await assertSucceeds(setDoc(ref(db), next));
  const saved = (await getDoc(ref(owner()))).data();
  assert.equal(saved.answers.focus, 'systems'); assert.equal(saved.permissions.credentialAccess, true);
  assert.equal(saved.autonomyMode, 'supervised'); assert.equal(saved.revision, 2);
});

test('unauthenticated, wrong UID, wrong email, unverified and wrong provider denied', async () => {
  await setDoc(ref(owner()), value());
  const contexts = [env.unauthenticatedContext().firestore(), owner('outsider'),
    owner(ownerUid, { email: 'other@example.com' }), owner(ownerUid, { email_verified: false }),
    owner(ownerUid, { firebase: { sign_in_provider: 'password' } })];
  for (const db of contexts) {
    await assertFails(getDoc(ref(db))); await assertFails(setDoc(ref(db), value(2)));
  }
});

test('autonomy requires acknowledgement and does not expand any permissions', async () => {
  const invalid = value(); invalid.autonomyMode = 'full';
  await assertFails(setDoc(ref(owner()), invalid));
  invalid.autonomyAcknowledged = true;
  await assertSucceeds(setDoc(ref(owner()), invalid));
  const saved = (await getDoc(ref(owner()))).data();
  assert.equal(saved.autonomyMode, 'full'); assert.ok(Object.values(saved.permissions).every((v) => v === false));
});

test('stale revision, revision skips and forged timestamps rejected', async () => {
  await setDoc(ref(owner()), value());
  for (const invalid of [value(), value(3), { ...value(2), revision: 2.5 },
    { ...value(2), revision: true }, { ...value(2), updatedAt: Timestamp.fromMillis(0) }]) {
    await assertFails(setDoc(ref(owner()), invalid));
  }
});

test('transactions from separate tabs preserve independent owner edits', async () => {
  await setDoc(ref(owner()), value());
  async function change(field, choice) {
    const db = owner();
    return runTransaction(db, async (tx) => {
      const w = (await tx.get(ref(db))).data();
      tx.set(ref(db), { ...w, answers: { ...w.answers, [field]: choice }, revision: w.revision + 1, updatedAt: serverTimestamp() });
    });
  }
  const results = await Promise.allSettled([change('focus', 'career'), change('horizon', 'week')]);
  // The emulator may enforce revision rules before returning an ABORTED retry.
  // A caller must surface this conflict or re-read and retry, never overwrite.
  for (const [i, result] of results.entries()) {
    if (result.status === 'rejected') {
      assert.equal(result.reason.code, 'permission-denied');
      await change(...[['focus', 'career'], ['horizon', 'week']][i]);
    }
  }
  const w = (await getDoc(ref(owner()))).data();
  assert.equal(w.answers.focus, 'career'); assert.equal(w.answers.horizon, 'week'); assert.equal(w.revision, 3);
});

test('unknown fields, secrets, invalid bools/enums and missing fields are rejected', async () => {
  const cases = [
    { ...value(), credentialValue: 'test-fixture-not-a-real-secret' },
    { ...value(), ownerUid: 'forged' }, { ...value(), learningEnabled: 'true' },
    { ...value(), schemaVersion: 'v2' }, { ...value(), autonomyMode: 'unlimited' },
    { ...value(), permissions: { ...value().permissions, root: true } },
    { ...value(), permissions: { ...value().permissions, credentialAccess: 'yes' } },
    { ...value(), answers: { ...value().answers, focus: 'arbitrary-instruction' } },
    { ...value(), answers: { ...value().answers, secret: 'no' } },
    { ...value(), decisions: { card: 'execute-now' } },
    { ...value(), decisions: Object.fromEntries(Array.from({ length: 61 }, (_, i) => [String(i), 'approve'])) },
  ];
  const missing = value(); delete missing.permissions.payments; cases.push(missing);
  for (const invalid of cases) await assertFails(setDoc(ref(owner()), invalid));
});

test('learning reset and pause preserve permission policy and acknowledgement', async () => {
  const initial = value(); initial.answers.focus = 'revenue'; initial.decisions = { 'onboard-revenue': 'approve' };
  initial.permissions.webResearch = true; initial.autonomyMode = 'full'; initial.autonomyAcknowledged = true;
  await setDoc(ref(owner()), initial);
  const reset = { ...initial, revision: 2, answers: value().answers, decisions: {}, learningEnabled: false, updatedAt: serverTimestamp() };
  await assertSucceeds(setDoc(ref(owner()), reset));
  const saved = (await getDoc(ref(owner()))).data();
  assert.equal(saved.permissions.webResearch, true); assert.equal(saved.autonomyMode, 'full');
  assert.equal(saved.autonomyAcknowledged, true); assert.deepEqual(saved.answers, value().answers);
});

test('owner cannot list, delete, create alternate workspace, or forge runtime acknowledgement', async () => {
  await setDoc(ref(owner()), value());
  await assertFails(getDocs(collection(owner(), 'cct_workspace')));
  await assertFails(deleteDoc(ref(owner())));
  await assertFails(setDoc(doc(owner(), 'cct_workspace', 'other'), value()));
  await assertFails(setDoc(doc(owner(), 'cct_bridge_status', 'current'), { effectiveAutonomy: 'full' }));
  await assertFails(setDoc(ref(owner()), { ...value(2), effectivePermissions: value().permissions }));
});


const messageId = 'msg-' + 'a'.repeat(32);
const messageRef = (db) => doc(db, 'cct_owner_messages', messageId);
const replyRef = (db) => doc(db, 'cct_owner_replies', messageId);
const replyValue = () => ({schemaVersion:'cct.owner_reply.v1', ownerUid, messageId,
  text:'Please research first.', createdAt:serverTimestamp()});
async function seedMessage(overrides = {}) {
  await env.withSecurityRulesDisabled(async c => {
    await setDoc(messageRef(c.firestore()), {schemaVersion:'cct.owner_message.v1',ownerUid,messageId,
      kind:'ask',state:'SENT',text:'What next?',replyDeadline:Timestamp.fromMillis(Date.now()+3600000),...overrides});
    await setDoc(doc(c.firestore(),'cct_owner_runtime','current'), {ownerUid,state:'CONNECTED'});
  });
}
test('owner connection runtime/message projections are readable but host-write only', async () => {
  await seedMessage();
  const db=owner();
  const runtime=doc(db,'cct_owner_runtime','current');
  await assertSucceeds(getDoc(runtime)); await assertSucceeds(getDoc(messageRef(db)));
  await assertSucceeds(getDocs(query(collection(db,'cct_owner_messages'),limit(20))));
  await assertFails(getDocs(collection(db,'cct_owner_messages')));
  await assertFails(getDocs(query(collection(db,'cct_owner_messages'),limit(21))));
  for (const ref of [runtime,messageRef(db)]) {
    await assertFails(setDoc(ref,{ownerUid,state:'CONNECTED'})); await assertFails(deleteDoc(ref));
  }
});
test('exact owner may create and read back one answer but never rewrite or grant authority', async () => {
  await seedMessage(); const db=owner(), ref=replyRef(db);
  await assertSucceeds(setDoc(ref,replyValue()));
  assert.equal((await getDoc(ref)).data().text,'Please research first.');
  await assertFails(setDoc(ref,{...replyValue(),text:'changed'})); await assertFails(deleteDoc(ref));
});
test('reply identity schema timestamps bounds and parent state fail closed', async () => {
  await seedMessage(); const db=owner();
  for (const bad of [{ownerUid:'wrong'},{messageId:'wrong'},{schemaVersion:'v0'},
    {text:''},{text:'   '},{text:'x'.repeat(2001)},{createdAt:Timestamp.fromMillis(0)},
    {grantPayments:true}]) await assertFails(setDoc(replyRef(db),{...replyValue(),...bad}));
  for (const bad of [{state:'QUEUED'},{state:'UNKNOWN'},{kind:'send'},{ownerUid:'wrong'},
    {replyDeadline:Timestamp.fromMillis(0)}]) {
    await seedMessage(bad); await assertFails(setDoc(replyRef(db),replyValue()));
  }
});
test('all non-owner identities denied connection projections and replies', async () => {
  await seedMessage();
  const contexts=[env.unauthenticatedContext().firestore(),owner('wrong'),
    owner(ownerUid,{email:'wrong@example.com'}),owner(ownerUid,{email_verified:false}),
    owner(ownerUid,{firebase:{sign_in_provider:'password'}})];
  for (const db of contexts) {
    await assertFails(getDoc(doc(db,'cct_owner_runtime','current')));
    await assertFails(getDoc(messageRef(db)));
    await assertFails(getDocs(query(collection(db,'cct_owner_messages'),limit(20))));
    await assertFails(setDoc(replyRef(db),replyValue()));
    await assertFails(getDoc(replyRef(db)));
  }
});
