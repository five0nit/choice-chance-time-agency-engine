import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test, { after, before } from 'node:test';
import {
  assertFails,
  assertSucceeds,
  initializeTestEnvironment,
} from '@firebase/rules-unit-testing';
import {
  doc,
  getDoc,
  serverTimestamp,
  setDoc,
  updateDoc,
} from 'firebase/firestore';

const projectId = 'demo-cctae-control';
const ownerEmail = 'owner@example.invalid';
const ownerUid = 'replace-with-owner-firebase-uid';
const digest = 'a'.repeat(64);
const previewIdToken = 'eyJhbGciOiJSUzI1NiJ9.eyJraW5kIjoicHJldmlldyJ9.c2lnbmF0dXJlcHJldmlldw';
const applyIdToken = 'eyJhbGciOiJSUzI1NiJ9.eyJraW5kIjoiYXBwbHkifQ.c2lnbmF0dXJlYXBwbHktc2lnbmF0dXJl';
let environment;

function request(id, kind = 'PREVIEW') {
  const value = {
    schemaVersion: 'cct.firebase_control_request.v1',
    requestId: id,
    kind,
    action: 'SET_CAPABILITY_ADMINISTRATIVE_ACTIVE',
    capability: 'operator.web',
    active: false,
    ownerUid,
    ownerEmail,
    idToken: kind === 'PREVIEW' ? previewIdToken : applyIdToken,
    state: 'PENDING',
    createdAt: serverTimestamp(),
  };
  if (kind === 'APPLY') {
    value.parentRequestId = 'req-preview0123456789';
    value.previewSha256 = digest;
  }
  return value;
}

before(async () => {
  environment = await initializeTestEnvironment({
    projectId,
    firestore: {
      host: '127.0.0.1',
      port: 8080,
      rules: await readFile(new URL('../../../firestore.rules', import.meta.url), 'utf8'),
    },
  });
  await environment.withSecurityRulesDisabled(async (context) => {
    const db = context.firestore();
    await setDoc(doc(db, 'cct_dashboard', 'current'), {
      schemaVersion: 'cct.firebase_dashboard.v1',
      ownerEmail,
      ownerUid,
      snapshot: { schema_version: 'cct.dashboard.v1' },
    });
    await setDoc(doc(db, 'cct_control_receipts', 'req-preview0123456789'), {
      status: 'PREVIEW_READY',
      ownerUid,
      ownerEmail,
      previewSha256: digest,
    });
  });
});

after(async () => {
  await environment.cleanup();
});

function owner() {
  return environment.authenticatedContext(ownerUid, {
    email: ownerEmail,
    email_verified: true,
    firebase: { sign_in_provider: 'google.com' },
  }).firestore();
}

test('exact verified Google owner can read dashboard and create bounded requests', async () => {
  const db = owner();
  await assertSucceeds(getDoc(doc(db, 'cct_dashboard', 'current')));
  await assertSucceeds(setDoc(doc(db, 'cct_control_requests', 'req-ownerpreview123456'), request('req-ownerpreview123456')));
  await assertSucceeds(setDoc(doc(db, 'cct_control_requests', 'req-ownerapply12345678'), request('req-ownerapply12345678', 'APPLY')));
});

test('outsider, unverified email, and non-Google provider are denied', async () => {
  const outsider = environment.authenticatedContext('outsider', {
    email: 'attacker@example.com', email_verified: true, firebase: { sign_in_provider: 'google.com' },
  }).firestore();
  const unverified = environment.authenticatedContext(ownerUid, {
    email: ownerEmail, email_verified: false, firebase: { sign_in_provider: 'google.com' },
  }).firestore();
  const wrongProvider = environment.authenticatedContext(ownerUid, {
    email: ownerEmail, email_verified: true, firebase: { sign_in_provider: 'password' },
  }).firestore();
  await assertFails(getDoc(doc(outsider, 'cct_dashboard', 'current')));
  await assertFails(getDoc(doc(unverified, 'cct_dashboard', 'current')));
  await assertFails(getDoc(doc(wrongProvider, 'cct_dashboard', 'current')));
});

test('owner cannot forge identity, extra fields, or unmatched apply receipt', async () => {
  const db = owner();
  const forged = { ...request('req-forgedidentity1234'), ownerUid: 'attacker' };
  const extra = { ...request('req-extrafield1234567'), surprise: true };
  const missingToken = request('req-missingtoken123456');
  delete missingToken.idToken;
  const malformedToken = { ...request('req-badtoken123456789'), idToken: 'not-a-jwt' };
  const wrongDigest = { ...request('req-wrongdigest123456', 'APPLY'), previewSha256: 'b'.repeat(64) };
  await assertFails(setDoc(doc(db, 'cct_control_requests', forged.requestId), forged));
  await assertFails(setDoc(doc(db, 'cct_control_requests', extra.requestId), extra));
  await assertFails(setDoc(doc(db, 'cct_control_requests', missingToken.requestId), missingToken));
  await assertFails(setDoc(doc(db, 'cct_control_requests', malformedToken.requestId), malformedToken));
  await assertFails(setDoc(doc(db, 'cct_control_requests', wrongDigest.requestId), wrongDigest));
});

test('clients cannot write dashboard or receipts, update requests, list, or access unknown paths', async () => {
  const db = owner();
  const id = 'req-immutable12345678';
  await assertSucceeds(setDoc(doc(db, 'cct_control_requests', id), request(id)));
  await assertFails(updateDoc(doc(db, 'cct_control_requests', id), { state: 'DONE' }));
  await assertFails(setDoc(doc(db, 'cct_dashboard', 'current'), { ownerEmail }));
  await assertFails(setDoc(doc(db, 'cct_control_receipts', 'req-clientwrite123456'), { status: 'PREVIEW_READY' }));
  await assertFails(getDoc(doc(db, 'unknown', 'document')));
  assert.ok(true);
});
