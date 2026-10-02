import assert from 'node:assert/strict';
import test from 'node:test';
import { readFileSync } from 'node:fs';
import vm from 'node:vm';
import * as model from '../src/owner-builds-model.js';

// Source-wiring checks complement the pure model suite. Browser/emulator QA is
// a separate integration gate; these do not claim executed host work.
test('Builds controller is owner-mounted, bounded, text-only and nonce-reconciled', () => {
  const source = readFileSync(new URL('../src/owner-builds.js', import.meta.url), 'utf8');
  const ui = readFileSync(new URL('../src/workspace-ui.js', import.meta.url), 'utf8');
  const html = readFileSync(new URL('../index.template.html', import.meta.url), 'utf8');
  const pkg = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8'));
  assert.ok(html.includes('href="#owner-builds">Builds</a>'));
  assert.ok(html.includes('id="owner-builds"'));
  assert.ok(ui.includes('mountOwnerBuilds(db, ownerUid, view, ownerStatus)'));
  assert.ok(ui.includes('builds?.setWorkspace(view)'));
  assert.ok(ui.includes('builds?.stop()'));
  for (const marker of ["where('ownerUid', '==', uid)", 'orderBy(documentId())',
    'startAfter(after)', 'limit(PAGE_SIZE)', 'includeMetadataChanges: true',
    'getDocFromServer(ref)', 'runTransaction(db', 'persistPending(item)',
    'sameRequest(actual, item.payload)', 'crypto.randomUUID()', 'sessionStorage.setItem',
    'serverTimestamp()', 'expiresAt: Timestamp.fromMillis', "getRuntime()?.state === 'CONNECTED'",
    'controlsPreview(context()', 'requestPreview(context()', 'downloadName(file.path)',
    "type: 'text/plain;charset=utf-8'", 'URL.revokeObjectURL', 'root.replaceChildren()']) {
    assert.ok(source.includes(marker), `missing controller guard: ${marker}`);
  }
  assert.doesNotMatch(source, /innerHTML|outerHTML|insertAdjacentHTML|srcdoc|eval\s*\(|new Function/);
  assert.ok(pkg.scripts.test.includes('tests/owner-builds.test.mjs'));
  assert.ok(pkg.scripts['test:rules'].includes('tests/owner-builds-rules.test.mjs'));
});


// TEST-ONLY wire fixtures: IDs, timestamps, digests and evidence below are
// synthetic shape checks, not host receipts, verified artifacts or live authority.
const uid = 'test-only-owner';
const now = Date.parse('2026-09-14T08:00:00.000Z');
const iso = new Date(now).toISOString();
const bundleDigest = 'a'.repeat(64);
const fileDigest = 'b'.repeat(64);
const caps = () => ({ maxDailyJobs: 1, maxDailyProviderCalls: 12, maxDailyToolCalls: 4 });
const build = (changes = {}) => ({
  schemaVersion: model.BUILD_SCHEMA, ownerUid: uid, buildId: 'test-only-build',
  parentBuildId: '', rootBuildId: 'test-only-build', action: 'build',
  title: 'Test-only artifact', summary: 'Synthetic saved evidence', status: 'COMPLETE', reason: '',
  createdAt: iso, updatedAt: iso, bundleDigest, archived: false,
  verification: { scope: 'TEST_ONLY_NOT_HOST_EVIDENCE' },
  usage: { providerCalls: 2, toolCalls: 1 },
  files: [{ path: 'index.html', content: '<script>test-only text</script>', sha256: fileDigest }],
  ...changes,
});
const controls = (changes = {}) => ({
  schemaVersion: model.CONTROLS_SCHEMA, ownerUid: uid, revision: 2,
  ...caps(), updatedAt: iso, ...changes,
});
const status = (changes = {}) => ({
  schemaVersion: model.STATUS_SCHEMA, ownerUid: uid, requestedRevision: 2, effectiveRevision: 2,
  state: 'APPLIED', reason: '', effective: caps(), ceilings: { ...model.CEILINGS },
  usage: { jobs: 1, providerCalls: 2, toolCalls: 1 }, updatedAt: iso, ...changes,
});
const request = (changes = {}) => ({
  schemaVersion: model.REQUEST_SCHEMA, ownerUid: uid, requestId: 'test-only-request',
  parentBuildId: 'test-only-build', parentDigest: bundleDigest, action: 'upgrade', instructions: '',
  maxProviderCalls: 3, maxToolCalls: 2, controlRevision: 2,
  createdAt: iso, expiresAt: '2026-09-20T08:00:00.000Z', ...changes,
});
const receipt = (changes = {}) => ({
  schemaVersion: model.RECEIPT_SCHEMA, ownerUid: uid, requestId: 'test-only-request',
  parentBuildId: 'test-only-build', action: 'upgrade', state: 'QUEUED', reason: '',
  buildId: '', updatedAt: iso, ...changes,
});
const context = (changes = {}) => ({
  uid, now, offline: false, controls: controls(), status: status(),
  verified: { status: true, controls: true, builds: true },
  workspace: { exists: true, verified: true, busy: false, workspace: {
    ownerUid: uid, autonomyMode: 'full', autonomyAcknowledged: true, learningEnabled: true,
    permissions: { workspaceRead: true, workspaceWrite: true },
  } }, ...changes,
});
const input = (changes = {}) => ({
  action: 'upgrade', instructions: '', maxProviderCalls: 3, maxToolCalls: 2, ...changes,
});
function rejectsChanges(validate, factory, changes) {
  for (const [label, change] of changes) {
    assert.equal(validate(factory(change), uid), false, label);
  }
}

for (const [name, validate, factory] of [
  ['build', model.validBuild, build], ['controls', model.validControls, controls],
  ['status', model.validStatus, status], ['request', model.validRequest, request],
  ['receipt', model.validReceipt, receipt],
]) {
  test(`${name} wire validator rejects owner/schema drift and missing required fields`, () => {
    assert.equal(validate(factory(), uid), true);
    for (const value of [null, undefined, [], 'projection', 1]) {
      assert.equal(validate(value, uid), false);
    }
    assert.equal(validate(factory(), ''), false);
    assert.equal(validate(factory(), 'different-owner'), false);
    rejectsChanges(validate, factory, [
      ['wrong owner', { ownerUid: 'different-owner' }],
      ['future schema', { schemaVersion: 'cct.owner_build.future' }],
      ['wrong schema type', { schemaVersion: 1 }],
    ]);
    for (const key of Object.keys(factory())) {
      const value = factory();
      delete value[key];
      assert.equal(validate(value, uid), false, `missing ${key}`);
    }
  });
}

test('wire constants and honest scope labels remain explicit', () => {
  assert.deepEqual([
    model.BUILD_SCHEMA, model.CONTROLS_SCHEMA, model.STATUS_SCHEMA,
    model.REQUEST_SCHEMA, model.RECEIPT_SCHEMA,
  ], ['cct.owner_build.v1', 'cct.owner_build_controls.v1', 'cct.owner_build_controls_status.v1',
    'cct.owner_build_request.v1', 'cct.owner_build_request_status.v1']);
  assert.deepEqual(model.CEILINGS, { maxDailyJobs: 4, maxDailyProviderCalls: 20, maxDailyToolCalls: 12 });
  assert.deepEqual(model.ACTIONS, ['upgrade', 'steer', 'discover', 'archive', 'restore']);
  assert.equal(Object.isFrozen(model.CEILINGS), true);
  assert.equal(Object.isFrozen(model.ACTIONS), true);
  assert.equal(model.TOOL_LABEL, 'Bounded sandbox verification dispatches');
  assert.equal(model.DISCOVERY_LABEL, 'Manual Discover: a saved-evidence brief; no fresh web research');
  assert.match(model.CONTINUATION_RESEARCH_LABEL, /fresh public evidence from the fixed catalog/);
  assert.match(model.CONTINUATION_RESEARCH_LABEL, /Manual Discover only creates a brief from saved evidence/);
});

test('build validation binds document ID, lineage, immutable file shapes and bounded content', () => {
  assert.equal(model.validBuild(build(), uid, 'other-document'), false);
  rejectsChanges(model.validBuild, build, [
    ['unsafe ID', { buildId: 'unsafe/build' }], ['unsafe parent', { parentBuildId: '../parent' }],
    ['empty root', { rootBuildId: '' }], ['unsupported build action', { action: 'archive' }],
    ['blank title', { title: ' \n ' }], ['long title', { title: 'x'.repeat(2001) }],
    ['long summary', { summary: 'x'.repeat(16001) }], ['nontext status', { status: 1 }],
    ['long status', { status: 'x'.repeat(81) }], ['long reason', { reason: 'x'.repeat(16001) }],
    ['invalid timestamp', { createdAt: 'not-a-time' }], ['numeric timestamp', { updatedAt: now }],
    ['uppercase digest', { bundleDigest: 'A'.repeat(64) }], ['short digest', { bundleDigest: 'a'.repeat(63) }],
    ['nonboolean archive', { archived: 'false' }], ['invalid evidence', { verification: [] }],
    ['invalid usage', { usage: null }], ['negative provider use', { usage: { providerCalls: -1, toolCalls: 1 } }],
    ['fractional tool use', { usage: { providerCalls: 1, toolCalls: 0.5 } }],
    ['nonarray files', { files: {} }], ['invalid file entry', { files: [null] }],
    ['duplicate file paths', { files: [build().files[0], build().files[0]] }],
    ['too many files', { files: Array.from({ length: 129 }, (_, i) => ({ ...build().files[0], path: `file-${i}` })) }],
  ]);
  for (const [label, change] of [
    ['empty path', { path: '' }], ['long path', { path: 'x'.repeat(4097) }],
    ['nontext content', { content: {} }], ['long content', { content: 'x'.repeat(900001) }],
    ['invalid checksum', { sha256: 'not-a-digest' }],
  ]) assert.equal(model.validBuild(build({ files: [{ ...build().files[0], ...change }] }), uid), false, label);
  assert.equal(model.validBuild(build({ files: [], bundleDigest: '', status: 'BUILDING' }), uid), true);
  assert.equal(model.validBuild(build({ files: [{ ...build().files[0], content: 'é'.repeat(480000) }] }), uid), false,
    'UTF-8 document bytes are bounded, not merely JavaScript character counts');
  const circular = build();
  circular.verification.self = circular;
  assert.equal(model.validBuild(circular, uid), false, 'unserializable projection fails closed');
  assert.equal(model.validBuild(build({ hostEvidence: { testOnly: true } }), uid), true,
    'host projections may carry additional read-only evidence');
});

test('caps and controls require positive whole values within host ceilings', () => {
  assert.equal(model.validCaps(model.CEILINGS), true);
  for (const [key, ceiling] of Object.entries(model.CEILINGS)) {
    for (const invalid of [0, -1, 1.5, '1', null, NaN, Infinity, ceiling + 1]) {
      assert.equal(model.validCaps({ ...caps(), [key]: invalid }), false, `${key}: ${invalid}`);
      assert.equal(model.validControls(controls({ [key]: invalid }), uid), false, `${key}: ${invalid}`);
    }
  }
  for (const revision of [0, -1, 1.5, '2', 2147483648, NaN, Infinity]) {
    assert.equal(model.validControls(controls({ revision }), uid), false, `revision ${revision}`);
  }
  assert.equal(model.validControls(controls({ revision: 2147483647 }), uid), true);
  assert.equal(model.validControls(controls({ updatedAt: {} }), uid), false);
});

test('status preserves separate requested/effective revisions and validates actual usage', () => {
  assert.equal(model.validStatus(status({ requestedRevision: 3, effectiveRevision: 2 }), uid), true);
  assert.equal(model.validStatus(status({ requestedRevision: 0, effectiveRevision: 0 }), uid), true);
  for (const key of ['requestedRevision', 'effectiveRevision']) {
    for (const value of [-1, 1.5, '2', Number.MAX_SAFE_INTEGER + 1]) {
      assert.equal(model.validStatus(status({ [key]: value }), uid), false, `${key}: ${value}`);
    }
  }
  rejectsChanges(model.validStatus, status, [
    ['invalid state', { state: null }], ['long state', { state: 'x'.repeat(81) }],
    ['invalid reason', { reason: [] }], ['invalid time', { updatedAt: 'invalid' }],
    ['invalid effective', { effective: { ...caps(), maxDailyProviderCalls: 21 } }],
    ['invalid ceilings', { ceilings: { ...caps(), maxDailyToolCalls: 0 } }],
  ]);
  for (const key of ['jobs', 'providerCalls', 'toolCalls']) {
    for (const value of [-1, 0.5, '1', NaN, Infinity]) {
      assert.equal(model.validStatus(status({ usage: { ...status().usage, [key]: value } }), uid), false, `${key}: ${value}`);
    }
  }
});

test('requests bind exact IDs, digest, action, instructions and per-request caps', () => {
  assert.equal(model.validRequest(request(), uid, 'other-document'), false);
  for (const action of model.ACTIONS) {
    assert.equal(model.validRequest(request({ action, instructions: action === 'steer' ? 'Test-only steering' : '' }), uid), true);
  }
  rejectsChanges(model.validRequest, request, [
    ['unsafe ID', { requestId: 'request/child' }], ['unsafe parent', { parentBuildId: '' }],
    ['empty digest', { parentDigest: '' }], ['uppercase digest', { parentDigest: 'A'.repeat(64) }],
    ['unsupported action', { action: 'build' }], ['case drift', { action: 'UPGRADE' }],
    ['nontext instructions', { instructions: null }], ['long instructions', { instructions: 'x'.repeat(2001) }],
    ['empty steer', { action: 'steer', instructions: '' }], ['blank steer', { action: 'steer', instructions: ' \n\t' }],
    ['negative revision', { controlRevision: -1 }], ['fractional revision', { controlRevision: 1.5 }],
    ['invalid created time', { createdAt: 'invalid' }], ['invalid expiry', { expiresAt: null }],
  ]);
  for (const [key, ceiling] of [['maxProviderCalls', 20], ['maxToolCalls', 12]]) {
    for (const invalid of [0, -1, 1.5, '1', Infinity, ceiling + 1]) {
      assert.equal(model.validRequest(request({ [key]: invalid }), uid), false, `${key}: ${invalid}`);
    }
    assert.equal(model.validRequest(request({ [key]: ceiling }), uid), true);
  }
  assert.equal(model.validRequest(request({ controlRevision: 0, instructions: 'x'.repeat(2000) }), uid), true);
});

test('receipts allow only declared host states and reject identity/action drift', () => {
  assert.equal(model.validReceipt(receipt(), uid, 'other-document'), false);
  for (const state of ['QUEUED', 'WAITING_BUDGET', 'RUNNING', 'COMPLETE', 'REJECTED', 'FAILED']) {
    assert.equal(model.validReceipt(receipt({ state }), uid), true, state);
  }
  assert.equal(model.validReceipt(receipt({ buildId: 'test-only-child' }), uid), true);
  rejectsChanges(model.validReceipt, receipt, [
    ['unsafe request ID', { requestId: 'request/child' }], ['unsafe parent', { parentBuildId: '' }],
    ['unsupported action', { action: 'build' }], ['unknown state', { state: 'SUCCESS' }],
    ['state case drift', { state: 'complete' }], ['invalid reason', { reason: null }],
    ['long reason', { reason: 'x'.repeat(16001) }], ['unsafe child ID', { buildId: 'child/build' }],
    ['invalid timestamp', { updatedAt: 'invalid' }],
  ]);
});

test('authority requires server-verified owner workspace and every full-mode permission', () => {
  const base = context();
  assert.equal(model.authorityReason(base), '');
  for (const change of [{ exists: false }, { verified: false }, { busy: true }, { workspace: null },
    { workspace: { ...base.workspace.workspace, ownerUid: 'different-owner' } }]) {
    assert.match(model.authorityReason(context({ workspace: { ...base.workspace, ...change } })), /Owner settings.*server-verified/);
  }
  assert.notEqual(model.authorityReason(context({ workspace: null })), '');
  for (const key of ['autonomyMode', 'autonomyAcknowledged', 'learningEnabled']) {
    for (const value of [undefined, false, 'true']) {
      const workspace = { ...base.workspace, workspace: { ...base.workspace.workspace, [key]: value } };
      assert.match(model.authorityReason(context({ workspace })), /confirmed full mode, learning, workspace read and workspace write/);
    }
  }
  for (const key of ['workspaceRead', 'workspaceWrite']) {
    for (const value of [undefined, false, 'true']) {
      const workspace = { ...base.workspace, workspace: { ...base.workspace.workspace,
        permissions: { ...base.workspace.workspace.permissions, [key]: value } } };
      assert.notEqual(model.authorityReason(context({ workspace })), '', key);
    }
  }
});

test('offline, cached or pending projections cannot establish verified authority', () => {
  assert.match(model.authorityReason(context({ offline: true })), /Offline/);
  // authorityReason consumes store-derived verified flags, not snapshot metadata.
  // Cache/pending mapping itself belongs to the store integration lane.
  for (const origin of ['cached', 'pending']) {
    for (const key of ['status', 'controls']) {
      const verified = { ...context().verified, [key]: false };
      assert.notEqual(model.authorityReason(context({ verified })), '', `${origin} ${key} is not verified`);
    }
    const workspace = { ...context().workspace, verified: false };
    assert.notEqual(model.authorityReason(context({ workspace })), '', `${origin} workspace is not verified`);
  }
  assert.notEqual(model.authorityReason(context({ verified: {} })), '');
  for (const change of [{ status: null }, { status: status({ ownerUid: 'other' }) },
    { controls: controls({ revision: 0 }) }, { controls: controls({ ownerUid: 'other' }) }]) {
    assert.notEqual(model.authorityReason(context(change)), '');
  }
});

test('authority checks precise freshness bounds and rejects host failure states', () => {
  for (const offset of [model.FRESHNESS_MS, -60000]) {
    assert.equal(model.authorityReason(context({ now: now + offset })), '');
  }
  for (const offset of [model.FRESHNESS_MS + 1, -60001]) {
    assert.match(model.authorityReason(context({ now: now + offset })), /out of date/);
  }
  for (const state of ['INVALID', 'REJECTED', 'DISCONNECTED', 'BLOCKED', 'ERROR']) {
    assert.match(model.authorityReason(context({ status: status({ state, reason: 'Test-only host rejection' }) })),
      /Host controls unavailable: Test-only host rejection/);
  }
});

test('requests require COMPLETE verified digest-bound parents and effective intent revision', () => {
  assert.equal(model.requestReason(context(), build(), 'upgrade'), '');
  assert.match(model.requestReason(context({ status: status({ requestedRevision: 3, effectiveRevision: 1 }) }), build(), 'upgrade'), /apply.*intent revision/);
  assert.equal(model.requestReason(context({ status: status({ requestedRevision: 3, effectiveRevision: 2 }) }), build(), 'upgrade'), '',
    'effectiveRevision, not requestedRevision, is matched against current owner intent');
  for (const candidate of [null, build({ ownerUid: 'other' }), build({ status: 'BUILDING' }),
    build({ status: 'complete' }), build({ bundleDigest: '' }), build({ bundleDigest: 'A'.repeat(64) })]) {
    assert.match(model.requestReason(context(), candidate, 'upgrade'), /server-verified COMPLETE build.*exact bundle digest/);
  }
  assert.match(model.requestReason(context({ verified: { ...context().verified, builds: false } }), build(), 'upgrade'), /server-verified COMPLETE/);
  assert.match(model.requestReason(context(), build(), 'execute'), /supported action/);
  assert.match(model.requestReason(context({ offline: true }), build(), 'upgrade'), /Offline/);
  const defaultContext = context({ controls: null, status: status({ requestedRevision: 0, effectiveRevision: 0 }) });
  assert.equal(model.requestReason(defaultContext, build(), 'upgrade'), '', 'verified absent intent uses host default revision zero');
  assert.notEqual(model.requestReason(context({ ...defaultContext, verified: { status: true, controls: false, builds: true } }), build(), 'upgrade'), '');
});

test('archive/restore are reversible organization requests, not alternate execution authority', () => {
  for (const action of ['upgrade', 'steer', 'discover', 'archive']) {
    assert.equal(model.requestReason(context(), build(), action), '', action);
    assert.match(model.requestReason(context(), build({ archived: true }), action), /Restore this archived build/);
  }
  assert.match(model.requestReason(context(), build(), 'restore'), /not archived/);
  assert.equal(model.requestReason(context(), build({ archived: true }), 'restore'), '');
  assert.match(model.requestReason(context({ offline: true }), build({ archived: true }), 'restore'), /Offline/);
});

test('controls preview is frozen, increments intent and contains only explicit writable fields', () => {
  const base = context();
  const candidate = { ...caps(), maxDailyJobs: 2, unexpected: 'not sent' };
  const preview = model.controlsPreview(base, candidate);
  assert.deepEqual(preview, { schemaVersion: model.CONTROLS_SCHEMA, ownerUid: uid, revision: 3,
    maxDailyJobs: 2, maxDailyProviderCalls: 12, maxDailyToolCalls: 4 });
  assert.equal(Object.isFrozen(preview), true);
  assert.throws(() => { preview.maxDailyJobs = 4; }, TypeError);
  candidate.maxDailyJobs = 4;
  assert.equal(preview.maxDailyJobs, 2);
  assert.equal(base.controls.revision, 2);
  assert.equal(Object.hasOwn(preview, 'updatedAt'), false, 'server timestamp is added at commit, not preview');
  const first = model.controlsPreview(context({ controls: null, status: status({ requestedRevision: 0, effectiveRevision: 0 }) }), caps());
  assert.equal(first.revision, 1);
  assert.throws(() => model.controlsPreview(context({ offline: true }), caps()), /Offline/);
  assert.throws(() => model.controlsPreview(context(), { ...caps(), maxDailyJobs: 5 }), /ceilings|whole positive/);
  assert.throws(() => model.controlsPreview(context({ status: status({ ceilings: caps() }) }), { ...caps(), maxDailyJobs: 2 }), /ceilings/);
});

test('request preview freezes exact target/action/instructions/caps and a six-day expiry', () => {
  const base = context();
  const parent = build();
  const candidate = input({ action: 'steer', instructions: '  Test-only direction\nKeep exact text.  ', unexpected: 'not sent' });
  const preview = model.requestPreview(base, parent, candidate, 'test-only-preview', now);
  assert.deepEqual(preview, {
    schemaVersion: model.REQUEST_SCHEMA, ownerUid: uid, requestId: 'test-only-preview',
    parentBuildId: 'test-only-build', parentDigest: bundleDigest, action: 'steer',
    instructions: candidate.instructions, maxProviderCalls: 3, maxToolCalls: 2,
    controlRevision: 2, expiresAt: '2026-09-20T08:00:00.000Z',
  });
  assert.equal(Object.isFrozen(preview), true);
  assert.throws(() => { preview.parentDigest = fileDigest; }, TypeError);
  candidate.instructions = 'Changed input';
  parent.bundleDigest = fileDigest;
  base.controls.revision = 3;
  assert.equal(preview.instructions, '  Test-only direction\nKeep exact text.  ');
  assert.equal(preview.parentDigest, bundleDigest);
  assert.equal(preview.controlRevision, 2);
  assert.equal(Object.hasOwn(preview, 'createdAt'), false, 'createdAt belongs to server commit');
  assert.equal(model.validRequest({ ...preview, createdAt: iso }, uid), true);
});

test('request preview enforces steering and effective caps even when requested caps are higher', () => {
  for (const change of [{ action: 'steer', instructions: '' }, { action: 'steer', instructions: '\n ' },
    { instructions: 'x'.repeat(2001) }, { maxProviderCalls: 0 }, { maxToolCalls: 1.5 },
    { maxProviderCalls: 13 }, { maxToolCalls: 5 }]) {
    assert.throws(() => model.requestPreview(context(), build(), input(change), 'test-only-preview', now), /instructions.*caps/);
  }
  const pendingIncrease = context({ controls: controls({ maxDailyProviderCalls: 20, maxDailyToolCalls: 12 }) });
  assert.throws(() => model.requestPreview(pendingIncrease, build(), input({ maxProviderCalls: 13 }), 'test-only-preview', now), /host-applied budgets/);
  assert.throws(() => model.requestPreview(context(), build(), input(), 'unsafe/id', now), /instructions.*caps/);
  assert.throws(() => model.requestPreview(context(), build(), input({ action: 'execute' }), 'test-only-preview', now), /supported action/);
  assert.throws(() => model.requestPreview(context({ status: status({ effectiveRevision: 1 }) }), build(), input(), 'test-only-preview', now), /intent revision/);
  const atCaps = model.requestPreview(context(), build(), input({ maxProviderCalls: 12, maxToolCalls: 4 }), 'test-only-preview', now);
  assert.equal(atCaps.maxProviderCalls, 12);
  assert.equal(atCaps.maxToolCalls, 4);
});

test('sameRequest checks all frozen fields while allowing server timestamp and receipt evidence', () => {
  const expected = model.requestPreview(context(), build(), input(), 'test-only-preview', now);
  const expiry = Date.parse(expected.expiresAt);
  const actual = { ...expected, createdAt: { seconds: now / 1000, nanoseconds: 0 }, hostEvidence: 'test-only',
    expiresAt: { seconds: expiry / 1000, nanoseconds: 0 } };
  assert.equal(model.sameRequest(actual, expected), true);
  assert.equal(model.sameRequest({ ...actual, expiresAt: { toMillis: () => expiry } }, expected), true);
  for (const key of Object.keys(expected)) {
    const changed = { ...actual, [key]: key === 'expiresAt' ? new Date(expiry + 1).toISOString()
      : typeof expected[key] === 'number' ? expected[key] + 1 : `${expected[key]}-changed` };
    assert.equal(model.sameRequest(changed, expected), false, `${key} drift`);
    const missing = { ...actual };
    delete missing[key];
    assert.equal(model.sameRequest(missing, expected), false, `missing ${key}`);
  }
});

test('search covers title, summary and ID case-insensitively without mixing archives or mutating input', () => {
  const older = build({ buildId: 'id-match', title: 'Older title', summary: 'Other', createdAt: '2026-09-13T08:00:00Z' });
  const title = build({ buildId: 'b-title', title: 'Needle title', summary: 'Other' });
  const summary = build({ buildId: 'a-summary', title: 'Other', summary: 'Needle purpose' });
  const archived = build({ buildId: 'archived-match', title: 'Needle archive', archived: true });
  const source = Object.freeze([older, title, archived, summary].map(Object.freeze));
  assert.deepEqual(model.filterBuilds(source).map(b => b.buildId), ['a-summary', 'b-title', 'id-match']);
  assert.deepEqual(model.filterBuilds(source, 'NEEDLE').map(b => b.buildId), ['a-summary', 'b-title']);
  assert.deepEqual(model.filterBuilds(source, 'ID-MATCH').map(b => b.buildId), ['id-match']);
  assert.deepEqual(model.filterBuilds(source, 'needle', true).map(b => b.buildId), ['archived-match']);
  assert.deepEqual(model.filterBuilds(source, 'missing'), []);
  assert.deepEqual(model.filterBuilds([], '', true), []);
  assert.deepEqual(source.map(b => b.buildId), ['id-match', 'b-title', 'archived-match', 'a-summary']);
});

test('artifact download filenames are basename-only sanitized text, never executable extensions', () => {
  for (const [path, expected] of [
    ['index.html', 'index.html.txt'], ['src/run.js', 'run.js.txt'],
    ['../../report.md', 'report.md.txt'], ['C:\\private\\run.cmd', 'run.cmd.txt'],
    ['unsafe name<script>.html', 'unsafe_name_script_.html.txt'],
    ['notes.txt', 'notes.txt.txt'], ['', 'artifact.txt'], ['folder/', 'artifact.txt'],
  ]) {
    const name = model.downloadName(path);
    assert.equal(name, expected);
    assert.match(name, /^[A-Za-z0-9._-]+\.txt$/);
    assert.doesNotMatch(name, /[\\/]/);
  }
});

// TEST-ONLY continuation and host envelopes. No live research/build evidence.
const continuation = (changes = {}) => ({
  schemaVersion: model.CONTINUATION_SCHEMA, enabled: true, state: 'DAILY_CAP',
  objective: 'Fixture: make the saved worksheet easier to verify',
  whatHappened: 'Fixture: the prior version was saved and reviewed.',
  whatImproved: 'Fixture: the saved version now explains its fee inputs.',
  nextAction: 'Fixture: queue one justified follow-up after the budget window.',
  blocker: 'Fixture: rolling job budget is exhausted.',
  nextEligibleAt: '2026-09-15T08:00:00.000Z', cycleId: 'test-only-cycle',
  parentBuildId: 'test-only-parent', childBuildId: null,
  research: { attempted: 2, verified: 1, maxPer24h: 2 }, updatedAt: iso, ...changes,
});
const delivery = (changes = {}) => ({
  schemaVersion: 'cct.owner_delivery.v1', ownerUid: uid, scope: 'PRIVATE_SANDBOXED_LOCAL_DELIVERY',
  trigger: 'AUTO_FULL_MODE', phase: 'IDLE', reason: 'Fixture envelope only.',
  nextAction: 'Fixture host next step.', counts: { queued: 0, complete: 0, blocked: 0, retry: 0 },
  job: null, lastOutcome: null, updatedAt: iso, continuation: continuation(), ...changes,
});
const continuationOptions = (changes = {}) => ({ uid, fromCache: false, hasPendingWrites: false, now, ...changes });

test('continuation validates the complete nested schema without coercing missing fields', () => {
  assert.equal(model.CONTINUATION_SCHEMA, 'cct.owner_continuation.v1');
  assert.equal(model.validContinuation(continuation()), true);
  for (const value of [undefined, null, [], 'COMPLETE', true]) assert.equal(model.validContinuation(value), false);
  for (const key of Object.keys(continuation())) {
    const value = continuation(); delete value[key];
    assert.equal(model.validContinuation(value), false, `missing ${key}`);
  }
  for (const change of [
    { schemaVersion: 'cct.owner_continuation.v2' }, { enabled: 'true' }, { state: '' }, { state: '<script>' },
    { objective: {} }, { whatHappened: null }, { whatImproved: false }, { nextAction: [] }, { blocker: 0 },
    { objective: 'x'.repeat(4001) }, { whatHappened: 'x'.repeat(4001) },
    { cycleId: '../cycle' }, { parentBuildId: {} }, { childBuildId: 'unsafe/child' },
    { nextEligibleAt: '' }, { nextEligibleAt: now }, { nextEligibleAt: '2026-09-15T08:00:00' },
    { updatedAt: null }, { updatedAt: 'yesterday' }, { updatedAt: { seconds: now / 1000 } },
    { research: null }, { research: [] }, { research: { attempted: 1, verified: 1 } },
    { research: { attempted: -1, verified: 0, maxPer24h: 2 } },
    { research: { attempted: '2', verified: 1, maxPer24h: 2 } },
    { research: { attempted: 2, verified: 0.5, maxPer24h: 2 } },
    { research: { attempted: 1, verified: 2, maxPer24h: 2 } },
    { research: { attempted: 2, verified: 1, maxPer24h: 3 } },
    { research: { attempted: 3, verified: 1, maxPer24h: 2 } },
    { objective: 'x'.repeat(1201) }, { whatImproved: 'x'.repeat(1201) },
    { cycleId: '' }, { blocker: undefined }, { state: 'COMPLETE' }, { state: 'WAITING_BUDGET' },
  ]) assert.equal(model.validContinuation(continuation(change)), false, JSON.stringify(change).slice(0, 180));
  assert.equal(model.validContinuation(continuation({ nextEligibleAt: null, childBuildId: 'test-only-child',
    updatedAt: '2026-09-14T08:00:00.123456+00:00' })), true, 'host ISO fractions and offsets are supported');
  const circular = continuation(); circular.extra = circular;
  assert.equal(model.validContinuation(circular), false);
});

test('continuation requires verified owner envelope and independently fresh nested status', () => {
  const summarize = (value = delivery(), changes = {}) => model.continuationSummary(value, continuationOptions(changes));
  assert.equal(summarize().available, true);
  assert.equal(model.continuationSummary(delivery(), { uid, now }).available, false, 'metadata defaults unverified');
  for (const [label, value, changes] of [
    ['signed out', delivery(), { uid: '' }], ['other owner', delivery(), { uid: 'different-owner' }],
    ['wrong envelope', delivery({ schemaVersion: 'cct.owner_delivery.future' }), {}],
    ['wrong scope', delivery({ scope: 'PUBLIC_DELIVERY' }), {}],
    ['missing envelope', null, {}], ['missing continuation', delivery({ continuation: undefined }), {}],
    ['null continuation', delivery({ continuation: null }), {}],
    ['malformed', delivery({ continuation: { state: 'COMPLETE' } }), {}],
    ['unknown state', delivery({ continuation: continuation({ state: 'NEW_HOST_STATE' }) }), {}],
    ['contradictory flag', delivery({ continuation: continuation({ enabled: true, state: 'DISABLED' }) }), {}],
    ['cache', delivery(), { fromCache: true }], ['pending write', delivery(), { hasPendingWrites: true }],
    ['offline', delivery(), { offline: true }], ['read error', delivery(), { error: 'Test-only read outage' }],
    ['non-finite clock', delivery(), { now: NaN }],
  ]) {
    const result = summarize(value, changes);
    assert.equal(result.available, false, label);
    assert.equal(result.label, 'Continuation status unavailable', label);
    assert.equal(result.receipt, null, 'unavailable data must not retain a prior receipt');
    assert.equal(result.objective, undefined, 'unavailable private narrative must not leak');
  }
  for (const field of ['envelope', 'continuation']) {
    for (const [age, expected] of [[model.FRESHNESS_MS, true], [model.FRESHNESS_MS + 1, false], [-60_000, true], [-60_001, false]]) {
      const updatedAt = new Date(now - age).toISOString();
      const value = field === 'envelope' ? delivery({ updatedAt }) : delivery({ continuation: continuation({ updatedAt }) });
      assert.equal(summarize(value).available, expected, `${field} age ${age}`);
    }
  }
});

test('human continuation account separates host outcomes, queued intent, WAIT and research receipts', () => {
  const value = delivery();
  const result = model.continuationSummary(value, continuationOptions());
  assert.equal(result.label, 'Waiting for budget');
  assert.equal(result.happened, value.continuation.whatHappened);
  assert.equal(result.improved, value.continuation.whatImproved);
  assert.equal(result.nextAction, value.continuation.nextAction);
  assert.equal(result.blocker, value.continuation.blocker);
  assert.match(result.researchLabel, /2 fetch attempts charged \/ 2 allowed; 1 fetch receipts verified/);
  assert.deepEqual(result.receipt.research, { attempted: 2, verified: 1, maxPer24h: 2 });
  assert.equal(result.receipt.cycleId, 'test-only-cycle');
  assert.equal(result.receipt.parentBuildId, 'test-only-parent');
  assert.equal(result.receipt.updatedAt, iso);
  assert.equal(result.receipt.deliveryUpdatedAt, iso);
  for (const [state, label] of [['QUEUED', 'Next build queued · not yet executed'],
    ['WAIT', 'Waiting before continuing'], ['LEARNED', 'Build outcome recorded'],
    ['DECIDING', 'Choosing an objective from the gathered evidence'], ['BLOCKED', 'Continuation is blocked']]) {
    const item = continuation({ state, whatImproved: ' ', childBuildId: 'test-only-child', nextEligibleAt: null });
    const summary = model.continuationSummary(delivery({ continuation: item }), continuationOptions());
    assert.equal(summary.label, label);
    assert.equal(summary.improved, 'No verified improvement reported.', 'state or child ID is not proof of improvement');
    assert.equal(summary.nextEligibleAt, null);
    assert.doesNotMatch(summary.label, /successful|accepted|verified improvement/i);
  }
  const disabled = model.continuationSummary(delivery({ continuation: continuation({ enabled: false, state: 'DISABLED',
    objective: '', whatHappened: '', whatImproved: '', nextAction: '', blocker: '',
    cycleId: null, parentBuildId: null, childBuildId: null, nextEligibleAt: null,
    research: { attempted: 0, verified: 0, maxPer24h: 2 } }) }), continuationOptions());
  assert.equal(disabled.available, true, 'explicit off state differs from an absent projection');
  assert.equal(disabled.label, 'Automatic continuation is off');
  assert.equal(disabled.objective, 'No current objective reported.');
  assert.equal(disabled.happened, 'No new activity reported.');
  assert.equal(disabled.improved, 'No verified improvement reported.');
  assert.equal(disabled.nextAction, 'Automatic continuation is off.');
  assert.equal(disabled.blocker, '');
});

// Minimal DOM + SDK test doubles execute production controller/renderer code.
// They assert structure and lifecycle, not CSS layout or a real host outcome.
class BuildsElement {
  constructor(tag) { this.tagName = tag; this.children = []; this.dataset = {}; this.attributes = {}; this.ownText = ''; this.value = ''; this.listeners = new Map(); }
  set textContent(value) { this.ownText = String(value); this.children = []; }
  get textContent() { return this.ownText + this.children.map(c => c.textContent).join('\n'); }
  append(...children) { this.children.push(...children); }
  prepend(...children) { this.children.unshift(...children); }
  replaceChildren(...children) { this.ownText = ''; this.children = children; }
  setAttribute(key, value) { this.attributes[key] = value; }
  addEventListener(name, fn) { this.listeners.set(name, fn); }
  removeEventListener(name) { this.listeners.delete(name); }
  querySelector(selector) { return this.querySelectorAll(selector)[0] || null; }
  querySelectorAll(selector) {
    const matches = item => selector.startsWith('[data-')
      ? Object.hasOwn(item.dataset, selector.slice(6, -1).replace(/-([a-z])/g, (_, letter) => letter.toUpperCase()))
      : item.tagName === selector;
    return this.children.flatMap(child => [...(matches(child) ? [child] : []), ...child.querySelectorAll(selector)]);
  }
}
function continuationHarness() {
  const root = new BuildsElement('section');
  const source = readFileSync(new URL('../src/owner-builds.js', import.meta.url), 'utf8');
  const subscriptions = [], listeners = new Map(), timers = new Map();
  let clock = now;
  const ctx = vm.createContext({ ...model,
    continuationSummary: (value, options) => model.continuationSummary(value, { now: clock, ...options }),
    document: { createElement: tag => new BuildsElement(tag), getElementById: id => id === 'owner-builds' ? root : null },
    navigator: { onLine: true }, sessionStorage: { getItem: () => null },
    window: { addEventListener: (name, fn) => listeners.set(name, fn), removeEventListener: name => listeners.delete(name),
      setInterval: fn => { timers.set(1, fn); return 1; }, clearInterval: id => timers.delete(id) },
    doc: (_db, collection, id) => ({ collection, id }), collection: (_db, name) => ({ collection: name }),
    documentId: () => '__name__', where: (...args) => args, orderBy: value => value, limit: value => value,
    query: (ref, ...constraints) => ({ ...ref, constraints }),
    onSnapshot: (ref, _options, success, failure) => {
      const entry = { ref, success, failure, stopped: false }; subscriptions.push(entry);
      return () => { entry.stopped = true; };
    },
  });
  vm.runInContext(source.replace(/^import[\s\S]*?;\n/gm, '').replaceAll('export function ', 'function '), ctx);
  return { root, ctx, source, subscriptions, listeners, timers, setClock: value => { clock = value; } };
}

test('continuation renderer uses human order, compact expandable exact receipts and text nodes only', () => {
  const h = continuationHarness();
  const injection = '<img src=x onerror="window.continuationExecuted=true"><script>bad()</script>';
  const value = delivery({ continuation: continuation({ whatHappened: injection, objective: injection,
    whatImproved: injection, nextAction: injection, blocker: injection, unexpected: { html: injection } }) });
  h.ctx.renderOwnerContinuation(h.root, value, continuationOptions());
  const steps = h.root.querySelector('dl').children;
  assert.deepEqual(steps.map(row => row.children[0].textContent), ['What happened', 'What improved', 'What comes next', 'What is blocking it']);
  for (const step of steps) assert.equal(step.children[1].textContent, injection);
  assert.equal(h.root.querySelector('h4').textContent, injection);
  const technical = h.root.querySelector('details');
  assert.equal(technical.open, false);
  const receipt = JSON.parse(technical.querySelector('pre').textContent);
  assert.equal(receipt.cycleId, 'test-only-cycle');
  assert.equal(receipt.state, 'DAILY_CAP');
  assert.equal(receipt.unexpected, undefined);
  assert.equal(receipt.bundleDigest, undefined, 'no manufactured hash');
  assert.match(h.root.textContent, /not a scheduled start or a promise of execution/);
  assert.match(h.root.textContent, /Verified fetch receipts mean public evidence was fetched, not that a build improved/);
  for (const tag of ['button', 'form', 'input', 'a', 'img', 'script', 'iframe']) assert.equal(h.root.querySelectorAll(tag).length, 0, tag);
  assert.equal(h.root.querySelectorAll('p').find(el => el.attributes.role === 'status').attributes['aria-live'], 'polite');
  technical.open = true;
  h.ctx.renderOwnerContinuation(h.root, delivery(), continuationOptions());
  assert.equal(h.root.querySelector('details').open, true, 'heartbeat retains receipt expansion');
  h.ctx.renderOwnerContinuation(h.root, delivery({ continuation: {} }), continuationOptions());
  assert.equal(h.root.dataset.state, 'unavailable');
  assert.equal(h.root.querySelector('details'), null, 'unavailable readback erases earlier private receipt');
  assert.equal(h.root.querySelector('h4'), null);
  assert.match(h.root.textContent, /Continuation status unavailable/);
  assert.doesNotMatch(h.root.textContent, /test-only-cycle|NaN|undefined|\[object Object\]/);
});

test('mounted continuation reuses forwarded delivery, expires without new snapshots and resets on signout', () => {
  const h = continuationHarness();
  const mounted = h.ctx.mountOwnerBuilds({}, uid, context().workspace, () => ({ state: 'CONNECTED' }));
  assert.equal(typeof mounted.setDelivery, 'function');
  assert.match(h.root.textContent, /Continuation status unavailable/);
  const refs = h.subscriptions.map(entry => entry.ref.collection);
  assert.deepEqual(refs, ['cct_owner_build_controls', 'cct_owner_build_controls_status', 'cct_owner_builds', 'cct_owner_build_requests', 'cct_owner_build_request_status']);
  assert.equal(refs.includes('cct_owner_delivery'), false, 'no duplicate delivery subscription');
  mounted.setDelivery(delivery());
  assert.match(h.root.textContent, /Continuation status unavailable/, 'payload without read metadata fails closed');
  mounted.setDelivery(delivery(), { fromCache: false, hasPendingWrites: false });
  assert.match(h.root.textContent, /Fixture: make the saved worksheet easier to verify/);
  for (const metadata of [{ fromCache: true }, { fromCache: false, hasPendingWrites: true }, { fromCache: false, error: 'Fixture outage' }]) {
    mounted.setDelivery(delivery(), metadata);
    assert.match(h.root.textContent, /Continuation status unavailable/);
    assert.doesNotMatch(h.root.textContent, /test-only-cycle/);
  }
  mounted.setDelivery(delivery(), { fromCache: false });
  h.ctx.navigator.onLine = false; h.listeners.get('offline')();
  assert.match(h.root.textContent, /Continuation status unavailable/);
  h.ctx.navigator.onLine = true; h.listeners.get('online')();
  assert.match(h.root.textContent, /Fixture: make the saved worksheet easier to verify/);
  h.setClock(now + model.FRESHNESS_MS + 1); h.timers.get(1)();
  assert.match(h.root.textContent, /Continuation status unavailable/);
  h.setClock(now); mounted.setDelivery(delivery(), { fromCache: false });
  mounted.stop();
  assert.equal(h.root.textContent, '');
  assert.equal(h.subscriptions.every(entry => entry.stopped), true);
  assert.equal(h.listeners.size, 0); assert.equal(h.timers.size, 0);
  mounted.setDelivery(delivery(), { fromCache: false });
  mounted.refresh();
  assert.equal(h.root.textContent, '', 'late delivery callbacks cannot repaint signed-out data');
  const anonymous = continuationHarness();
  anonymous.ctx.mountOwnerBuilds({}, '', context().workspace);
  assert.equal(anonymous.subscriptions.length, 0);
  assert.equal(anonymous.root.textContent, '');
});


test('continuation matches emitted host states, nullable status fields and disabled configuration failure', () => {
  assert.equal(model.validContinuation(continuation({ objective: '😀'.repeat(1200) })), true, 'Python Unicode length');
  assert.equal(model.validContinuation(continuation({ objective: '😀'.repeat(1201) })), false);
  // cct_agent/owner_continuation.py status()/tick() wire states; not delivery job phases.
  const states = ['DISABLED', 'IDLE', 'PLANNING', 'DECIDING', 'REVIEWING', 'READY',
    'QUEUED', 'WAIT', 'REJECTED', 'BLOCKED', 'COOLDOWN', 'DAILY_CAP', 'LEARNED'];
  for (const state of states) {
    const value = continuation({ state, enabled: state !== 'DISABLED', blocker: null,
      cycleId: null, parentBuildId: null, childBuildId: null, nextEligibleAt: null,
      whatImproved: '' });
    assert.equal(model.validContinuation(value), true, state);
    const result = model.continuationSummary(delivery({ continuation: value }), continuationOptions());
    assert.equal(result.available, true, state);
    assert.equal(result.receipt.cycleId, null);
    assert.equal(result.receipt.parentBuildId, null);
    assert.equal(result.receipt.childBuildId, null);
    assert.equal(result.improved, 'No verified improvement reported.');
    assert.equal(result.blocker, '');
  }
  const blocked = continuation({ state: 'BLOCKED', enabled: false,
    blocker: 'CONTINUATION_CONFIG_MISSING', parentBuildId: null, childBuildId: null });
  const result = model.continuationSummary(delivery({ continuation: blocked }), continuationOptions());
  assert.equal(result.available, true, 'disabled configuration errors are explicit BLOCKED, not malformed');
  assert.equal(result.blocker, 'CONTINUATION_CONFIG_MISSING');
  assert.equal(result.label, 'Continuation is blocked');
  assert.equal(model.continuationSummary(delivery({ continuation: continuation({ enabled: false, state: 'QUEUED' }) }), continuationOptions()).available, false);
});
