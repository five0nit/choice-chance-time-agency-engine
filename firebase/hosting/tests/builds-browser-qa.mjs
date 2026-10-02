// Isolated Builds flow against production modules and a local Firestore emulator.
// Continuation fixtures are synthetic wire-shape evidence, never real host outcomes.
import assert from 'node:assert/strict';
import { mkdir, writeFile, readFile } from 'node:fs/promises';
import { collection, getDocs } from 'firebase/firestore';
import { chromium } from 'playwright';
import { startHarness } from './browser-harness.mjs';
import { defaultWorkspace } from '../src/workspace-model.js';
import { checkBuilds } from './owner-builds-browser.mjs';

async function checkContinuation({ page, harness, ownerUid, checks, output }) {
  const panel = page.locator('#builds-continuation');
  const fixture = (changes = {}) => ({
    schemaVersion: 'cct.owner_continuation.v1', enabled: true, state: 'PLANNING',
    objective: 'TEST FIXTURE: improve the saved worksheet explanation',
    whatHappened: 'TEST FIXTURE: comparing saved evidence and an actual-outcome-shaped record.',
    whatImproved: '', nextAction: 'TEST FIXTURE: resume only when current authority and capacity permit.',
    blocker: null, nextEligibleAt: null, cycleId: 'continuation-browser-fixture',
    parentBuildId: null, childBuildId: null,
    research: { attempted: 0, verified: 0, maxPer24h: 2 }, updatedAt: new Date().toISOString(), ...changes,
  });
  const envelope = (continuation, changes = {}) => ({
    schemaVersion: 'cct.owner_delivery.v1', ownerUid, scope: 'PRIVATE_SANDBOXED_LOCAL_DELIVERY',
    trigger: 'AUTO_FULL_MODE', phase: 'IDLE', reason: 'TEST FIXTURE ONLY; no live work.',
    nextAction: 'TEST FIXTURE ONLY; no execution inferred.',
    counts: { queued: 0, complete: 0, blocked: 0, retry: 0 }, job: null, lastOutcome: null,
    updatedAt: new Date().toISOString(), continuation, ...changes,
  });
  const seed = value => harness.seedOwnerDocument('cct_owner_delivery', 'current', value);
  const waitLabel = label => page.waitForFunction(expected =>
    document.querySelector('#builds-continuation .builds-continuation-status')?.textContent === expected, label);
  const authoritySnapshot = async () => {
    const result = {};
    // Read once before/after; these are not subscriptions or production writes.
    await harness.env.withSecurityRulesDisabled(async context => {
      for (const name of ['cct_workspace', 'cct_owner_build_controls', 'cct_owner_build_requests']) {
        result[name] = (await getDocs(collection(context.firestore(), name))).docs
          .map(d => ({ id: d.id, data: d.data() })).sort((a, b) => a.id.localeCompare(b.id));
      }
    });
    return result;
  };
  const authorityBefore = await authoritySnapshot();
  await waitLabel('Continuation status unavailable');
  assert.equal(await panel.locator('h4, details').count(), 0, 'no absent-status success');

  // These are the exact states emitted by owner_continuation.py, not job phases.
  const states = [
    ['DISABLED', 'Automatic continuation is off', { enabled: false, cycleId: null }],
    ['IDLE', 'Waiting for a useful next step', { cycleId: null }],
    ['PLANNING', 'Considering the next objective', {}],
    ['DECIDING', 'Choosing an objective from the gathered evidence', { research: { attempted: 2, verified: 1, maxPer24h: 2 } }],
    ['REVIEWING', 'Checking whether the next step adds value', {}],
    ['READY', 'Ready to consider the next step', {}],
    ['QUEUED', 'Next build queued · not yet executed', { parentBuildId: 'fixture-parent', childBuildId: 'fixture-child' }],
    ['WAIT', 'Waiting before continuing', {}],
    ['REJECTED', 'Proposed next step was not accepted', { blocker: 'CONTINUATION_NOVELTY_REJECTED' }],
    ['BLOCKED', 'Continuation is blocked', { enabled: false, blocker: 'CONTINUATION_CONFIG_MISSING' }],
    ['COOLDOWN', 'Waiting before the next eligible attempt', { blocker: 'CONTINUATION_DEPENDENCY_UNAVAILABLE', nextEligibleAt: new Date(Date.now() + 3600000).toISOString() }],
    ['DAILY_CAP', 'Waiting for budget', { blocker: 'DELIVERY_JOB_DAILY_CAP', nextEligibleAt: new Date(Date.now() + 86400000).toISOString() }],
    ['LEARNED', 'Build outcome recorded', { whatImproved: 'TEST FIXTURE: the recorded artifact explains its fee inputs.', parentBuildId: 'fixture-parent', childBuildId: 'fixture-child' }],
  ];
  for (const [state, label, changes] of states) {
    const value = envelope(fixture({ state, ...changes }));
    await seed(value);
    // Persisted startup avoids the emulator's initial newly-created-doc listener race.
    if (state === 'DISABLED') await page.reload();
    await waitLabel(label);
    assert.deepEqual(await panel.locator('dt').allTextContents(),
      ['What happened', 'What improved', 'What comes next', ...(changes.blocker ? ['What is blocking it'] : [])]);
    assert.equal(await panel.locator('button, input, textarea, form, a, iframe, img, script').count(), 0);
    assert.equal(await panel.locator('details').evaluate(el => el.open), false);
    if (state !== 'LEARNED') assert.equal(await panel.locator('[data-continuation-step="improved"] dd').innerText(), 'No verified improvement reported.');
    for (const width of [1440, 390]) {
      await page.setViewportSize({ width, height: width === 1440 ? 1000 : 844 });
      await panel.scrollIntoViewIfNeeded();
      assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true, `${state}: page overflow at ${width}`);
      assert.equal(await panel.evaluate(el => el.scrollWidth <= el.clientWidth), true, `${state}: panel overflow at ${width}`);
      await panel.screenshot({ path: output + `continuation-${state.toLowerCase()}-${width}.png` });
    }
    await panel.locator('summary').click();
    const receipt = JSON.parse(await panel.locator('pre').innerText());
    for (const key of ['schemaVersion', 'state', 'enabled', 'cycleId', 'parentBuildId', 'childBuildId', 'research', 'nextEligibleAt', 'updatedAt']) {
      assert.deepEqual(receipt[key], value.continuation[key], `${state}: exact ${key}`);
    }
    assert.equal(receipt.deliveryUpdatedAt, value.updatedAt);
    assert.equal(receipt.bundleDigest, undefined, 'never manufacture artifact receipts');
    await panel.locator('summary').click();
  }
  checks.push('Continuation: all emitted host states, nullable fields, disabled/BLOCKED configuration failure, exact expandable receipts; desktop and 390px screenshots');

  const injection = '<img src=x onerror="window.continuationExecuted=true"><script>window.continuationExecuted=true</script>';
  const literal = injection + ' fixture-long-token-'.repeat(45);
  await seed(envelope(fixture({ objective: literal, whatHappened: injection, whatImproved: injection, nextAction: injection, blocker: injection })));
  await waitLabel('Considering the next objective');
  assert.equal(await panel.locator('h4').textContent(), literal);
  for (const dd of await panel.locator('dd').allTextContents()) assert.equal(dd, injection);
  assert.equal(await panel.locator('img, script, iframe, a').count(), 0);
  assert.equal(await page.evaluate(() => window.continuationExecuted), undefined);
  assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true, 'literal long text at 390px');
  await panel.screenshot({ path: output + 'continuation-safe-text-390.png' });
  checks.push('Continuation: untrusted markup and long words remain literal, inert, wrapping text');

  const stale = new Date(Date.now() - 240000).toISOString();
  const absent = envelope(null); delete absent.continuation;
  for (const [name, value] of [
    ['absent', absent], ['null', envelope(null)], ['malformed', envelope({ state: 'LEARNED' })],
    ['unknown-state', envelope(fixture({ state: 'COMPLETE' }))],
    ['invalid-counters', envelope(fixture({ research: { attempted: 3, verified: 1, maxPer24h: 2 } }))],
    ['stale-nested', envelope(fixture({ updatedAt: stale }))],
    ['stale-envelope', envelope(fixture(), { updatedAt: stale })],
  ]) {
    await seed(envelope(fixture())); await waitLabel('Considering the next objective');
    await panel.locator('summary').click();
    await seed(value); await waitLabel('Continuation status unavailable');
    assert.equal(await panel.locator('h4, details, pre').count(), 0, `${name}: erase earlier private narrative/receipt`);
    assert.doesNotMatch(await panel.innerText(), /continuation-browser-fixture|fixture-parent|NaN|undefined|\[object Object\]/);
    await panel.screenshot({ path: output + `continuation-${name}-390.png` });
  }
  checks.push('Continuation: absent/null/malformed/unknown/invalid-counter/stale nested and envelope projections fail closed and clear prior private receipts');
  const finalValue = envelope(fixture({ state: 'QUEUED', childBuildId: 'fixture-child' }));
  await seed(finalValue); await waitLabel('Next build queued · not yet executed');
  assert.deepEqual(await authoritySnapshot(), authorityBefore, 'continuation viewing must not mutate workspace, budgets or owner requests');
  assert.equal(await page.locator('#owner-builds button[type="submit"]').isDisabled(), true, 'continuation cannot override stale budget authority');
  checks.push('Continuation: read-only viewing leaves existing owner settings/budgets/requests unchanged and cannot grant authority');
  return finalValue;
}

const output = (process.env.CCT_QA_OUTPUT || '/tmp/cct-builds-browser-qa') + '/';
await mkdir(output, { recursive: true });
const harness = await startHarness();
const browser = await chromium.launch({ headless: true, executablePath: process.env.CCT_CHROMIUM_PATH || '/usr/bin/google-chrome' });
const page = await browser.newPage({ viewport: { width: 1440, height: 1000 }, reducedMotion: 'reduce' });
const errors = [], checks = []; page.on('pageerror', e => errors.push(e.message));
try {
  const ownerUid = 'replace-with-owner-firebase-uid';
  await harness.seedOwnerDocument('cct_workspace', 'current', { ...defaultWorkspace(ownerUid), revision: 1, updatedAt: new Date() });
  const snapshot = JSON.parse(await readFile(new URL('./fixtures/dashboard-snapshot.json', import.meta.url), 'utf8'));
  snapshot.generated_at = new Date().toISOString(); await harness.seedSnapshot(snapshot);
  await page.goto(harness.url);
  await page.waitForSelector('#owner-builds h2');
  await checkBuilds({ page, harness, ownerUid, checks, output });
  const lastContinuation = await checkContinuation({ page, harness, ownerUid, checks, output });
  await page.context().setOffline(true);
  await page.waitForFunction(() => document.querySelector('#builds-continuation')?.dataset.state === 'unavailable');
  assert.equal(await page.locator('#owner-builds button[type="submit"]').isDisabled(), true);
  assert.equal(await page.locator('#builds-continuation details').count(), 0);
  await page.context().setOffline(false);
  await page.waitForFunction(() => document.querySelector('#builds-continuation')?.dataset.state === 'recorded');
  await page.locator('#sign-out').click();
  assert.equal(await page.locator('#owner-builds').innerText(), '');
  assert.equal(await page.locator('#app').isVisible(), false);
  // A later host projection must not revive the disposed owner UI.
  await harness.seedOwnerDocument('cct_owner_delivery', 'current', { ...lastContinuation, updatedAt: new Date().toISOString() });
  assert.equal(await page.locator('#owner-builds').innerText(), '');
  assert.equal(await page.locator('#builds-continuation').count(), 0);
  await page.screenshot({ path: output + 'continuation-signed-out-390.png', fullPage: false });
  checks.push('Builds/continuation: offline fails closed; signout removes private status/files/controls and ignores later projection');
  assert.deepEqual(errors, []);
  await writeFile(output + 'verification.json', JSON.stringify({ status: 'passed', checks, errors,
    scope: 'Real controller and Firestore emulator with synthetic identity and continuation fixtures; not signed-in production or executed host-outcome QA' }, null, 2));
  console.log(JSON.stringify({ status: 'passed', checks, errors, output }));
} catch (e) {
  await page.screenshot({ path: output + 'failure.png', fullPage: true });
  console.error(JSON.stringify({ checks, errors, host: await harness.readOwnerDocument('cct_owner_build_controls_status', 'current'),
    body: (await page.locator('#owner-builds').innerText()).slice(0, 6000) }));
  throw e;
} finally { await browser.close(); await harness.close(); }
