// Focused emulator proof. Genuine archived data copied locally; no production writes or model calls.
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { readFile, writeFile } from 'node:fs/promises';
import { execFileSync } from 'node:child_process';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { startHarness } from './browser-harness.mjs';
import { assertFails } from '@firebase/rules-unit-testing';
import { doc, getDocFromServer, serverTimestamp, setDoc } from 'firebase/firestore';
const require = createRequire(import.meta.url);
const { chromium } = require('playwright');
const report = process.env.CCT_QA_OUTPUT;
if (!report || process.env.FIRESTORE_EMULATOR_HOST !== '127.0.0.1:8080') throw Error('ISOLATED_EMULATOR_REQUIRED');
const data = JSON.parse(await readFile(join(report, 'owner-work-live.json'), 'utf8'));
const uid = data.workspace.ownerUid;
const discovery = { ...data.discovery, updatedAt: new Date().toISOString() };
const id = `promote-${discovery.question.id.slice(2)}-0`;
const h = await startHarness();
let browser;
const result = { mode: 'EMULATOR_ONLY', views: [], rules: [], productionWrites: 0, modelCalls: 0, publicFetches: 0 };
try {
  await h.seedOwnerDocument('cct_workspace', 'current', data.workspace);
  await h.seedOwnerDocument('cct_discovery', 'current', discovery);
  await h.seedOwnerDocument('cct_owner_work', 'current', data.work);
  browser = await chromium.launch({ headless: true, executablePath: process.env.CCT_QA_CHROMIUM || undefined });
  for (const viewport of [{ width: 1440, height: 1000 }, { width: 390, height: 844 }]) {
    const page = await browser.newPage({ viewport, reducedMotion: 'reduce' });
    const errors = []; page.on('pageerror', e => errors.push(e.message));
    await page.route('**/*', route => ['127.0.0.1','localhost'].includes(new URL(route.request().url()).hostname) ? route.continue() : route.abort());
    await page.goto(h.url + '/#owner-connection');
    await page.locator('#learning-tab').click();
    const button = page.locator('.discovery-promote').first();
    await button.waitFor();
    await page.waitForFunction(() => !document.querySelector('.discovery-promote')?.disabled);
    await button.scrollIntoViewIfNeeded();
    await page.screenshot({ path: join(report, `promotion-${viewport.width}.png`) });
    const dimensions = await page.evaluate(() => ({ page: document.documentElement.scrollWidth, viewport: innerWidth }));
    assert.ok(dimensions.page <= dimensions.viewport, 'horizontal overflow');
    if (viewport.width === 390) {
      await button.click();
      await page.waitForFunction(() => /Research requested/.test(document.querySelector('.discovery-promote').textContent));
      const saved = await h.readOwnerDocument('cct_work_requests', id);
      assert.equal(saved.state, 'PENDING');
      assert.deepEqual(saved.idea, discovery.workIdeas[0]);
      assert.equal(saved.turnId, discovery.question.id);
      const output = execFileSync(process.env.CCT_QA_PYTHON || 'python3', [fileURLToPath(new URL('./promotion-claim.py', import.meta.url))], { env: process.env, encoding: 'utf8', timeout: 30000 });
      result.worker = JSON.parse(output);
      await page.waitForFunction(() => document.querySelector('.discovery-promote').textContent === 'Queued');
      assert.equal(await button.isDisabled(), true);
      await page.screenshot({ path: join(report, 'promotion-queued-390.png') });
      await page.reload();
      await page.locator('#learning-tab').click();
      await page.waitForFunction(() => document.querySelector('.discovery-promote')?.textContent === 'Queued');
      assert.equal(await button.isDisabled(), true);
      result.reloadKeepsReceipt = true;
    }
    assert.deepEqual(errors, []);
    result.views.push({ viewport, dimensions, errors });
    await page.close();
  }
  const owner = h.env.authenticatedContext(uid, { email: 'owner@example.invalid', email_verified: true, firebase: { sign_in_provider: 'google.com' } }).firestore();
  const saved = (await getDocFromServer(doc(owner, 'cct_work_requests', id))).data();
  await assertFails(setDoc(doc(owner, 'cct_work_requests', id), { ...saved, createdAt: serverTimestamp() }));
  result.rules.push('immutable request overwrite denied');
  const candidate = { schemaVersion: 'cct.work_request.v1', ownerUid: uid, conversationId: discovery.conversationId,
    turnId: discovery.question.id, ideaIndex: 1, idea: discovery.workIdeas[1], scope: 'PUBLIC_RESEARCH_PRIVATE_REPORT', state: 'PENDING', createdAt: serverTimestamp() };
  const secondId = `promote-${discovery.question.id.slice(2)}-1`;
  await assertFails(setDoc(doc(owner, 'cct_work_requests', secondId), { ...candidate, idea: { ...candidate.idea, title: 'tampered' } }));
  result.rules.push('changed exact idea denied');
  await assertFails(setDoc(doc(owner, 'cct_work_requests', secondId), { ...candidate, scope: 'TRADE' }));
  result.rules.push('expanded scope denied');
  await assertFails(setDoc(doc(owner, 'cct_work_requests', `promote-${'f'.repeat(32)}-1`), candidate));
  result.rules.push('request identity mismatch denied');
  const guest = h.env.unauthenticatedContext().firestore();
  await assertFails(getDocFromServer(doc(guest, 'cct_work_requests', id)));
  result.rules.push('unauthenticated read denied');
  await h.seedOwnerDocument('cct_workspace', 'current', { ...data.workspace, learningEnabled: false });
  await assertFails(setDoc(doc(owner, 'cct_work_requests', secondId), candidate));
  result.rules.push('paused promotion denied');
  result.passed = true;
  await writeFile(join(report, 'promotion-browser.json'), JSON.stringify(result, null, 2));
  console.log(JSON.stringify(result));
} finally { await browser?.close(); await h.close(); }
