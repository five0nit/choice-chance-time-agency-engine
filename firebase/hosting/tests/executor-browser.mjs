// Emulator-only UI test. Host receipts below are labeled fixtures, not live execution.
import assert from 'node:assert/strict';
import { controlHash } from '../src/executor-model.js';

export async function checkExecutor({ page, harness, ownerUid, checks }) {
  const saved = async (enabled, revision) => page.waitForFunction(
    ({ enabled, revision }) => document.querySelector('#executor-save')?.textContent.includes(`Saved ${enabled ? 'ON' : 'OFF'} revision ${revision}`), { enabled, revision });
  const seedRuntime = async (control, overrides = {}) => {
    const runtime = { schemaVersion: 'cct.executor_runtime.v1', scope: 'BOUNDED_TEST_EXECUTOR', ownerUid,
      projectId: 'demo-cctae-browser', updatedAt: new Date().toISOString(), state: 'OFF', reasonCode: 'EMULATOR_FIXTURE',
      revision: control.revision, runNonce: control.runNonce, controlSha256: await controlHash(control),
      completedRuns: 0, maxRuns: control.maxRuns, task: control.task, lastRunId: null, nextRunAt: null, ...overrides };
    await harness.seedOwnerDocument('cct_executor_runtime', 'current', runtime);
    return runtime;
  };
  const control = () => harness.readOwnerDocument('cct_executor_control', 'current');
  assert.equal(await page.locator('#executor-once').isDisabled(), true);
  assert.equal(await page.locator('#executor-stop').isEnabled(), true);
  await page.locator('#executor-stop').click(); await saved(false, 1);
  let c = await control(); assert.equal(c.enabled, false);
  await seedRuntime(c);
  await page.waitForFunction(() => !document.querySelector('#executor-once').disabled);
  await page.waitForFunction(() => document.querySelector('#executor-ack').textContent.includes('matches revision 1'));
  await page.locator('#executor-once').click(); await saved(true, 2);
  c = await control(); assert.equal(c.enabled, true); assert.equal(c.maxRuns, 1);
  assert.match(await page.locator('#executor-ack').innerText(), /pending or unavailable/);
  await seedRuntime(c, { state: 'RUNNING', controlSha256: '0'.repeat(64) });
  await page.waitForFunction(() => document.querySelector('#executor-host').textContent.startsWith('RUNNING'));
  assert.match(await page.locator('#executor-ack').innerText(), /pending or unavailable/);
  const runId = `run-${'b'.repeat(32)}`;
  await harness.seedOwnerDocument('cct_executor_runs', runId, {
    schemaVersion: 'cct.executor_run.v1', ownerUid, runId, runNonce: c.runNonce, revision: c.revision,
    task: c.task, state: 'COMPLETED', reasonCode: 'EMULATOR_FIXTURE_ONLY', startedAt: new Date().toISOString(),
    finishedAt: new Date().toISOString(), artifactSha256: 'a'.repeat(64),
    reportText: 'EMULATOR FIXTURE ONLY <script>window.executorInjected=true</script>' });
  await seedRuntime(c, { state: 'COMPLETED', completedRuns: 1, lastRunId: runId });
  await page.waitForFunction(() => document.querySelector('#executor-ack').textContent.includes('matches revision 2'));
  await page.locator('#executor-runs details summary').click();
  assert.match(await page.locator('#executor-runs pre').innerText(), /EMULATOR FIXTURE ONLY <script>/);
  assert.equal(await page.evaluate(() => window.executorInjected), undefined);
  await seedRuntime(c, { state: 'RUNNING', updatedAt: new Date(Date.now() - 240000).toISOString() });
  await page.waitForFunction(() => document.querySelector('#executor-once').disabled);
  assert.equal(await page.locator('#executor-stop').isEnabled(), true);
  await page.locator('#executor-stop').click(); await saved(false, 3);
  const stopped = await control(); assert.equal(stopped.enabled, false); assert.equal(stopped.runNonce, c.runNonce);
  assert.match(await page.locator('#executor-ack').innerText(), /pending or unavailable/);
  await seedRuntime(stopped);
  await page.waitForFunction(() => !document.querySelector('#executor-start').disabled);
  await page.locator('#executor-max-runs').fill('3');
  await page.locator('#executor-start').click(); await saved(true, 4);
  c = await control(); assert.equal(c.maxRuns, 3); assert.notEqual(c.runNonce, stopped.runNonce);
  await page.locator('#executor-stop').click(); await saved(false, 5);
  await seedRuntime(await control());
  await page.reload();
  await page.locator('#owner-settings-button').click();
  await page.locator('#runtime-diagnostics > summary').click();
  await page.waitForFunction(() => document.querySelector('#executor-ack')?.textContent.includes('matches revision 5'));
  assert.match(await page.locator('#executor-control').innerText(), /OFF request/);
  checks.push('executor real emulator browser controls: OFF bootstrap, run once, bounded Start, stale/wrong-hash ACK rejection, stale-host Stop, exact readback, literal fixture report and reload persistence');
}
