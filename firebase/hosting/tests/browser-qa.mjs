// Local emulator only. Simulated owner identity; never loads production credentials.
import assert from 'node:assert/strict';
import { readFile, writeFile, mkdir, mkdtemp } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
const { chromium } = await import(process.env.PLAYWRIGHT_MODULE || 'playwright');
import { startHarness } from './browser-harness.mjs';
const output = (process.env.CCT_QA_OUTPUT || await mkdtemp(join(tmpdir(), 'cct-browser-receipt-'))) + '/';
await mkdir(output, {recursive:true});
const harness = await startHarness();
const browser = await chromium.launch({headless:true,...(process.env.CCT_CHROMIUM_PATH ? {executablePath:process.env.CCT_CHROMIUM_PATH} : {})});
const context = await browser.newContext({viewport:{width:1440,height:1000},reducedMotion:'reduce'});
const page = await context.newPage();
const errors = [], checks = [];
page.on('pageerror', error => errors.push(error.message));
const ready = async (target=page) => {
  await target.waitForFunction(() => {
    const element = document.querySelector('[data-focus="permission-credentialAccess"]');
    return element && !element.disabled;
  });
  // Legacy controls live inside collapsed settings; exercise the actual opener.
  if (!(await target.locator('#context-settings').evaluate(el => el.open))) {
    await target.locator('#owner-settings-button').click();
  }
};
const saved = async () => {
  await page.waitForFunction(() => document.querySelector('#workspace-save-status')?.textContent.includes('server verified'));
  await ready();
};
const screenshot = async name => { await page.evaluate(() => {window.scrollTo(0,0); document.activeElement?.blur();}); await page.screenshot({path:output+name,fullPage:true}); };
try {
  const snapshot=JSON.parse(await readFile(new URL('./fixtures/dashboard-snapshot.json', import.meta.url),'utf8'));
  snapshot.generated_at=new Date().toISOString();
  await harness.seedSnapshot(snapshot);
  await page.goto(harness.url);
  await ready();
  await page.waitForFunction(() => document.querySelector('#workspace-goals')?.textContent.includes('QA fixture: review one workflow'));
  assert.equal(await page.locator('#decision-cards article').count(),3);
  assert.match(await page.locator('#workspace-goals').innerText(),/QA fixture: review one workflow/);
  assert.equal(await page.locator('#workspace-permissions input:checked').count(),0);
  assert.equal(await page.locator('#autonomy-switch').isChecked(),false);
  assert.equal(await page.locator('#policy-effective').innerText(),'No effective owner messaging');
  checks.push('initial private workspace, real snapshot labels, default permissions off');
  await screenshot('desktop-initial.png');
  const questionBefore=await page.locator('#active-question h3').innerText();
  await page.locator('[data-focus="question-focus-systems"]').click();
  await saved();
  assert.notEqual(await page.locator('#active-question h3').innerText(),questionBefore);
  assert.match(await page.locator('#active-question h3').innerText(),/kind of next step/);
  await page.locator('[data-focus="question-nextStep-repair"]').click();
  await saved();
  assert.match(await page.locator('#ranked-ideas article').first().innerText(),/Repair one thing/);
  assert.equal((await harness.workspace()).answers.nextStep,'repair');
  checks.push('adaptive follow-up and preference ranking persisted with server readback');
  await page.locator('[data-focus="seed-system-repair-later"]').click(); await saved();
  assert.equal((await harness.workspace()).decisions['seed-system-repair'],'later');
  await page.locator('#decision-toggle').click();
  assert.match(await page.locator('#decision-cards').innerText(),/Recorded: later/);
  await page.locator('#decision-toggle').click();
  checks.push('decision feedback persisted and editable in the full board');
  await page.locator('[data-focus="permission-credentialAccess"]').check();
  await saved();
  assert.equal((await harness.workspace()).permissions.credentialAccess,true);
  assert.equal((await harness.workspace()).permissions.payments,false);
  checks.push('credential permission intent isolated from spending');
  await page.locator('#autonomy-switch').click();
  assert.equal(await page.locator('#confirm-autonomy').isDisabled(),true);
  await page.locator('#cancel-autonomy').click();
  assert.equal((await harness.workspace()).autonomyMode,'supervised');
  await page.locator('#autonomy-switch').click();
  await page.locator('#autonomy-acknowledge').check();
  await page.locator('#confirm-autonomy').click();
  await saved();
  let workspace=await harness.workspace();
  assert.equal(workspace.autonomyMode,'full');
  assert.equal(workspace.autonomyAcknowledged,true);
  assert.equal(Object.values(workspace.permissions).filter(Boolean).length,1);
  assert.equal(await page.locator('#policy-effective').innerText(),'No effective owner messaging');
  checks.push('autonomy cancel, acknowledgement gate, persistence, no permission expansion');
  await page.locator('#autonomy-switch').click();
  await saved();
  await page.reload(); await ready();
  assert.equal(await page.locator('[data-focus="permission-credentialAccess"]').isChecked(),true);
  assert.equal(await page.locator('#autonomy-switch').isChecked(),false);
  assert.equal(await page.locator('#focus-value').innerText(),'Systems');
  checks.push('reload persistence and switch back to supervised');
  const other=await context.newPage(); await other.goto(harness.url); await ready(other);
  await page.locator('[data-focus="permission-webResearch"]').check(); await saved();
  await other.waitForFunction(()=>document.querySelector('[data-focus="permission-webResearch"]')?.checked);
  await other.close(); checks.push('second-tab live synchronization');
  await page.locator('summary').filter({hasText:'Inspect & edit what CCT has learned'}).click();
  await page.locator('#learning-enabled').click(); await saved();
  assert.match(await page.locator('#learning-state').innerText(),/paused/);
  await page.locator('#learning-enabled').click(); await saved();
  page.once('dialog', dialog=>dialog.accept());
  await page.locator('#reset-learning').click(); await saved();
  workspace=await harness.workspace();
  assert.equal(Object.values(workspace.answers).every(value=>value===''),true);
  assert.equal(workspace.permissions.credentialAccess,true);
  assert.equal(workspace.permissions.webResearch,true);
  assert.equal(workspace.decisions['seed-system-repair'],'later');
  checks.push('learning pause/resume and answer reset preserve permissions');
  await page.locator('[data-focus="permission-externalMessages"]').check(); await saved();
  workspace = await harness.workspace();
  const ownerUid = workspace.ownerUid;
  const runtime = {schemaVersion:'cct.owner_runtime.v1', ownerUid, projectId:'demo-cctae-browser',
    scope:'OWNER_MESSAGES_ONLY', state:'CONNECTED', revision:workspace.revision, updatedAt:new Date().toISOString(),
    policySha256:'a'.repeat(64), workspaceSha256:'b'.repeat(64),
    effectivePolicy:{ownerMessages:true,autonomyMode:'supervised'}, unsupportedPermissions:['payments'], reasonCode:'OWNER_SCOPE_APPLIED'};
  const message = {schemaVersion:'cct.owner_message.v1', ownerUid, messageId:'msg-'+'1'.repeat(32), kind:'ask',
    text:'QA fixture: which workflow next? <script>window.injected=true</script>', state:'SENT',
    createdAt:new Date().toISOString(), expiresAt:new Date(Date.now()+3600000).toISOString(),
    replyDeadline:new Date(Date.now()+3600000), revision:runtime.revision, policySha256:runtime.policySha256,
    telegramMessageId:'42', answer:null};
  await harness.seedOwnerDocument('cct_owner_runtime','current',runtime);
  await harness.seedOwnerDocument('cct_owner_messages',message.messageId,message);
  await page.waitForFunction(()=>document.querySelector('#policy-effective')?.textContent==='Effective: private owner messages only');
  await page.locator('#owner-conversation > summary').click();
  await page.locator('#reply-'+message.messageId).fill('Review the workflow. This is answer data, not permission.');
  await page.locator('.owner-reply-form button').click();
  await page.waitForFunction(()=>document.querySelector('.owner-reply-feedback')?.textContent.includes('exact server readback verified'));
  const reply = await harness.readOwnerDocument('cct_owner_replies',message.messageId);
  assert.equal(reply.text,'Review the workflow. This is answer data, not permission.');
  assert.equal(reply.ownerUid,ownerUid);
  assert.equal(await page.evaluate(()=>window.injected),undefined);
  assert.deepEqual((await harness.workspace()).permissions,workspace.permissions);
  assert.equal(await page.locator('.owner-reply-form').isVisible(),false);
  checks.push('owner connection, literal message text, authenticated create-only answer and exact readback; no permission mutation');
  await harness.seedOwnerDocument('cct_owner_runtime','current',{...runtime,effectivePolicy:{ownerMessages:false,autonomyMode:'supervised'},reasonCode:'OWNER_TELEGRAM_UNAVAILABLE'});
  await page.waitForFunction(()=>document.querySelector('#workspace-runtime-detail')?.textContent.includes('Telegram delivery is unavailable'));
  assert.equal(await page.locator('#policy-effective').innerText(),'Connected · owner messages disabled');
  checks.push('Telegram outage preserves connection but never claims effective messaging');
  await harness.seedOwnerDocument('cct_owner_runtime','current',runtime);
  const { checkExecutor } = await import('./executor-browser.mjs');
  await page.locator('#runtime-diagnostics > summary').click();
  await checkExecutor({page,harness,ownerUid,checks});
  const { checkDiscovery } = await import('./discovery-browser.mjs');
  await checkDiscovery({page,harness,ownerUid,checks});
  for(const viewport of [{width:1440,height:1000},{width:390,height:844},{width:320,height:740}]) {
    await page.setViewportSize(viewport);
    assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),true,`overflow at ${viewport.width}`);
    await screenshot(`dashboard-${viewport.width}.png`);
  }
  checks.push('desktop 1440 and phones 390/320 no horizontal overflow');
  await context.setOffline(true);
  await page.waitForFunction(()=>document.querySelector('#workspace-save-status')?.textContent.includes('Offline'));
  assert.equal(await page.locator('[data-focus="permission-credentialAccess"]').isDisabled(),true);
  await context.setOffline(false); await ready();
  checks.push('offline controls disabled and online recovery');
  await page.locator('#sign-out').click();
  assert.equal(await page.locator('#decision-cards article').count(),0);
  assert.equal(await page.locator('#app').isVisible(),false);
  checks.push('sign-out clears private board');
  assert.deepEqual(errors,[]);
  const result={status:'PASS',identity:'simulated Google owner; real local Firestore rules',productionWrites:0,checks,pageErrors:errors};
  await writeFile(output+'browser-qa.json',JSON.stringify(result,null,2));
  console.log(JSON.stringify(result,null,2));
} catch(error) {
  await page.screenshot({path:output+'browser-failure.png',fullPage:true}).catch(()=>{});
  console.error({checks,errors,body:(await page.locator('body').innerText()).slice(0,7000)});
  throw error;
} finally { await context.close(); await browser.close(); await harness.close(); }
