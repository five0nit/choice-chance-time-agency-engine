// Production controller + real local Firestore emulator. No live identities/effects.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
export async function checkBuilds({page,harness,ownerUid,checks,output}) {
  let w=await harness.workspace();
  w={...w,revision:w.revision+1,updatedAt:new Date(),autonomyMode:'full',autonomyAcknowledged:true,
    learningEnabled:true,permissions:{...w.permissions,workspaceRead:true,workspaceWrite:true}};
  await harness.seedOwnerDocument('cct_workspace','current',w);
  await harness.seedOwnerDocument('cct_owner_runtime','current',{schemaVersion:'cct.owner_runtime.v1',ownerUid,
    projectId:'demo-cctae-browser',scope:'OWNER_MESSAGES_ONLY',state:'CONNECTED',revision:w.revision,
    updatedAt:new Date().toISOString(),policySha256:'a'.repeat(64),workspaceSha256:'b'.repeat(64),
    effectivePolicy:{ownerMessages:true,autonomyMode:'supervised'},unsupportedPermissions:[],reasonCode:'OWNER_SCOPE_APPLIED'});
  const root=page.locator('#owner-builds');
  await page.locator('a[href="#owner-builds"]').click();
  assert.equal(await root.getByRole('button',{name:'Preview budget change',exact:true}).isDisabled(),true);
  const host={schemaVersion:'cct.owner_build_controls_status.v1',ownerUid,requestedRevision:0,effectiveRevision:0,
    state:'DEFAULTS',reason:'Fixture host defaults; not live.',updatedAt:new Date().toISOString(),
    effective:{maxDailyJobs:1,maxDailyProviderCalls:12,maxDailyToolCalls:4},
    ceilings:{maxDailyJobs:4,maxDailyProviderCalls:20,maxDailyToolCalls:12},usage:{jobs:1,providerCalls:4,toolCalls:0}};
  const content='<script>window.buildArtifactExecuted=true</script>\nPrivate fixture source. Never execute.';
  const b={schemaVersion:'cct.owner_build.v1',ownerUid,buildId:'delivery-browser-fixture',parentBuildId:'',rootBuildId:'delivery-browser-fixture',
    action:'build',title:'Fixture fee worksheet',summary:'Private fixture, not factual trading advice.',status:'COMPLETE',reason:'Fixture verification receipt.',
    createdAt:new Date().toISOString(),updatedAt:new Date().toISOString(),bundleDigest:'a'.repeat(64),archived:false,
    verification:{status:'passed',independentBehavior:true,generatedTestsVerified:false,scope:'Fixture cases only.'},usage:{providerCalls:3,toolCalls:0},
    files:[{path:'README.md',content,sha256:createHash('sha256').update(content).digest('hex')}]};
  await harness.seedOwnerDocument('cct_owner_build_controls_status','current',host);
  await harness.seedOwnerDocument('cct_owner_builds',b.buildId,b);
  // Exercise persisted startup after fixture seeding, not concurrent emulator
  // listener bootstrap (which can lose a newly-created document's first event).
  await page.reload();
  await page.waitForFunction(()=>!document.querySelector('#owner-builds button[type="submit"]').disabled);
  await root.locator('.builds-card').click();
  await root.locator('summary').filter({hasText:'README.md'}).click();
  assert.match(await root.locator('.builds-inspector').innerText(),/window.buildArtifactExecuted/);
  assert.equal(await page.evaluate(()=>window.buildArtifactExecuted),undefined);
  const downloadPromise=page.waitForEvent('download');
  await root.getByRole('button',{name:'Download as text',exact:true}).click();
  const download=await downloadPromise; assert.equal(download.suggestedFilename(),'README.md.txt');
  checks.push('Builds: exact private file viewed literally and downloaded as text; no artifact execution');
  await root.locator('input[name="maxDailyJobs"]').fill('2');
  await root.locator('input[name="maxDailyProviderCalls"]').fill('14');
  await root.locator('input[name="maxDailyToolCalls"]').fill('5');
  await root.getByRole('button',{name:'Preview budget change',exact:true}).click();
  assert.match(await root.locator('dialog pre').innerText(),/"maxDailyProviderCalls": 14/);
  await root.getByRole('button',{name:'Confirm and save',exact:true}).click();
  await page.waitForFunction(()=>document.querySelector('#owner-builds .builds-feedback').textContent.includes('Budget intent revision 1 server-verified'));
  const intent=await harness.readOwnerDocument('cct_owner_build_controls','current');
  assert.equal(intent.maxDailyJobs,2); assert.equal(intent.maxDailyProviderCalls,14); assert.equal(intent.revision,1);
  assert.equal((await harness.readOwnerDocument('cct_owner_build_controls_status','current')).effectiveRevision,0);
  assert.equal(await root.getByRole('button',{name:'Preview steer',exact:true}).isDisabled(),true);
  await harness.seedOwnerDocument('cct_owner_build_controls_status','current',{...host,requestedRevision:1,effectiveRevision:1,state:'APPLIED',
    effective:{maxDailyJobs:2,maxDailyProviderCalls:14,maxDailyToolCalls:5},updatedAt:new Date().toISOString()});
  await page.waitForFunction(()=>!Array.from(document.querySelectorAll('#owner-builds button')).find(e=>e.textContent==='Preview steer')?.disabled);
  await root.locator('.builds-inspector textarea').fill('Add an explicit fee input and preserve original.');
  await root.getByRole('button',{name:'Preview steer',exact:true}).click();
  const payload=JSON.parse(await root.locator('dialog pre').innerText());
  assert.equal(payload.parentBuildId,b.buildId); assert.equal(payload.parentDigest,b.bundleDigest); assert.equal(payload.controlRevision,1);
  await root.getByRole('button',{name:'Confirm and save',exact:true}).click();
  await page.waitForFunction(()=>document.querySelector('#owner-builds .builds-feedback').textContent.includes('Submission is not acceptance'));
  const saved=await harness.readOwnerDocument('cct_owner_build_requests',payload.requestId);
  assert.equal(saved.instructions,payload.instructions); assert.equal(saved.parentDigest,payload.parentDigest);
  assert.equal(saved.maxProviderCalls,payload.maxProviderCalls);
  await harness.seedOwnerDocument('cct_owner_build_request_status',payload.requestId,{schemaVersion:'cct.owner_build_request_status.v1',ownerUid,
    requestId:payload.requestId,parentBuildId:b.buildId,action:'steer',state:'WAITING_BUDGET',reason:'Fixture rolling budget reached.',buildId:'',updatedAt:new Date().toISOString()});
  await page.waitForFunction(()=>document.querySelector('#owner-builds .builds-requests').textContent.includes('WAITING_BUDGET'));
  checks.push('Builds: real transactional budget intent/host acknowledgement and immutable digest-bound steering request/readback');
  await root.getByRole('searchbox').fill('not a match'); assert.equal(await root.locator('.builds-card').count(),0);
  await root.getByRole('searchbox').fill('fee'); assert.equal(await root.locator('.builds-card').count(),1);
  for(const width of [1440,390,320]) {
    await page.setViewportSize({width,height:width===1440?1000:844});
    await root.scrollIntoViewIfNeeded();
    if (!await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth)) console.error(await page.evaluate(()=>Array.from(document.querySelectorAll('body *')).filter(e=>e.getBoundingClientRect().right>innerWidth+1).map(e=>({tag:e.tagName,id:e.id,class:e.className,right:e.getBoundingClientRect().right,text:e.textContent.slice(0,55)})).slice(0,18)));
    assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),true,`Builds overflow ${width}`);
    await page.screenshot({path:output+`builds-${width}.png`,fullPage:false});
  }
  checks.push('Builds: functional search, desktop/390/320 layout without overflow');
  await harness.seedOwnerDocument('cct_owner_build_controls_status','current',{...host,updatedAt:new Date(Date.now()-240000).toISOString()});
  await page.waitForFunction(()=>document.querySelector('#owner-builds button[type="submit"]').disabled);
  checks.push('Builds: stale host readback disables further budget/action writes');
}
