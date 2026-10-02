// Local Firestore emulator only: real browser storage and immutable answer rules.
import assert from 'node:assert/strict';
export async function checkDiscovery({ page, harness, ownerUid, checks }) {
  const id = 'q-' + 'd'.repeat(32);
  const answer = 'QA fixture only: preserve this exact draft through reload. <script>never run</script>';
  const state = { schemaVersion:'cct.discovery.v1',ownerUid,conversationId:'local-repair-qa',revision:1,
    updatedAt:new Date().toISOString(),executionEnabled:false,phase:'AWAITING_INPUT',reason:'',
    question:{id,text:'Local QA: what should survive a reload?'},answersConsumed:0,history:[],unknowns:[],
    learning:{wants:[],frustrations:[],constraints:[],delegation:[]},workIdeas:[] };
  await harness.seedOwnerDocument('cct_discovery','current',state);
  await page.locator('#discovery-input').waitFor({state:'visible'});
  await page.waitForFunction(()=>!document.querySelector('#discovery-submit').disabled);
  await page.locator('#discovery-input').fill(answer);
  assert.match(await page.locator('#discovery-feedback').innerText(),/survives reload/);
  await page.reload();
  await page.waitForFunction(expected=>document.querySelector('#discovery-input')?.value===expected,answer);
  await page.waitForFunction(()=>!document.querySelector('#discovery-submit').disabled);
  assert.equal(await harness.readOwnerDocument('cct_discovery_answers',id),undefined);
  checks.push('discovery draft survives actual browser reload; typing/reload never sends it');
  await page.locator('#discovery-submit').click();
  await page.waitForFunction(()=>document.querySelector('#discovery-saved-reply')?.textContent.includes('preserve this exact draft'));
  const saved = await harness.readOwnerDocument('cct_discovery_answers',id);
  assert.equal(saved.text,answer);
  assert.equal(saved.ownerUid,ownerUid);
  assert.deepEqual(Object.keys(saved).sort(),['createdAt','ownerUid','questionId','schemaVersion','text']);
  assert.equal(await page.locator('#discovery-form').isVisible(),false);
  assert.equal(await page.evaluate(({uid,id})=>localStorage.getItem(`cct.discovery-draft.v1:${encodeURIComponent(uid)}:${id}`),{uid:ownerUid,id}),null);
  await page.reload();
  await page.waitForFunction(()=>document.querySelector('#discovery-saved-reply')?.textContent.includes('preserve this exact draft'));
  assert.equal((await harness.readOwnerDocument('cct_discovery_answers',id)).createdAt.toMillis(),saved.createdAt.toMillis());
  checks.push('discovery create-only answer, exact server readback, cleared draft, reload identity and no duplicate write');
}
