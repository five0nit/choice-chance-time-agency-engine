import './executor.css';
import { createExecutorStore } from './executor-store.js';
import { runtimeAcknowledged, runtimeStatus } from './executor-model.js';
export function mountExecutor(db, ownerUid, projectId) {
  const byId = (id) => document.getElementById(id);
  let stopped = false; let view = {};
  const context = () => ({ ownerUid, projectId, fromCache: view.runtimeFromCache !== false, offline: navigator.onLine === false });
  function render() {
    if (stopped) return;
    const host = runtimeStatus(view.runtime, context());
    byId('executor-host').textContent = `${host.state} · ${host.reason}`;
    byId('executor-save').textContent = view.message || 'Waiting for server state.';
    byId('executor-save').dataset.state = view.error ? 'error' : 'ok';
    const c = view.control;
    byId('executor-control').textContent = c ? `${view.controlVerified ? 'Server verified' : 'Unverified'} control · ${c.enabled === true ? 'ON request' : 'OFF request'} · revision ${c.revision} · ${c.task} · max ${c.maxRuns} runs / ${c.intervalSeconds}s` : 'No control yet. Use Stop to initialize OFF.';
    const ack = view.controlVerified && runtimeAcknowledged(view.runtime, c, view.digest, context());
    byId('executor-ack').textContent = ack ? `Host acknowledgement matches revision ${c.revision}, nonce and canonical SHA-256. State: ${host.state}.` : 'Host acknowledgement pending or unavailable. Saved control is not proof of execution.';
    byId('executor-once').disabled = !!view.busy || !host.ready || !view.controlVerified;
    byId('executor-start').disabled = !!view.busy || !host.ready || !view.controlVerified;
    byId('executor-stop').disabled = !!view.busy;
    byId('executor-runs-source').textContent = view.runsVerified ? 'Server run receipts · newest 20 maximum' : 'Run receipts unverified / cached; not completion proof';
    const runs = byId('executor-runs'); runs.replaceChildren();
    if (!view.runs?.length) { const p = document.createElement('p'); p.textContent = 'No valid run receipts received. No report has been invented.'; runs.append(p); }
    for (const run of view.runs || []) {
      const card = document.createElement('details');
      const summary = document.createElement('summary'); summary.textContent = `${run.task} · ${run.state} · ${run.startedAt}`;
      const meta = document.createElement('p'); meta.textContent = `${run.runId} · revision ${run.revision} · ${run.reasonCode} · finished ${run.finishedAt || 'not recorded'}`;
      const hash = document.createElement('p'); hash.textContent = `Artifact SHA-256: ${run.artifactSha256 || 'not recorded'}`;
      const report = document.createElement('pre'); report.textContent = run.reportText || 'No completed report in this receipt.';
      card.append(summary, meta, hash, report); runs.append(card);
    }
  }
  const store = createExecutorStore(db, ownerUid, projectId, (next) => { view = next; render(); });
  const listeners = [];
  for (const [id, action] of [['executor-once', 'once'], ['executor-start', 'start'], ['executor-stop', 'stop']]) {
    const element = byId(id);
    const handler = () => {
      if (stopped) return;
      void store.save(action, { task: byId('executor-task').value, maxRuns: Number(byId('executor-max-runs').value), intervalSeconds: Number(byId('executor-interval').value) });
    };
    element.addEventListener('click', handler); listeners.push(() => element.removeEventListener('click', handler));
  }
  const timer = window.setInterval(render, 10000);
  window.addEventListener('offline', render); window.addEventListener('online', render);
  store.start(); render();
  return { refresh: () => store.refresh(), stop() {
    stopped = true; store.stop(); window.clearInterval(timer); listeners.forEach((off) => off());
    window.removeEventListener('offline', render); window.removeEventListener('online', render);
    byId('executor-runs').replaceChildren();
    for (const id of ['executor-once', 'executor-start', 'executor-stop']) byId(id).disabled = true;
    for (const id of ['executor-control', 'executor-ack', 'executor-host', 'executor-save', 'executor-runs-source']) byId(id).textContent = 'Signed out.';
  } };
}
