import { collection, doc, getDocFromServer, getDocsFromServer, limit, onSnapshot, orderBy, query, runTransaction, serverTimestamp } from 'firebase/firestore';
import { buildControl, controlHash, runtimeStatus, serverSnapshot, validRun, verifyControl } from './executor-model.js';
const firestore = { collection, doc, getDocFromServer, getDocsFromServer, limit, onSnapshot, orderBy, query, runTransaction, serverTimestamp };
export function createExecutorStore(db, ownerUid, projectId, onChange, api = firestore) {
  // This location is deliberately pinned to the deployed rules/host contract.
  const ref = api.doc(db, 'cct_executor_control', 'current');
  const runtimeRef = api.doc(db, 'cct_executor_runtime', 'current');
  const runsQuery = api.query(api.collection(db, 'cct_executor_runs'), api.orderBy('startedAt', 'desc'), api.limit(20));
  const state = { control: null, controlVerified: false, digest: null, runtime: null, runtimeFromCache: true,
    runs: [], runsVerified: false, busy: false, message: 'Read-only until server state arrives.', error: false };
  let closed = !ownerUid; let started = false; let controlGeneration = 0;
  const unsubscribes = [];
  const emit = () => { if (!closed) onChange({ ...state }); };
  const consumeControl = async (s) => {
    if (closed) return;
    const generation = ++controlGeneration;
    state.controlVerified = false; state.digest = null; state.control = s.exists() ? s.data() : null; emit();
    if (!serverSnapshot(s) || !s.exists() || !verifyControl(s.data(), s.data(), ownerUid)) return;
    try {
      const digest = await controlHash(s.data());
      if (closed || generation !== controlGeneration) return;
      state.controlVerified = true; state.digest = digest; emit();
    } catch { /* No canonical hash means no acknowledgement proof. */ }
  };
  const consumeRuntime = (s) => {
    if (closed) return;
    state.runtime = s.exists() ? s.data() : null; state.runtimeFromCache = !serverSnapshot(s); emit();
  };
  const consumeRuns = (s) => {
    if (closed) return;
    state.runs = s.docs.filter((d) => validRun(d.data(), ownerUid, d.id)).map((d) => d.data());
    state.runsVerified = serverSnapshot(s); emit();
  };
  const fail = (kind) => {
    if (closed) return;
    if (kind === 'runtime') { state.runtime = null; state.runtimeFromCache = true; }
    if (kind === 'control') { ++controlGeneration; state.controlVerified = false; state.digest = null; }
    if (kind === 'runs') state.runsVerified = false;
    state.error = true; state.message = `${kind} unavailable. No cached state counts as verified.`; emit();
  };
  return {
    start() {
      if (closed || started) return; started = true;
      for (const [target, consume, kind] of [[ref, consumeControl, 'control'], [runtimeRef, consumeRuntime, 'runtime'], [runsQuery, consumeRuns, 'runs']]) {
        unsubscribes.push(api.onSnapshot(target, { includeMetadataChanges: true }, consume, () => fail(kind)));
      }
    },
    stop() { closed = true; ++controlGeneration; unsubscribes.forEach((u) => u()); state.control = null; state.runtime = null; state.runs = []; },
    async refresh() {
      if (closed) return;
      await Promise.all([
        api.getDocFromServer(ref).then(consumeControl, () => fail('control')),
        api.getDocFromServer(runtimeRef).then(consumeRuntime, () => fail('runtime')),
        api.getDocsFromServer(runsQuery).then(consumeRuns, () => fail('runs')),
      ]);
    },
    async save(action, settings = {}) {
      if (closed || state.busy) return false;
      ++controlGeneration;
      state.busy = true; state.error = false; state.controlVerified = false; state.message = 'Saving control; awaiting exact server readback…'; emit();
      let written = false;
      try {
        const runNonce = globalThis.crypto.randomUUID().replaceAll('-', '');
        const expected = await api.runTransaction(db, async (tx) => {
          if (closed) throw new Error('SIGNED_OUT');
          const previousSnapshot = await tx.get(ref);
          if (closed || !serverSnapshot(previousSnapshot)) throw new Error('SERVER_REQUIRED');
          const previous = previousSnapshot.exists() ? previousSnapshot.data() : null;
          // OFF never reads or depends on runtime availability.
          if (action !== 'stop') {
            const host = await tx.get(runtimeRef);
            if (closed || !serverSnapshot(host) || !runtimeStatus(host.exists() ? host.data() : null, { ownerUid, projectId }).ready) throw new Error('HOST_NOT_READY');
          }
          const payload = buildControl(previous, { ownerUid, action, task: settings.task || 'project-audit', maxRuns: settings.maxRuns ?? 3,
            intervalSeconds: settings.intervalSeconds ?? 300, runNonce, updatedAt: api.serverTimestamp() });
          if (closed) throw new Error('SIGNED_OUT');
          tx.set(ref, payload); return payload;
        });
        written = true;
        if (closed) return false;
        const readback = await api.getDocFromServer(ref);
        if (closed) return false;
        if (!serverSnapshot(readback) || !readback.exists() || !verifyControl(readback.data(), expected, ownerUid)) throw new Error('READBACK_UNVERIFIED');
        await consumeControl(readback);
        if (closed) return false;
        state.message = `Saved ${expected.enabled ? 'ON' : 'OFF'} revision ${expected.revision} · exact server values verified. Host acknowledgement is separate.`;
        return true;
      } catch (error) {
        if (closed) return false;
        ++controlGeneration;
        state.controlVerified = false; state.digest = null; state.error = true;
        state.message = written ? 'Write may have reached the server, but exact readback is unverified. Refresh before retrying.'
          : error.message === 'BOOTSTRAP_OFF_REQUIRED' ? 'Initialize safely with Stop first; initial control must be OFF.'
          : error.message === 'HOST_NOT_READY' ? 'ON blocked: fresh exact-owner host readiness is required. Stop still works.'
          : 'Control not verified. Check owner access, bounds and connection; Stop does not require a live host.';
        return false;
      } finally { if (!closed) { state.busy = false; emit(); } }
    },
  };
}
