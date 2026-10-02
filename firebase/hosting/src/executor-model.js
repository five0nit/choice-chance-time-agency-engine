export const CONTROL_SCHEMA = 'cct.executor_control.v1';
const fields = ['schemaVersion', 'ownerUid', 'revision', 'updatedAt', 'enabled', 'runNonce', 'task', 'maxRuns', 'intervalSeconds'];
export const TASKS = ['project-audit', 'public-docs-check'];
const integer = (n, low, high) => Number.isInteger(n) && n >= low && n <= high;
const nonce = (n) => typeof n === 'string' && /^[A-Za-z0-9_-]{16,80}$/.test(n);
const sha = (s) => typeof s === 'string' && /^[0-9a-f]{64}$/.test(s);
export const serverSnapshot = (s) => s?.metadata?.fromCache === false && s.metadata.hasPendingWrites === false;
export function controlValid(c, uid) {
  return !!c && Object.keys(c).length === fields.length && fields.every((f) => Object.hasOwn(c, f))
    && c.schemaVersion === CONTROL_SCHEMA && !!uid && c.ownerUid === uid && integer(c.revision, 1, 2147483647)
    && typeof c.enabled === 'boolean' && nonce(c.runNonce) && TASKS.includes(c.task)
    && integer(c.maxRuns, 1, 3) && integer(c.intervalSeconds, 60, 3600);
}
// Match Python stamp(..., timespec='microseconds'), not Date's millisecond rounding.
export function timestampCanonical(t) {
  if (!Number.isInteger(t?.seconds) || !integer(t?.nanoseconds, 0, 999999999)) throw new Error('TIMESTAMP_INVALID');
  return new Date(t.seconds * 1000).toISOString().slice(0, 19) + '.' + String(Math.floor(t.nanoseconds / 1000)).padStart(6, '0') + '+00:00';
}
export function canonicalControl(c) {
  return JSON.stringify(Object.fromEntries(fields.slice().sort().map((f) => [f, f === 'updatedAt' ? timestampCanonical(c[f]) : c[f]])));
}
export async function controlHash(c) {
  const bytes = await globalThis.crypto.subtle.digest('SHA-256', new TextEncoder().encode(canonicalControl(c)));
  return [...new Uint8Array(bytes)].map((b) => b.toString(16).padStart(2, '0')).join('');
}
export function verifyControl(actual, expected, uid) {
  try {
    timestampCanonical(actual?.updatedAt);
    return controlValid(actual, uid) && fields.filter((f) => f !== 'updatedAt').every((f) => actual[f] === expected[f]);
  } catch { return false; }
}
export function runtimeStatus(r, { ownerUid, projectId, now = Date.now(), fromCache = false, pending = false, offline = false } = {}) {
  const blocked = (reason) => ({ ready: false, valid: false, reason, state: 'UNAVAILABLE' });
  if (!r) return blocked('No host receipt. ON is blocked.');
  if (!ownerUid || !projectId || r.schemaVersion !== 'cct.executor_runtime.v1' || r.ownerUid !== ownerUid || r.projectId !== projectId || r.scope !== 'BOUNDED_TEST_EXECUTOR') return blocked('Host identity or executor scope mismatch.');
  const states = ['OFF', 'READY', 'RUNNING', 'COMPLETED', 'STOPPED', 'BLOCKED', 'INVALID', 'UNAVAILABLE'];
  if (!states.includes(r.state) || typeof r.updatedAt !== 'string' || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|\+00:00)$/.test(r.updatedAt)) return blocked('Invalid host receipt.');
  const time = Date.parse(r.updatedAt);
  if (!Number.isFinite(time) || now < time || now - time > 180000 || fromCache || pending || offline) return blocked('Host receipt stale, cached or disconnected. ON is blocked; Stop remains available.');
  // Readiness means a fresh scoped host observation, not a grant or completed work.
  // The actual v1 runtime has no hostEnabled field; execution rechecks the host grant.
  const ready = r.hostEnabled !== false && !['BLOCKED', 'INVALID', 'UNAVAILABLE'].includes(r.state);
  return { valid: true, ready, state: r.state, reason: ready ? 'Fresh exact-owner executor receipt. Host policy still gates every run.' : 'Host readiness not attested. ON is blocked; Stop remains available.' };
}
export function runtimeAcknowledged(r, c, digest, context) {
  return runtimeStatus(r, context).valid && controlValid(c, context.ownerUid) && sha(digest)
    && r.revision === c.revision && r.runNonce === c.runNonce && r.controlSha256 === digest;
}
export function buildControl(previous, { ownerUid, action, task, maxRuns, intervalSeconds, runNonce, updatedAt }) {
  if (!ownerUid || !['once', 'start', 'stop'].includes(action)) throw new Error('CONTROL_INVALID');
  if (previous && !controlValid(previous, ownerUid)) throw new Error('CONTROL_INVALID');
  if (previous?.revision === 2147483647) throw new Error('REVISION_EXHAUSTED');
  if (action === 'stop' && previous) return { ...previous, enabled: false, revision: previous.revision + 1, updatedAt };
  if (action !== 'stop' && !previous) throw new Error('BOOTSTRAP_OFF_REQUIRED');
  if (!TASKS.includes(task) || !integer(maxRuns, 1, 3) || !integer(intervalSeconds, 60, 3600) || !nonce(runNonce) || (action !== 'stop' && runNonce === previous?.runNonce)) throw new Error('CONTROL_INVALID');
  return { schemaVersion: CONTROL_SCHEMA, ownerUid, revision: (previous?.revision || 0) + 1, updatedAt,
    enabled: action !== 'stop', runNonce, task, maxRuns: action === 'once' ? 1 : maxRuns, intervalSeconds };
}
export function validRun(r, uid, id) {
  return !!r && r.schemaVersion === 'cct.executor_run.v1' && r.ownerUid === uid && r.runId === id && /^run-[0-9a-f]{32}$/.test(id)
    && nonce(r.runNonce) && integer(r.revision, 1, 2147483647) && TASKS.includes(r.task)
    && ['RUNNING', 'COMPLETED', 'STOPPED', 'BLOCKED', 'UNKNOWN'].includes(r.state)
    && typeof r.reportText === 'string' && r.reportText.length <= 12000 && typeof r.reasonCode === 'string' && r.reasonCode.length <= 160
    && typeof r.startedAt === 'string' && Number.isFinite(Date.parse(r.startedAt))
    && (r.artifactSha256 === null || sha(r.artifactSha256));
}
