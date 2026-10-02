import { deliveryReadback, validOwnerDelivery } from './owner-delivery-model.js';

export const CONTINUATION_SCHEMA = 'cct.owner_continuation.v1';
export const BUILD_SCHEMA = 'cct.owner_build.v1';
export const CONTROLS_SCHEMA = 'cct.owner_build_controls.v1';
export const STATUS_SCHEMA = 'cct.owner_build_controls_status.v1';
export const REQUEST_SCHEMA = 'cct.owner_build_request.v1';
export const RECEIPT_SCHEMA = 'cct.owner_build_request_status.v1';
export const PAGE_SIZE = 100;
export const FRESHNESS_MS = 180_000;
export const CEILINGS = Object.freeze({ maxDailyJobs: 4, maxDailyProviderCalls: 20, maxDailyToolCalls: 12 });
export const ACTIONS = Object.freeze(['upgrade', 'steer', 'discover', 'archive', 'restore']);
export const TOOL_LABEL = 'Bounded sandbox verification dispatches';
export const DISCOVERY_LABEL = 'Manual Discover: a saved-evidence brief; no fresh web research';
export const CONTINUATION_RESEARCH_LABEL = 'Automatic continuation can fetch fresh public evidence from the fixed catalog. Manual Discover only creates a brief from saved evidence; it does not fetch new sources.';
const continuationLabels = Object.freeze({
  DISABLED: 'Automatic continuation is off',
  IDLE: 'Waiting for a useful next step',
  READY: 'Ready to consider the next step',
  PLANNING: 'Considering the next objective',
  DECIDING: 'Choosing an objective from the gathered evidence',
  REVIEWING: 'Checking whether the next step adds value',
  QUEUED: 'Next build queued · not yet executed',
  LEARNED: 'Build outcome recorded',
  WAIT: 'Waiting before continuing',
  DAILY_CAP: 'Waiting for budget',
  COOLDOWN: 'Waiting before the next eligible attempt',
  BLOCKED: 'Continuation is blocked',
  REJECTED: 'Proposed next step was not accepted',
});
const record = v => v !== null && typeof v === 'object' && !Array.isArray(v);
const text = (v, max = 4000) => typeof v === 'string' && v.length <= max;
export const safeId = v => typeof v === 'string' && /^[A-Za-z0-9_-]{1,100}$/.test(v);
const digest = v => typeof v === 'string' && /^[0-9a-f]{64}$/.test(v);
const count = v => Number.isSafeInteger(v) && v >= 0;
export function timeMillis(v) {
  if (v && typeof v.toMillis === 'function') return v.toMillis();
  if (record(v) && Number.isFinite(v.seconds)) return v.seconds * 1000 + (v.nanoseconds || 0) / 1e6;
  return typeof v === 'string' ? Date.parse(v) : NaN;
}
const timestamp = v => Number.isFinite(timeMillis(v));
const bounded = v => { try { return new TextEncoder().encode(JSON.stringify(v)).length < 950_000; } catch { return false; } };
const owner = (v, uid, schema) => Boolean(uid && record(v) && v.ownerUid === uid && v.schemaVersion === schema);
const continuationTime = v => text(v, 80)
  && /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,6})?(?:Z|[+-]\d\d:\d\d)$/.test(v)
  && Number.isFinite(Date.parse(v));

// Nested read-only data derives identity from the validated delivery envelope.
// Do not coerce absent fields, counters, booleans or timestamps into success.
export function validContinuation(v) {
  return record(v) && v.schemaVersion === CONTINUATION_SCHEMA && typeof v.enabled === 'boolean'
    && text(v.state, 80) && Object.hasOwn(continuationLabels, v.state)
    // Python status() truncates Unicode code points, not UTF-16 code units.
    && ['objective', 'whatHappened', 'whatImproved'].every(k => text(v[k], 2400) && [...v[k]].length <= 1200)
    && text(v.nextAction) && (v.blocker === null || text(v.blocker))
    && ['cycleId', 'parentBuildId', 'childBuildId'].every(k => v[k] === null || safeId(v[k]))
    && (v.nextEligibleAt === null || continuationTime(v.nextEligibleAt)) && continuationTime(v.updatedAt)
    && record(v.research) && count(v.research.attempted) && count(v.research.verified)
    && v.research.maxPer24h === 2 && v.research.verified <= v.research.attempted
    && v.research.attempted <= v.research.maxPer24h && bounded(v);
}

export function continuationSummary(delivery, { uid, fromCache = true, hasPendingWrites = false,
  offline = false, error = '', now = Date.now() } = {}) {
  const unavailable = reason => ({ available: false, state: 'UNAVAILABLE',
    label: 'Continuation status unavailable', reason, receipt: null });
  if (!uid) return unavailable('An authenticated owner session is required.');
  if (error) return unavailable('The host delivery readback is unavailable. No current work or outcome is inferred.');
  if (!delivery) return unavailable('No host continuation status has been received.');
  if (!validOwnerDelivery(delivery, uid)) return unavailable('The host identity or delivery contract did not verify.');
  const readback = deliveryReadback(delivery, { fromCache, hasPendingWrites, offline, now });
  if (!readback.current) return unavailable(readback.label);
  const value = delivery.continuation;
  if (value === null || value === undefined) return unavailable('This host has not published continuation status.');
  if (!validContinuation(value)) return unavailable('The continuation status is incomplete or does not match its contract.');
  const age = now - Date.parse(value.updatedAt);
  if (!Number.isFinite(age) || age > FRESHNESS_MS || age < -60_000) {
    return unavailable('The continuation status is out of date. A fresh delivery heartbeat alone does not verify it.');
  }

  // A configuration/read failure is a real BLOCKED status with enabled=false.
  if ((value.enabled && value.state === 'DISABLED')
    || (!value.enabled && !['DISABLED', 'BLOCKED'].includes(value.state))) {
    return unavailable('The continuation enabled flag and state disagree.');
  }
  const research = { attempted: value.research.attempted, verified: value.research.verified, maxPer24h: value.research.maxPer24h };
  return {
    available: true, state: value.state, enabled: value.enabled, label: continuationLabels[value.state], reason: '',
    objective: value.objective.trim() ? value.objective : 'No current objective reported.',
    happened: value.whatHappened.trim() ? value.whatHappened : 'No new activity reported.',
    improved: value.whatImproved.trim() ? value.whatImproved : 'No verified improvement reported.',
    nextAction: value.nextAction.trim() ? value.nextAction : value.enabled ? 'No next action reported.' : 'Automatic continuation is off.',
    blocker: value.blocker?.trim() ? value.blocker : '', nextEligibleAt: value.nextEligibleAt,
    researchLabel: `Public catalog evidence, rolling 24 hours: ${research.attempted} fetch attempts charged / ${research.maxPer24h} allowed; ${research.verified} fetch receipts verified.`,
    // Explicit bounded fields only: unknown payloads never become rendered HTML,
    // clickable links, invented file hashes or an alternate authority channel.
    receipt: { schemaVersion: value.schemaVersion, enabled: value.enabled, state: value.state,
      cycleId: value.cycleId, parentBuildId: value.parentBuildId, childBuildId: value.childBuildId,
      research, nextEligibleAt: value.nextEligibleAt, updatedAt: value.updatedAt, deliveryUpdatedAt: delivery.updatedAt },
  };
}

export const validCaps = v => record(v) && Object.entries(CEILINGS).every(([k, max]) => Number.isSafeInteger(v[k]) && v[k] >= 1 && v[k] <= max);
export function validBuild(v, uid, id = v?.buildId) {
  return owner(v, uid, BUILD_SCHEMA) && safeId(v.buildId) && v.buildId === id
    && (v.parentBuildId === '' || safeId(v.parentBuildId)) && safeId(v.rootBuildId)
    && ['build', 'upgrade', 'steer', 'discover'].includes(v.action)
    && text(v.title, 2000) && v.title.trim().length > 0 && text(v.summary, 16000)
    && text(v.status, 80) && text(v.reason, 16000) && timestamp(v.createdAt) && timestamp(v.updatedAt)
    && (v.bundleDigest === '' || digest(v.bundleDigest)) && typeof v.archived === 'boolean'
    && record(v.verification) && record(v.usage) && count(v.usage.providerCalls) && count(v.usage.toolCalls)
    && Array.isArray(v.files) && v.files.length <= 128 && v.files.every(f => record(f)
      && text(f.path, 4096) && f.path.length > 0 && text(f.content, 900000) && digest(f.sha256))
    && new Set(v.files.map(f => f.path)).size === v.files.length && bounded(v);
}
export function validControls(v, uid) {
  return owner(v, uid, CONTROLS_SCHEMA) && Number.isSafeInteger(v.revision) && v.revision > 0
    && v.revision <= 2147483647 && validCaps(v) && timestamp(v.updatedAt);
}
export function validStatus(v, uid) {
  return owner(v, uid, STATUS_SCHEMA) && count(v.requestedRevision) && count(v.effectiveRevision)
    && text(v.state, 80) && text(v.reason, 16000) && validCaps(v.effective) && validCaps(v.ceilings)
    && record(v.usage) && ['jobs', 'providerCalls', 'toolCalls'].every(k => count(v.usage[k])) && timestamp(v.updatedAt);
}
export function validRequest(v, uid, id = v?.requestId) {
  return owner(v, uid, REQUEST_SCHEMA) && safeId(v.requestId) && v.requestId === id
    && safeId(v.parentBuildId) && digest(v.parentDigest) && ACTIONS.includes(v.action)
    && text(v.instructions, 2000) && (v.action !== 'steer' || v.instructions.trim().length > 0)
    && Number.isSafeInteger(v.maxProviderCalls) && v.maxProviderCalls >= 1 && v.maxProviderCalls <= 20
    && Number.isSafeInteger(v.maxToolCalls) && v.maxToolCalls >= 1 && v.maxToolCalls <= 12
    && count(v.controlRevision) && timestamp(v.createdAt) && timestamp(v.expiresAt);
}
export function validReceipt(v, uid, id = v?.requestId) {
  return owner(v, uid, RECEIPT_SCHEMA) && safeId(v.requestId) && v.requestId === id
    && safeId(v.parentBuildId) && ACTIONS.includes(v.action)
    && ['QUEUED', 'WAITING_BUDGET', 'RUNNING', 'COMPLETE', 'REJECTED', 'FAILED'].includes(v.state)
    && text(v.reason, 16000) && (v.buildId === '' || safeId(v.buildId)) && timestamp(v.updatedAt);
}
export function authorityReason({ uid, workspace, status, controls, verified = {}, offline = false, now = Date.now() }) {
  if (offline) return 'Offline. Reconnect before changing budgets or requesting work.';
  if (!workspace?.exists || !workspace.verified || workspace.busy || workspace.workspace?.ownerUid !== uid) return 'Owner settings are not server-verified.';
  const w = workspace.workspace;
  if (w.autonomyMode !== 'full' || w.autonomyAcknowledged !== true || w.learningEnabled !== true
    || w.permissions?.workspaceRead !== true || w.permissions?.workspaceWrite !== true) return 'Enable confirmed full mode, learning, workspace read and workspace write in owner settings.';
  if (!validStatus(status, uid) || !verified.status) return 'Disconnected: no verified host budget projection.';
  const age = now - timeMillis(status.updatedAt);
  if (age > FRESHNESS_MS || age < -60_000) return 'Disconnected: host budget readback is out of date.';
  if (!verified.controls || (controls && !validControls(controls, uid))) return 'Budget intent is not server-verified.';
  if (/INVALID|REJECTED|DISCONNECTED|BLOCKED|ERROR/.test(status.state)) return `Host controls unavailable: ${status.reason || status.state}`;
  return '';
}
export function requestReason(context, build, action) {
  const reason = authorityReason(context);
  if (reason) return reason;
  if (context.status.effectiveRevision !== (context.controls?.revision || 0)) return 'Wait for the host to apply the current budget intent revision.';
  if (!context.verified.builds || !validBuild(build, context.uid) || build.status !== 'COMPLETE' || !digest(build.bundleDigest)) return 'Select a server-verified COMPLETE build with an exact bundle digest.';
  if (!ACTIONS.includes(action)) return 'Choose a supported action.';
  if (build.archived && action !== 'restore') return 'Restore this archived build before requesting more work.';
  if (!build.archived && action === 'restore') return 'This build is not archived.';
  return '';
}
export function controlsPreview(context, caps) {
  const reason = authorityReason(context);
  if (reason) throw new Error(reason);
  if (!validCaps(caps) || Object.keys(CEILINGS).some(k => caps[k] > context.status.ceilings[k])) throw new Error('Budgets exceed the host ceilings or are not whole positive numbers.');
  return Object.freeze({ schemaVersion: CONTROLS_SCHEMA, ownerUid: context.uid,
    revision: (context.controls?.revision || 0) + 1, ...Object.fromEntries(Object.keys(CEILINGS).map(k => [k, caps[k]])) });
}
export function requestPreview(context, build, input, requestId, now = Date.now()) {
  const reason = requestReason(context, build, input.action);
  if (reason) throw new Error(reason);
  const payload = { schemaVersion: REQUEST_SCHEMA, ownerUid: context.uid, requestId,
    parentBuildId: build.buildId, parentDigest: build.bundleDigest, action: input.action,
    instructions: input.instructions, maxProviderCalls: input.maxProviderCalls,
    maxToolCalls: input.maxToolCalls, controlRevision: context.controls?.revision || 0,
    expiresAt: new Date(now + 6 * 86400000).toISOString() };
  if (!validRequest({ ...payload, createdAt: new Date(now).toISOString() }, context.uid)
    || payload.maxProviderCalls > context.status.effective.maxDailyProviderCalls
    || payload.maxToolCalls > context.status.effective.maxDailyToolCalls) throw new Error('Check instructions and per-request caps against host-applied budgets.');
  return Object.freeze(payload);
}
export function sameRequest(actual, expected) {
  return Object.entries(expected).every(([k, v]) => k === 'expiresAt' ? timeMillis(actual[k]) === timeMillis(v) : actual[k] === v);
}
export function filterBuilds(builds, search = '', archived = false) {
  const term = search.toLocaleLowerCase();
  return builds.filter(b => b.archived === archived && `${b.title}\n${b.summary}\n${b.buildId}`.toLocaleLowerCase().includes(term))
    .sort((a, b) => timeMillis(b.createdAt) - timeMillis(a.createdAt) || a.buildId.localeCompare(b.buildId));
}
export function downloadName(path) {
  // Never open projected HTML/JS with its executable extension.
  return `${String(path).split(/[\\/]/).pop().replace(/[^A-Za-z0-9._-]/g, '_') || 'artifact'}.txt`;
}
