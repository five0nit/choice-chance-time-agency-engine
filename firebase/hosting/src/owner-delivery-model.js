export const DELIVERY_SCHEMA = 'cct.owner_delivery.v1';
export const DELIVERY_SCOPE = 'PRIVATE_SANDBOXED_LOCAL_DELIVERY';
export const DELIVERY_FRESHNESS_MS = 180_000;

const record = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const text = (value, max = 4000) => typeof value === 'string' && value.length <= max;
const identifier = value => text(value, 500) && value.trim().length > 0 && !/[\u0000-\u001f\u007f]/.test(value);
const phase = value => text(value, 80) && /^[A-Z][A-Z0-9_]*$/.test(value);
const count = value => Number.isSafeInteger(value) && value >= 0;
const timestamp = value => text(value, 80) && /^\d{4}-\d\d-\d\dT.*(?:Z|[+-]\d\d:\d\d)$/.test(value) && Number.isFinite(Date.parse(value));
const optionalText = (value, max) => value === null || value === undefined || text(value, max);
const optionalRecord = value => value === null || value === undefined || record(value);
const validCapabilities = value => value === null || value === undefined || (
  Array.isArray(value) && value.length <= 64
  && value.every(c => record(c) && identifier(c.id)
    && optionalText(c.reason, 4000) && optionalText(c.reasonCode, 4000)
    && ['implemented', 'configured', 'authorized', 'readVerified'].every(key => typeof c[key] === 'boolean')
    && ['requiresExactTicket', 'rootPolicyEnabled', 'ticketAuthorityBound'].every(key => c[key] === undefined || typeof c[key] === 'boolean')
    && optionalRecord(c.lastEvidence))
  && new Set(value.map(c => c.id)).size === value.length
);
const boundedJson = value => {
  try { return JSON.stringify(value).length <= 80_000; } catch { return false; }
};

// Validate identity and the specified projection contract, not an imagined
// executor. Unknown bounded receipt fields remain evidence, never authority.
export function validOwnerDelivery(value, uid) {
  if (!uid || !record(value) || value.schemaVersion !== DELIVERY_SCHEMA || value.ownerUid !== uid
    || value.scope !== DELIVERY_SCOPE || value.trigger !== 'AUTO_FULL_MODE'
    || !timestamp(value.updatedAt) || !phase(value.phase) || !text(value.reason)
    || !text(value.nextAction) || !record(value.counts)
    || !['queued', 'complete', 'blocked', 'retry'].every(key => count(value.counts[key]))
    || !validCapabilities(value.capabilities)
    || !(value.lastOutcome === null || text(value.lastOutcome) || record(value.lastOutcome))
    || !boundedJson(value)) return false;
  if (value.job === null) return true;
  const j = value.job;
  return record(j) && identifier(j.id) && identifier(j.ideaId) && identifier(j.turnId)
    && text(j.title, 2000) && j.title.trim().length > 0 && phase(j.phase) && count(j.attempts)
    && optionalText(j.artifactRoot, 4096) && text(j.reason) && text(j.nextAction)
    && optionalRecord(j.verification) && optionalRecord(j.review)
    && (j.retryAt === undefined || j.retryAt === null || (Number.isFinite(j.retryAt) && j.retryAt >= 0 && j.retryAt <= 8_640_000_000_000))
    && (j.reportIds === undefined || (Array.isArray(j.reportIds) && j.reportIds.length <= 100 && j.reportIds.every(identifier)));
}

export function deliveryReadback(value, { fromCache = false, hasPendingWrites = false, offline = false, now = Date.now() } = {}) {
  if (!value) return { state: 'WAITING', current: false, label: 'No host delivery projection received.' };
  if (hasPendingWrites) return { state: 'UNCONFIRMED', current: false, label: 'Pending local data · not a verified host receipt.' };
  if (fromCache || offline) return { state: 'CACHED', current: false, label: 'Cached receipt · current host execution is not verified.' };
  const age = now - Date.parse(value.updatedAt);
  if (!Number.isFinite(age) || age > DELIVERY_FRESHNESS_MS || age < -60_000) {
    return { state: 'STALE', current: false, label: 'Out-of-date host receipt · current execution is not verified.' };
  }
  return { state: 'SERVER_READ', current: true, label: 'Server read · host-reported capability and job evidence.' };
}

export function configuredDeliveryMode(view) {
  if (!view?.exists) return 'No saved mode verified';
  const w = view.workspace;
  const saved = view.verified && !view.busy ? 'Server-verified setting' : 'Last available setting · unconfirmed';
  if (w?.autonomyMode === 'full' && w.autonomyAcknowledged === true) return `Full mode configured · ${saved}`;
  if (w?.autonomyMode === 'supervised') return `Supervised configured · ${saved}`;
  return 'Mode setting could not be verified';
}

export function deliveryCapabilityCounts(capabilities = []) {
  return Object.fromEntries(['implemented', 'configured', 'authorized', 'readVerified']
    .map(key => [key, (capabilities || []).filter(capability => capability[key] === true).length]));
}

export function receiptJson(value) {
  return value === null || value === undefined ? '' : JSON.stringify(value, null, 2);
}
