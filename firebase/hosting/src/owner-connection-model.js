// Host attestation only. Legacy observer snapshots never establish authority.
const digest = (value) => typeof value === 'string' && /^[a-f0-9]{64}$/.test(value);
const revision = (value) => Number.isSafeInteger(value) && value >= 1 && value <= 2147483647;
const object = (value) => value && typeof value === 'object' && !Array.isArray(value);
const exactKeys = (value, keys) => object(value) && Object.keys(value).length === keys.length && keys.every((key) => Object.hasOwn(value, key));
const isoTime = (value) => typeof value === 'string' && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|\+00:00)$/.test(value) && Number.isFinite(Date.parse(value)) && new Date(Date.parse(value)).toISOString().slice(0, 19) === value.slice(0, 19);
export const messageIdValid = (value) => typeof value === 'string' && /^msg-[a-f0-9]{32}$/.test(value);
const result = (state, detail, ownerMessages = false) => ({ state, detail, effectivePolicy: { ownerMessages, autonomyMode: 'supervised' } });

export function validateRuntimeStatus(value, { ownerUid, projectId, workspaceRevision, workspaceVerified = false, fromCache = false, hasPendingWrites = false, now = Date.now() } = {}) {
  if (!value) return result('NOT_CONNECTED', 'No owner-runtime attestation received. Legacy diagnostics are not connection proof.');
  if (!ownerUid || !projectId || !object(value) || value.schemaVersion !== 'cct.owner_runtime.v1'
    || value.ownerUid !== ownerUid || value.projectId !== projectId || value.scope !== 'OWNER_MESSAGES_ONLY'
    || !['CONNECTED', 'INVALID', 'DISABLED'].includes(value.state)
    || !isoTime(value.updatedAt) || !Number.isFinite(now)
    || !(value.revision === null || revision(value.revision))
    || !(value.policySha256 === null || digest(value.policySha256))
    || !(value.workspaceSha256 === null || digest(value.workspaceSha256))
    || !exactKeys(value.effectivePolicy, ['ownerMessages', 'autonomyMode'])
    || typeof value.effectivePolicy.ownerMessages !== 'boolean' || value.effectivePolicy.autonomyMode !== 'supervised'
    || !Array.isArray(value.unsupportedPermissions) || value.unsupportedPermissions.length > 16
    || !value.unsupportedPermissions.every((key) => typeof key === 'string' && /^[a-zA-Z][a-zA-Z0-9_]{0,63}$/.test(key))
    || typeof value.reasonCode !== 'string' || !/^[A-Z][A-Z0-9_]{0,63}$/.test(value.reasonCode)) {
    return result('INVALID', 'Owner runtime identity, schema, scope or policy evidence is invalid. No effective authority.');
  }
  const age = now - Date.parse(value.updatedAt);
  if (fromCache || hasPendingWrites || age > 180_000 || age < -60_000) return result('STALE', 'Owner-runtime evidence is cached or outside its freshness window. Reconnect for fresh proof.');
  if (value.state !== 'CONNECTED') return result(value.state, value.state === 'DISABLED' ? 'The host has disabled owner messaging.' : 'The host rejected the owner connection. Review host configuration.');
  if (!revision(value.revision) || !digest(value.policySha256) || !digest(value.workspaceSha256)) return result('INVALID', 'Connected runtime requires a workspace revision and valid policy and workspace digests.');
  if (!workspaceVerified || value.revision !== workspaceRevision) return result('SYNC_PENDING', 'Waiting for the host to acknowledge the current, server-verified workspace revision.');
  const detail = value.reasonCode === 'OWNER_TELEGRAM_UNAVAILABLE'
    ? 'Dashboard connected. Telegram delivery is unavailable; owner messages are not effective.'
    : 'Fresh host attestation for this owner and workspace. Supervised; private owner messages only.';
  return result('CONNECTED', detail, value.effectivePolicy.ownerMessages);
}

export function validateOwnerMessage(value, ownerUid, documentId) {
  return object(value) && value.schemaVersion === 'cct.owner_message.v1' && value.ownerUid === ownerUid
    && messageIdValid(value.messageId) && value.messageId === documentId
    && ['ask', 'send'].includes(value.kind) && typeof value.text === 'string' && value.text.trim().length > 0 && value.text.length <= 4000
    && ['QUEUED', 'SENDING', 'SENT', 'ANSWERED', 'DENIED', 'UNKNOWN'].includes(value.state)
    && isoTime(value.createdAt) && isoTime(value.expiresAt) && Date.parse(value.expiresAt) > Date.parse(value.createdAt)
    && revision(value.revision) && digest(value.policySha256)
    && (value.telegramMessageId === null || (typeof value.telegramMessageId === 'string' && value.telegramMessageId.length > 0 && value.telegramMessageId.length <= 64))
    && (value.answer === null || (typeof value.answer === 'string' && value.answer.length <= 2000));
}

export function canReplyToMessage(value, now = Date.now()) {
  return value?.kind === 'ask' && value.state === 'SENT' && value.answer === null && isoTime(value.expiresAt) && Date.parse(value.expiresAt) > now;
}

export function buildOwnerReply(ownerUid, messageId, text, createdAt) {
  if (!ownerUid || !messageIdValid(messageId) || typeof text !== 'string' || !text.trim() || text.trim().length > 2000) throw new Error('REPLY_INVALID');
  return { schemaVersion: 'cct.owner_reply.v1', ownerUid, messageId, text: text.trim(), createdAt };
}

export function verifyOwnerReply(value, expected) {
  return exactKeys(value, ['schemaVersion', 'ownerUid', 'messageId', 'text', 'createdAt'])
    && ['schemaVersion', 'ownerUid', 'messageId', 'text'].every((key) => value[key] === expected[key])
    && typeof value.createdAt?.toMillis === 'function' && Number.isFinite(value.createdAt.toMillis());
}
