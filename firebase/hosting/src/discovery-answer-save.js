// Local recovery metadata only. The five-field Firestore answer schema is unchanged.
const PREFIX = 'cct.discovery-draft.v1:';
const questionId = value => typeof value === 'string' && /^q-[a-f0-9]{32}$/.test(value);
const answerText = value => typeof value === 'string' && value.trim().length > 0 && value.length <= 4000;
const fresh = snapshot => snapshot?.metadata?.fromCache === false && snapshot.metadata.hasPendingWrites === false;
const copy = value => JSON.parse(JSON.stringify(value));
export const ANSWER_STAGE_TIMEOUT_MS = 15_000;

export function validAnswer(value, uid, id) {
  return !!value && Object.keys(value).length === 5 && value.schemaVersion === 'cct.discovery_answer.v1'
    && value.ownerUid === uid && value.questionId === id && answerText(value.text)
    && typeof value.createdAt?.toMillis === 'function' && Number.isFinite(value.createdAt.toMillis());
}

export function answerFailureReason(error) {
  const code = String(error?.code || error?.status || error?.message || '').toLowerCase().replace(/^firestore\//, '');
  if (/resource.exhausted|quota|(^|\D)429(\D|$)/.test(code)) return 'Firestore quota/rate limit reached (429 / resource-exhausted).';
  if (/unavailable|offline|network/.test(code) && code !== 'storage_unavailable') return 'Firestore is unavailable or the connection is offline.';
  if (code === 'timeout') return `Timed out while ${error.stage || 'contacting Firestore'}.`;
  if (code === 'question_changed') return 'The question or learning settings changed.';
  if (code === 'inactive') return 'This owner session is no longer active.';
  if (/permission-denied|unauthenticated/.test(code)) return 'Firestore could not authorize this owner session.';
  if (code === 'storage_unavailable') return 'Durable browser storage is unavailable; no reply was sent.';
  return 'The server reply could not be verified.';
}

export async function answerStage(stage, action, timeoutMs = ANSWER_STAGE_TIMEOUT_MS) {
  let timer;
  try {
    return await Promise.race([
      Promise.resolve().then(action),
      new Promise((_, reject) => { timer = setTimeout(() => reject(Object.assign(new Error('TIMEOUT'), { code: 'timeout', stage })), timeoutMs); }),
    ]);
  } finally { clearTimeout(timer); }
}

export function createAnswerDraftStore(ownerUid, storageProvider = () => globalThis.localStorage) {
  if (typeof ownerUid !== 'string' || !ownerUid) throw Error('OWNER_REQUIRED');
  const memory = new Map();
  const key = id => {
    if (!questionId(id)) throw Error('QUESTION_REQUIRED');
    return `${PREFIX}${encodeURIComponent(ownerUid)}:${id}`;
  };
  const empty = id => ({ version: 1, ownerUid, questionId: id, text: '', attempt: null });
  const valid = (record, id) => record?.version === 1 && record.ownerUid === ownerUid && record.questionId === id
    && typeof record.text === 'string' && record.text.length <= 4000
    && (record.attempt === null || !!record.attempt && typeof record.attempt.id === 'string' && record.attempt.id.length > 0
      && answerText(record.attempt.text) && ['pending', 'acknowledged', 'rejected'].includes(record.attempt.state));
  function read(id) {
    const storageKey = key(id);
    const cached = memory.get(id);
    try {
      const raw = storageProvider().getItem(storageKey);
      // A failed write must not be replaced by an older disk draft.
      if (cached && !cached.available) return copy(cached);
      const record = raw === null ? empty(id) : JSON.parse(raw);
      if (!valid(record, id)) throw Error('INVALID_DRAFT');
      const entry = { record, durable: raw !== null, available: true, blocked: false };
      memory.set(id, entry);
      return copy(entry);
    } catch {
      const entry = cached ? { ...cached, durable: false, available: false }
        : { record: empty(id), durable: false, available: false, blocked: true };
      memory.set(id, entry);
      return copy(entry);
    }
  }
  function write(id, record) {
    if (!valid(record, id)) throw Error('INVALID_DRAFT');
    const entry = { record: copy(record), durable: false, available: false, blocked: false };
    memory.set(id, entry);
    try {
      const storage = storageProvider();
      const raw = JSON.stringify(record);
      storage.setItem(key(id), raw);
      if (storage.getItem(key(id)) !== raw) throw Error('STORAGE_READBACK');
      entry.durable = true; entry.available = true;
    } catch { /* Retain the actual latest draft in memory; never claim reload safety. */ }
    return copy(entry);
  }
  return {
    read, write,
    edit(id, text) {
      const entry = read(id);
      if (entry.record.attempt && entry.record.attempt.state !== 'rejected') return entry;
      // Keep storage-read uncertainty locked, but retain typed text in this tab.
      if (entry.blocked) {
        entry.record.text = text; memory.set(id, entry); return copy(entry);
      }
      return write(id, { ...entry.record, text });
    },
    clear(id) {
      try { storageProvider().removeItem(key(id)); }
      catch { return false; }
      memory.delete(id);
      return true;
    },
    forget() { memory.clear(); },
  };
}

export function draftRetention(entry) {
  return entry?.durable ? 'Draft saved in this browser for this owner and question; it survives reload.'
    : 'Draft is only in this tab: browser storage is unavailable. Copy it before closing or reloading.';
}

// A rejected SDK operation is retryable only for definite rejection codes. A timeout,
// transport failure, lost acknowledgement or reload NEVER proves that a write stopped.
const definiteRejection = error => ['permission-denied', 'unauthenticated', 'invalid-argument', 'failed-precondition', 'resource-exhausted']
  .includes(String(error?.code || '').replace(/^firestore\//, ''));

export function createAnswerSaver({ ownerUid, drafts, readAnswer, checkContext, writeAnswer,
  isActive = () => true, onChange = () => {}, timeoutMs = ANSWER_STAGE_TIMEOUT_MS }) {
  const running = new Set();
  const messages = new Map();
  const verified = new Map();
  const conflicts = new Map();
  const changed = () => { if (isActive()) onChange(); };
  function state(id) {
    const entry = drafts.read(id);
    const attempt = entry.record.attempt;
    const locked = entry.blocked || !!attempt && attempt.state !== 'rejected';
    return { ...entry, busy: running.has(id), locked, saved: verified.get(id) || null, existing: conflicts.get(id) || null,
      message: messages.get(id) || (locked ? 'A previous save is unverified. Check saved reply; this will only read, never resend.' : '') };
  }
  function observe(id, snapshot) {
    if (!fresh(snapshot) || !snapshot.exists()) return false;
    const record = snapshot.data();
    if (!validAnswer(record, ownerUid, id)) throw Error('UNVERIFIED');
    const entry = drafts.read(id);
    const expected = entry.record.attempt?.text || entry.record.text;
    // Existing replies remain immutable. Keep a different local draft for copying.
    const matches = !expected || record.text === expected;
    if (matches) {
      verified.set(id, record);
      conflicts.delete(id);
      drafts.clear(id);
      messages.set(id, 'Saved and verified from the server. CCT will build on your thoughts—not start work from this reply.');
    } else {
      conflicts.set(id, record);
      messages.set(id, 'Another reply is already saved for this question. Your different draft has not overwritten it; copy it before leaving.');
    }
    changed();
    return true;
  }
  async function read(id, stage) {
    const snapshot = await answerStage(stage, () => readAnswer(id), timeoutMs);
    if (!fresh(snapshot)) throw Error('UNVERIFIED');
    return snapshot;
  }
  async function run(id, verifyOnly = false) {
    if (running.has(id) || !isActive()) return;
    running.add(id);
    messages.set(id, verifyOnly ? 'Checking the exact saved reply…' : 'Checking the server before saving…');
    changed();
    try {
      // Always read the exact answer FIRST, including a retry after a definite failure.
      const prior = await read(id, 'checking for an existing reply');
      if (!isActive()) return;
      if (observe(id, prior)) return;
      let entry = drafts.read(id);
      if (verifyOnly || state(id).locked) {
        messages.set(id, 'No saved reply was verified yet. The earlier write may still finish; it will not be sent again.');
        return;
      }
      if (!answerText(entry.record.text)) throw Error('INVALID_ANSWER');
      const answer = entry.record.text;
      await answerStage('checking the current question and learning settings', () => checkContext(id), timeoutMs);
      if (!isActive()) return;
      // Re-read durable intent after awaits: another mount may already have attempted it.
      entry = drafts.read(id);
      if (state(id).locked || entry.record.text !== answer) throw Error('UNVERIFIED');
      const attempt = { id: globalThis.crypto.randomUUID(), text: answer, state: 'pending' };
      const intent = drafts.write(id, { ...entry.record, attempt });
      if (!intent.durable) throw Error('STORAGE_UNAVAILABLE');
      messages.set(id, 'Sending your reply; the draft stays until exact server verification.');
      changed();
      const settle = (state, failure) => {
        const current = drafts.read(id);
        if (current.record.attempt?.id !== attempt.id) return;
        drafts.write(id, { ...current.record, attempt: { ...attempt, state } });
        if (failure) messages.set(id, `${answerFailureReason(failure)} ${state === 'rejected'
          ? 'The write was rejected. Retry checks the server before sending.'
          : 'The write outcome is unknown. Check saved reply; it will not be resent.'}`);
        changed();
      };
      // Observe the REAL promise after the deadline too; Promise.race is not cancellation.
      const write = Promise.resolve().then(() => writeAnswer(id, answer)).then(
        result => { settle('acknowledged'); return result; },
        failure => { settle(definiteRejection(failure) ? 'rejected' : 'pending', failure); throw failure; });
      await answerStage('waiting for the save acknowledgement', () => write, timeoutMs);
      const readback = await read(id, 'verifying the saved reply');
      if (!isActive()) return;
      if (!observe(id, readback)) throw Error('UNVERIFIED');
    } catch (failure) {
      if (verified.has(id) || conflicts.has(id)) return;
      const entry = drafts.read(id);
      messages.set(id, `${answerFailureReason(failure)} ${entry.record.attempt && entry.record.attempt.state !== 'rejected'
        ? 'The save outcome is unknown. Check saved reply; no new write will be sent.'
        : 'No saved reply is confirmed. Retry checks the server before sending.'}`);
    } finally { running.delete(id); changed(); }
  }
  return { state, observe, save: id => run(id), verify: id => run(id, true) };
}
