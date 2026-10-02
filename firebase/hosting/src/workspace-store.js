import { doc, getDocFromServer, onSnapshot, runTransaction, serverTimestamp } from 'firebase/firestore';
import { applyWorkspaceAction, defaultWorkspace, validateWorkspace } from './workspace-model.js';

// Firestore does not preserve map insertion order.
const canonical = (value) => JSON.stringify(value, (key, item) => item && typeof item === 'object' && !Array.isArray(item)
  ? Object.fromEntries(Object.keys(item).sort().map((name) => [name, item[name]])) : item);

const errorCopy = (error) => {
  if (error?.code === 'permission-denied') return 'Save unavailable: owner access or workspace rules rejected this request.';
  if (error?.code === 'unavailable' || error?.code === 'deadline-exceeded') return 'Connection unavailable. Nothing is marked saved; reconnect and retry.';
  if (error?.message === 'DECISION_LIMIT') return 'The 60-card feedback limit is reached. Existing card feedback can still be changed.';
  if (error?.message === 'WORKSPACE_INVALID') return 'The saved workspace has an unsupported schema. No data was overwritten.';
  if (error?.message === 'READBACK_UNVERIFIED') return 'Write acknowledgement received, but server readback was not verified. Refresh before retrying.';
  if (error?.code === 'aborted') return 'Another session changed the workspace. Refresh and retry; no stale form was written.';
  return 'Save not verified. Refresh the workspace and try again.';
};

export function createWorkspaceStore(db, ownerUid, onChange) {
  const reference = doc(db, 'cct_workspace', 'current');
  const state = { workspace: defaultWorkspace(ownerUid), ready: false, busy: false, exists: false,
    verified: false, message: 'Reading your private workspace…', error: false };
  let unsubscribe = null;
  let closed = false;
  const emit = () => { if (!closed) onChange({ ...state }); };
  const consume = (snapshot) => {
    if (closed || snapshot.metadata.hasPendingWrites) return;
    if (snapshot.exists() && !validateWorkspace(snapshot.data(), ownerUid)) {
      state.ready = false;
      state.verified = false;
      state.error = true;
      state.message = 'Unsupported workspace schema. Saving is blocked; existing data is preserved.';
      emit();
      return;
    }
    state.exists = snapshot.exists();
    state.workspace = snapshot.exists() ? snapshot.data() : defaultWorkspace(ownerUid);
    state.verified = !snapshot.metadata.fromCache;
    state.ready = state.verified;
    if (!state.busy) {
      state.error = false;
      state.message = state.verified
        ? (state.exists ? `Saved · revision ${state.workspace.revision} · server verified` : 'Private workspace ready. Your first change will create it.')
        : 'Cached workspace only. Connect to verify it before saving.';
    }
    emit();
  };
  return {
    start() {
      emit();
      unsubscribe = onSnapshot(reference, { includeMetadataChanges: true }, consume, () => {
        state.ready = false;
        state.verified = false;
        state.error = true;
        state.message = 'Workspace unavailable. Owner access or network connection could not be verified.';
        emit();
      });
    },
    stop() { closed = true; unsubscribe?.(); },
    async refresh() {
      try { consume(await getDocFromServer(reference)); }
      catch (_error) {
        state.ready = false;
        state.verified = false;
        state.error = true;
        state.message = 'Server refresh failed. Displayed settings are not freshly verified.';
        emit();
      }
    },
    async save(action) {
      if (closed || state.busy || !state.ready) return false;
      state.busy = true;
      state.error = false;
      state.message = 'Saving owner intent… waiting for server readback.';
      emit();
      // Keep intent fixed across Firestore transaction retries.
      const intent = Object.freeze({ ...action });
      let writeAcknowledged = false;
      try {
        const committed = await runTransaction(db, async (transaction) => {
          if (closed) throw new Error('OWNER_SESSION_CLOSED');
          const current = await transaction.get(reference);
          const base = current.exists() ? current.data() : defaultWorkspace(ownerUid);
          if (!validateWorkspace(base, ownerUid, { allowUnsaved: !current.exists() })) throw new Error('WORKSPACE_INVALID');
          const updated = applyWorkspaceAction(base, intent);
          const payload = {
            schemaVersion: updated.schemaVersion,
            ownerUid,
            revision: base.revision + 1,
            updatedAt: serverTimestamp(),
            learningEnabled: updated.learningEnabled,
            permissions: { ...updated.permissions },
            autonomyMode: updated.autonomyMode,
            autonomyAcknowledged: updated.autonomyAcknowledged,
            answers: { ...updated.answers },
            decisions: { ...updated.decisions },
          };
          transaction.set(reference, payload);
          return { revision: payload.revision, workspace: updated };
        });
        writeAcknowledged = true;
        const verified = await getDocFromServer(reference);
        if (closed) return false;
        if (!verified.exists() || verified.metadata.fromCache || verified.metadata.hasPendingWrites
          || !validateWorkspace(verified.data(), ownerUid) || verified.data().revision < committed.revision) throw new Error('READBACK_UNVERIFIED');
        const readback = verified.data();
        if (readback.revision === committed.revision) {
          const expected = { ...committed.workspace, revision: committed.revision, updatedAt: readback.updatedAt };
          if (canonical(readback) !== canonical(expected)) throw new Error('READBACK_UNVERIFIED');
        }
        consume(verified);
        state.error = false;
        state.message = verified.data().revision === committed.revision
          ? `Saved · revision ${committed.revision} · server verified. Owner-runtime acknowledgement is shown separately.`
          : `Revision ${committed.revision} committed; newer revision ${verified.data().revision} now shown. Review changes from another session.`;
        return true;
      } catch (error) {
        if (closed) return false;
        if (writeAcknowledged) {
          state.ready = false;
          state.verified = false;
        }
        state.error = true;
        state.message = errorCopy(writeAcknowledged ? new Error('READBACK_UNVERIFIED') : error);
        return false;
      } finally {
        state.busy = false;
        emit();
      }
    },
  };
}
