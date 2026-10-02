import { collection, doc, getDocFromServer, getDocsFromServer, limit, onSnapshot, orderBy, query, serverTimestamp, setDoc } from 'firebase/firestore';
import { buildOwnerReply, canReplyToMessage, validateOwnerMessage, validateRuntimeStatus, verifyOwnerReply } from './owner-connection-model.js';

const firestore = { collection, doc, getDocFromServer, getDocsFromServer, limit, onSnapshot, orderBy, query, serverTimestamp, setDoc };
const replyError = (error) => {
  if (error?.message === 'REPLY_INVALID') return 'Enter an answer between 1 and 2,000 characters.';
  if (error?.message === 'REPLY_EXISTS') return 'An answer already exists. Replies are create-only and cannot be replaced.';
  if (error?.message === 'REPLY_NOT_ALLOWED') return 'Reply unavailable: the question expired, changed, or its owner connection is not current.';
  if (error?.message === 'READBACK_UNVERIFIED') return 'Answer may have been saved, but exact server readback was not verified. Refresh before retrying.';
  if (error?.code === 'permission-denied') return 'Owner access or reply rules rejected this answer. Nothing is marked verified.';
  return 'Answer not verified. Check your connection and retry; your draft is retained.';
};

export function createOwnerConnection(db, ownerUid, projectId, workspaceContext, onChange, api = firestore) {
  const runtimeRef = api.doc(db, 'cct_owner_runtime', 'current');
  const messagesQuery = api.query(api.collection(db, 'cct_owner_messages'), api.orderBy('createdAt', 'desc'), api.limit(20));
  const state = { runtime: null, runtimeFromCache: true, runtimePending: false, messages: [], messagesFromCache: true,
    runtimeError: '', messagesError: '', replies: {} };
  let closed = false;
  let started = false;
  const unsubscribes = [];
  const emit = () => { if (!closed) onChange({ ...state, replies: { ...state.replies } }); };
  const consumeRuntime = (snapshot) => {
    if (closed) return;
    state.runtime = snapshot.exists() ? snapshot.data() : null;
    state.runtimeFromCache = snapshot.metadata.fromCache;
    state.runtimePending = snapshot.metadata.hasPendingWrites;
    state.runtimeError = '';
    emit();
  };
  const consumeMessages = (snapshot) => {
    if (closed) return;
    state.messages = snapshot.docs.filter((item) => validateOwnerMessage(item.data(), ownerUid, item.id)).map((item) => item.data());
    state.messagesFromCache = snapshot.metadata.fromCache || snapshot.metadata.hasPendingWrites;
    state.messagesError = state.messages.length === snapshot.docs.length ? '' : 'Some message records have an unsupported schema and are hidden.';
    emit();
  };
  const runtimeFailure = () => { state.runtime = null; state.runtimeFromCache = true; state.runtimeError = 'Owner runtime unavailable. No connection proof.'; emit(); };
  const messagesFailure = () => { state.messagesFromCache = true; state.messagesError = 'Owner messages unavailable. Check owner access and connection.'; emit(); };
  return {
    start() {
      if (started || closed) return;
      started = true;
      unsubscribes.push(api.onSnapshot(runtimeRef, { includeMetadataChanges: true }, consumeRuntime, runtimeFailure));
      unsubscribes.push(api.onSnapshot(messagesQuery, { includeMetadataChanges: true }, consumeMessages, messagesFailure));
    },
    stop() { closed = true; unsubscribes.forEach((unsubscribe) => unsubscribe()); state.messages = []; state.runtime = null; state.replies = {}; },
    async refresh() {
      if (closed) return;
      await Promise.all([
        api.getDocFromServer(runtimeRef).then(consumeRuntime, runtimeFailure),
        api.getDocsFromServer(messagesQuery).then(consumeMessages, messagesFailure),
      ]);
    },
    async reply(messageId, text) {
      if (closed || state.replies[messageId]?.busy) return false;
      state.replies[messageId] = { busy: true, verified: false, error: false, message: 'Saving answer… waiting for exact server readback.' };
      emit();
      let acknowledged = false;
      try {
        const payload = buildOwnerReply(ownerUid, messageId, text, api.serverTimestamp());
        const replyRef = api.doc(db, 'cct_owner_replies', messageId);
        const messageRef = api.doc(db, 'cct_owner_messages', messageId);
        const [runtimeSnapshot, messageSnapshot, existing] = await Promise.all([
          api.getDocFromServer(runtimeRef), api.getDocFromServer(messageRef), api.getDocFromServer(replyRef),
        ]);
        if (closed) return false;
        const serverSnapshots = [runtimeSnapshot, messageSnapshot, existing];
        if (serverSnapshots.some((snapshot) => snapshot.metadata.fromCache || snapshot.metadata.hasPendingWrites)) throw new Error('REPLY_NOT_ALLOWED');
        if (existing.exists()) {
          if (!verifyOwnerReply(existing.data(), payload)) throw new Error('REPLY_EXISTS');
          state.replies[messageId] = { busy: false, verified: true, error: false, message: 'Answer already saved · exact server readback verified. Answer data only, not execution approval.' };
          return true;
        }
        const runtime = runtimeSnapshot.exists() ? runtimeSnapshot.data() : null;
        const message = messageSnapshot.exists() ? messageSnapshot.data() : null;
        const status = validateRuntimeStatus(runtime, { ...workspaceContext(), ownerUid, projectId });
        if (status.state !== 'CONNECTED' || !status.effectivePolicy.ownerMessages || !validateOwnerMessage(message, ownerUid, messageId)
          || !canReplyToMessage(message) || message.revision !== runtime.revision || message.policySha256 !== runtime.policySha256) throw new Error('REPLY_NOT_ALLOWED');
        // The owner rules permit creation only; a concurrent existing reply fails closed.
        await api.setDoc(replyRef, payload);
        acknowledged = true;
        const readback = await api.getDocFromServer(replyRef);
        if (closed) return false;
        if (!readback.exists() || readback.metadata.fromCache || readback.metadata.hasPendingWrites || !verifyOwnerReply(readback.data(), payload)) throw new Error('READBACK_UNVERIFIED');
        state.replies[messageId] = { busy: false, verified: true, error: false, message: 'Answer saved · exact server readback verified. Answer data only, not execution approval.' };
        return true;
      } catch (error) {
        if (!closed) state.replies[messageId] = { busy: false, verified: false, error: true, message: replyError(acknowledged ? new Error('READBACK_UNVERIFIED') : error) };
        return false;
      } finally {
        if (!closed && state.replies[messageId]) state.replies[messageId].busy = false;
        emit();
      }
    },
  };
}
