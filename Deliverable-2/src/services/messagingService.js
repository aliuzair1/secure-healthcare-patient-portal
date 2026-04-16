/**
 * messagingService.js
 *
 * HTTP operations (load, send, mark-read) route through the Flask backend.
 * Real-time delivery keeps the Supabase subscription — Flask doesn't expose
 * a WebSocket endpoint, and the JWT is validated on the Supabase channel
 * using the same token the frontend already holds.
 */
import api from '../config/api';
import { supabase } from '../lib/supabaseClient';

// ---- conversations ----
export async function getConversations() {
  const { data } = await api.get('/messages/conversations');
  return data.conversations ?? [];
}

// ---- send ----
export async function sendMessage(senderId, receiverId, content) {
  const { data } = await api.post('/messages', { senderId, receiverId, content });
  return data;
}

// ---- mark as read ----
export async function markAsRead(messageIds) {
  if (!messageIds?.length) return { message: 'No messages to update.' };
  const { data } = await api.patch('/messages/read', { messageIds });
  return data;
}

// ---- real-time subscription (Supabase only — no HTTP polling needed) ----
export function subscribeToMessages(userId, contactId, onMessage) {
  const channel = supabase
    .channel(`messages:${[userId, contactId].sort().join('-')}`)
    .on(
      'postgres_changes',
      {
        event: 'INSERT',
        schema: 'public',
        table: 'messages',
        filter: `receiver_id=eq.${userId}`,
      },
      (payload) => {
        const msg = payload.new;
        if (msg.sender_id === contactId) {
          onMessage({
            id: msg.id,
            senderId: msg.sender_id,
            receiverId: msg.receiver_id,
            content: msg.content,
            timestamp: msg.created_at,
            status: msg.status,
            encrypted: msg.encrypted,
          });
        }
      },
    )
    .subscribe();

  return () => supabase.removeChannel(channel);
}
