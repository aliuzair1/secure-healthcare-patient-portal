import { supabase } from '../lib/supabaseClient';

export async function getConversations(userId) {
  const { data: messages, error } = await supabase
    .from('messages')
    .select('*')
    .or(`sender_id.eq.${userId},receiver_id.eq.${userId}`)
    .order('created_at', { ascending: true });

  if (error) throw { status: 500, message: 'Failed to load conversations.' };

  const allMessages = messages ?? [];

  // Collect unique contact IDs
  const contactIds = [
    ...new Set(
      allMessages.map((m) => (m.sender_id === userId ? m.receiver_id : m.sender_id))
    ),
  ];

  if (contactIds.length === 0) return [];

  // Fetch contact profiles in one query
  const { data: contacts } = await supabase
    .from('profiles')
    .select('id, role, first_name, last_name')
    .in('id', contactIds);

  const contactMap = Object.fromEntries((contacts ?? []).map((c) => [c.id, c]));

  return contactIds.map((contactId) => {
    const contact = contactMap[contactId];
    const thread = allMessages.filter(
      (m) =>
        (m.sender_id === userId && m.receiver_id === contactId) ||
        (m.sender_id === contactId && m.receiver_id === userId)
    );
    const lastMsg = thread[thread.length - 1];
    const unread = thread.filter(
      (m) => m.receiver_id === userId && m.status !== 'read'
    ).length;

    return {
      contactId,
      contactName: contact
        ? contact.role === 'doctor'
          ? `Dr. ${contact.first_name} ${contact.last_name}`
          : `${contact.first_name} ${contact.last_name}`
        : 'Unknown',
      contactRole: contact?.role ?? 'unknown',
      lastMessage: lastMsg?.content ?? '',
      lastTimestamp: lastMsg?.created_at ?? '',
      unreadCount: unread,
      messages: thread.map(mapMessage),
    };
  });
}

export async function sendMessage(senderId, receiverId, content) {
  const { data, error } = await supabase
    .from('messages')
    .insert({
      sender_id: senderId,
      receiver_id: receiverId,
      content,
      status: 'sent',
      encrypted: true,
    })
    .select()
    .single();

  if (error) throw { status: 500, message: 'Failed to send message.' };
  return mapMessage(data);
}

export async function markAsRead(messageIds) {
  if (!messageIds?.length) return { message: 'No messages to update.' };

  const { error } = await supabase
    .from('messages')
    .update({ status: 'read' })
    .in('id', messageIds);

  if (error) throw { status: 500, message: 'Failed to mark messages as read.' };
  return { message: 'Messages marked as read.' };
}

// Subscribe to real-time messages for a conversation thread.
// Returns an unsubscribe function — call it on component unmount.
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
          onMessage(mapMessage(msg));
        }
      }
    )
    .subscribe();

  return () => supabase.removeChannel(channel);
}

function mapMessage(row) {
  return {
    id: row.id,
    senderId: row.sender_id,
    receiverId: row.receiver_id,
    content: row.content,
    timestamp: row.created_at,
    status: row.status,
    encrypted: row.encrypted,
  };
}
