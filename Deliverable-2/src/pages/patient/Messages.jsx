import { useState, useEffect, useRef } from 'react';
import { useAuth } from '../../context/AuthContext';
import { useToast } from '../../context/ToastContext';
import { PageLoader } from '../../components/ui/Components';
import { getConversations, sendMessage } from '../../services/messagingService';
import { formatRelativeTime } from '../../utils/formatters';
import { stripTags } from '../../utils/sanitize';
import { containsDangerousContent } from '../../utils/validators';
import { validateFile } from '../../utils/fileValidation';

export default function Messages() {
  const { user } = useAuth();
  const { showToast } = useToast();
  const [conversations, setConversations] = useState([]);
  const [selectedConvo, setSelectedConvo] = useState(null);
  const [newMessage, setNewMessage] = useState('');
  const [loading, setLoading] = useState(true);
  const [sending, setSending] = useState(false);
  const messagesEndRef = useRef(null);

  useEffect(() => {
    async function load() {
      try {
        const convos = await getConversations(user.id);
        setConversations(convos);
        if (convos.length > 0) setSelectedConvo(convos[0]);
      } catch {}
      setLoading(false);
    }
    load();
  }, [user.id]);

  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [selectedConvo?.messages]);

  const handleSend = async () => {
    const cleaned = stripTags(newMessage).trim();
    if (!cleaned) return;
    if (containsDangerousContent(cleaned)) { showToast('Message contains invalid content.', 'error'); return; }
    setSending(true);
    try {
      const msg = await sendMessage(user.id, selectedConvo.contactId, cleaned);
      const updated = conversations.map((c) =>
        c.contactId === selectedConvo.contactId
          ? { ...c, messages: [...c.messages, msg], lastMessage: msg.content, lastTimestamp: msg.timestamp }
          : c
      );
      setConversations(updated);
      setSelectedConvo(updated.find((c) => c.contactId === selectedConvo.contactId));
      setNewMessage('');
    } catch { showToast('Failed to send message.', 'error'); }
    setSending(false);
  };

  const handleFileAttach = (e) => {
    const file = e.target.files?.[0];
    if (!file) return;
    const err = validateFile(file);
    if (err) { showToast(err, 'error'); return; }
    showToast(`File "${file.name}" ready to attach.`, 'info');
  };

  if (loading) return <PageLoader />;

  return (
    <div className="animate-fade-in">
      <div className="mb-6">
        <h1 className="text-2xl font-bold text-white">Secure Messages</h1>
        <p className="text-surface-400 mt-1">End-to-end encrypted communication with your healthcare team</p>
      </div>

      <div className="glass rounded-2xl border border-surface-700/20 flex h-[calc(100vh-220px)] min-h-[500px]">
        {/* Conversation list */}
        <div className={`w-80 border-r border-surface-700/30 flex flex-col flex-shrink-0 ${selectedConvo ? 'hidden md:flex' : 'flex'}`}>
          <div className="p-4 border-b border-surface-700/30">
            <p className="text-sm font-semibold text-surface-300">Conversations</p>
          </div>
          <div className="flex-1 overflow-y-auto">
            {conversations.length === 0 ? (
              <p className="p-4 text-sm text-surface-500">No conversations</p>
            ) : conversations.map((convo) => (
              <button key={convo.contactId} onClick={() => setSelectedConvo(convo)}
                className={`w-full p-4 text-left border-b border-surface-700/10 transition-colors ${selectedConvo?.contactId === convo.contactId ? 'bg-primary-500/5 border-l-2 border-l-primary-500' : 'hover:bg-surface-800/30'}`}>
                <div className="flex items-center justify-between mb-1">
                  <p className="text-sm font-medium text-white truncate">{convo.contactName}</p>
                  {convo.unreadCount > 0 && (
                    <span className="w-5 h-5 rounded-full bg-primary-500 text-white text-xs flex items-center justify-center">{convo.unreadCount}</span>
                  )}
                </div>
                <p className="text-xs text-surface-400 truncate">{convo.lastMessage}</p>
                <p className="text-xs text-surface-600 mt-1">{formatRelativeTime(convo.lastTimestamp)}</p>
              </button>
            ))}
          </div>
        </div>

        {/* Chat area */}
        {selectedConvo ? (
          <div className="flex-1 flex flex-col min-w-0">
            {/* Header */}
            <div className="p-4 border-b border-surface-700/30 flex items-center justify-between">
              <div className="flex items-center gap-3">
                <button className="md:hidden text-surface-400 hover:text-white" onClick={() => setSelectedConvo(null)}>
                  <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 19l-7-7 7-7" /></svg>
                </button>
                <div className="w-9 h-9 rounded-xl bg-primary-500/20 flex items-center justify-center text-primary-400 font-semibold text-sm">
                  {selectedConvo.contactName.split(' ').map(w => w[0]).slice(0, 2).join('')}
                </div>
                <div>
                  <p className="font-medium text-white">{selectedConvo.contactName}</p>
                  <p className="text-xs text-surface-500 capitalize">{selectedConvo.contactRole}</p>
                </div>
              </div>
              <div className="flex items-center gap-1.5 px-2 py-1 rounded-lg bg-emerald-500/10 border border-emerald-500/20">
                <svg className="w-3 h-3 text-emerald-400" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" /></svg>
                <span className="text-xs text-emerald-400">E2E Encrypted</span>
              </div>
            </div>

            {/* Messages */}
            <div className="flex-1 overflow-y-auto p-4 space-y-3">
              {selectedConvo.messages.map((msg) => {
                const isMe = msg.senderId === user.id;
                return (
                  <div key={msg.id} className={`flex ${isMe ? 'justify-end' : 'justify-start'}`}>
                    <div className={`max-w-[70%] p-3 rounded-2xl ${isMe ? 'bg-primary-600/30 border border-primary-500/20 rounded-tr-md' : 'bg-surface-800/60 border border-surface-700/20 rounded-tl-md'}`}>
                      <p className="text-sm text-surface-100">{msg.content}</p>
                      <div className="flex items-center justify-end gap-1 mt-1">
                        <span className="text-[10px] text-surface-500">{formatRelativeTime(msg.timestamp)}</span>
                        {isMe && (
                          <span className={`text-[10px] ${msg.status === 'read' ? 'text-primary-400' : 'text-surface-500'}`}>
                            {msg.status === 'read' ? '✓✓' : msg.status === 'delivered' ? '✓✓' : '✓'}
                          </span>
                        )}
                      </div>
                    </div>
                  </div>
                );
              })}
              <div ref={messagesEndRef} />
            </div>

            {/* Input */}
            <div className="p-4 border-t border-surface-700/30">
              <div className="flex items-end gap-3">
                <label className="cursor-pointer text-surface-400 hover:text-primary-400 transition-colors flex-shrink-0 self-center">
                  <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15.172 7l-6.586 6.586a2 2 0 102.828 2.828l6.414-6.586a4 4 0 00-5.656-5.656l-6.415 6.585a6 6 0 108.486 8.486L20.5 13" /></svg>
                  <input type="file" className="hidden" onChange={handleFileAttach} />
                </label>
                <textarea
                  className="input-secure flex-1 min-h-[42px] max-h-32 resize-none"
                  rows={1} placeholder="Type a secure message…"
                  value={newMessage}
                  onChange={(e) => setNewMessage(e.target.value)}
                  onKeyDown={(e) => { if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); handleSend(); } }}
                />
                <button onClick={handleSend} disabled={sending || !newMessage.trim()}
                  className="btn-primary px-4 py-2.5 flex-shrink-0 self-center disabled:opacity-40">
                  <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 19l9 2-9-18-9 18 9-2zm0 0v-8" /></svg>
                </button>
              </div>
            </div>
          </div>
        ) : (
          <div className="flex-1 flex items-center justify-center">
            <p className="text-surface-500">Select a conversation</p>
          </div>
        )}
      </div>
    </div>
  );
}
