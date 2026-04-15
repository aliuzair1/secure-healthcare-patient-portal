import { useState, useEffect } from 'react';
import { useToast } from '../../context/ToastContext';
import { PageLoader, Badge, Modal } from '../../components/ui/Components';
import { getPendingDoctors, approveDoctor, rejectDoctor } from '../../services/adminService';
import { formatDate } from '../../utils/formatters';

export default function DoctorApprovals() {
  const { showToast } = useToast();
  const [pending, setPending] = useState([]);
  const [loading, setLoading] = useState(true);
  const [rejectModal, setRejectModal] = useState(null);
  const [rejectReason, setRejectReason] = useState('');
  const [history, setHistory] = useState([]);

  useEffect(() => {
    async function load() {
      try { setPending(await getPendingDoctors()); } catch {}
      setLoading(false);
    }
    load();
  }, []);

  const handleApprove = async (doc) => {
    try {
      await approveDoctor(doc.id);
      setPending(pending.filter((d) => d.id !== doc.id));
      setHistory([{ ...doc, decision: 'approved', decidedAt: new Date().toISOString() }, ...history]);
      showToast(`Dr. ${doc.firstName} ${doc.lastName} approved.`, 'success');
    } catch { showToast('Failed to approve.', 'error'); }
  };

  const handleReject = async () => {
    if (!rejectReason.trim()) { showToast('Please provide a reason.', 'warning'); return; }
    try {
      await rejectDoctor(rejectModal.id, rejectReason);
      setPending(pending.filter((d) => d.id !== rejectModal.id));
      setHistory([{ ...rejectModal, decision: 'rejected', reason: rejectReason, decidedAt: new Date().toISOString() }, ...history]);
      setRejectModal(null);
      setRejectReason('');
      showToast('Doctor account rejected.', 'info');
    } catch { showToast('Failed to reject.', 'error'); }
  };

  if (loading) return <PageLoader />;

  return (
    <div className="space-y-6 animate-fade-in">
      <div>
        <h1 className="text-2xl font-bold text-white">Doctor Approvals</h1>
        <p className="text-surface-400 mt-1">Review and approve doctor registrations</p>
      </div>

      {/* Pending */}
      <div>
        <h2 className="text-lg font-semibold text-white mb-4">Pending Approvals <Badge variant="warning">{pending.length}</Badge></h2>
        {pending.length === 0 ? (
          <div className="card text-center py-12"><p className="text-surface-500">No pending approvals</p></div>
        ) : (
          <div className="space-y-4">
            {pending.map((doc) => (
              <div key={doc.id} className="card flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
                <div className="flex items-center gap-4">
                  <div className="w-12 h-12 rounded-xl bg-amber-500/10 flex items-center justify-center text-amber-400 font-bold">{doc.firstName[0]}{doc.lastName[0]}</div>
                  <div>
                    <p className="font-semibold text-white">Dr. {doc.firstName} {doc.lastName}</p>
                    <p className="text-sm text-surface-400">{doc.specialty} · License: {doc.licenseNumber}</p>
                    <p className="text-xs text-surface-500">Applied: {formatDate(doc.createdAt)} · {doc.email}</p>
                  </div>
                </div>
                <div className="flex gap-3">
                  <button onClick={() => handleApprove(doc)} className="btn-primary text-sm px-4 py-2">Approve</button>
                  <button onClick={() => setRejectModal(doc)} className="btn-danger text-sm px-4 py-2">Reject</button>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Decision History */}
      {history.length > 0 && (
        <div>
          <h2 className="text-lg font-semibold text-white mb-4">Decision History</h2>
          <div className="space-y-3">
            {history.map((h, i) => (
              <div key={i} className="flex items-center justify-between p-3 rounded-xl bg-surface-800/30 border border-surface-700/20">
                <div>
                  <p className="text-sm font-medium text-white">Dr. {h.firstName} {h.lastName} — {h.specialty}</p>
                  {h.reason && <p className="text-xs text-surface-400">Reason: {h.reason}</p>}
                </div>
                <div className="flex items-center gap-2">
                  <Badge variant={h.decision === 'approved' ? 'success' : 'danger'}>{h.decision}</Badge>
                  <span className="text-xs text-surface-500">{formatDate(h.decidedAt)}</span>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Reject Modal */}
      <Modal isOpen={!!rejectModal} onClose={() => setRejectModal(null)} title="Reject Doctor Account" size="sm">
        <div className="space-y-4">
          <p className="text-surface-300">Reject <strong className="text-white">Dr. {rejectModal?.firstName} {rejectModal?.lastName}</strong>?</p>
          <div>
            <label className="block text-sm font-medium text-surface-300 mb-1.5">Reason <span className="text-red-400">*</span></label>
            <textarea className="input-secure h-24 resize-none" value={rejectReason} onChange={(e) => setRejectReason(e.target.value)} placeholder="Provide rejection reason…" />
          </div>
          <div className="flex gap-3">
            <button onClick={handleReject} className="btn-danger flex-1">Confirm Reject</button>
            <button onClick={() => setRejectModal(null)} className="btn-secondary">Cancel</button>
          </div>
        </div>
      </Modal>
    </div>
  );
}
