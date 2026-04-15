import { useState, useEffect } from 'react';
import { useToast } from '../../context/ToastContext';
import { PageLoader, Badge, DataTable, Modal } from '../../components/ui/Components';
import { getPatientAssignments, assignPatientToDoctor } from '../../services/adminService';

export default function PatientAssignment() {
  const { showToast } = useToast();
  const [data, setData] = useState({ patients: [], doctors: [], assignments: [] });
  const [loading, setLoading] = useState(true);
  const [assignModal, setAssignModal] = useState(null);
  const [selectedDoctor, setSelectedDoctor] = useState('');

  useEffect(() => {
    async function load() {
      try { setData(await getPatientAssignments()); } catch {}
      setLoading(false);
    }
    load();
  }, []);

  const handleAssign = async () => {
    if (!selectedDoctor) { showToast('Please select a doctor.', 'warning'); return; }
    try {
      await assignPatientToDoctor(assignModal.patientId, selectedDoctor);
      const doc = data.doctors.find((d) => d.id === selectedDoctor);
      setData({
        ...data,
        assignments: data.assignments.map((a) =>
          a.patientId === assignModal.patientId
            ? { ...a, doctorId: selectedDoctor, doctorName: doc ? `Dr. ${doc.firstName} ${doc.lastName}` : 'Unknown' }
            : a
        ),
      });
      setAssignModal(null);
      showToast('Patient assignment updated.', 'success');
    } catch { showToast('Failed to assign.', 'error'); }
  };

  if (loading) return <PageLoader />;

  const columns = [
    { key: 'patientName', label: 'Patient', render: (a) => <span className="font-medium text-white">{a.patientName}</span> },
    { key: 'doctorName', label: 'Assigned Doctor', render: (a) => (
      a.doctorId ? <Badge variant="primary">{a.doctorName}</Badge> : <Badge variant="warning">Unassigned</Badge>
    )},
    { key: 'action', label: '', render: (a) => (
      <button onClick={(e) => { e.stopPropagation(); setAssignModal(a); setSelectedDoctor(a.doctorId || ''); }}
        className="text-sm text-primary-400 hover:text-primary-300">
        {a.doctorId ? 'Reassign' : 'Assign'}
      </button>
    )},
  ];

  return (
    <div className="space-y-6 animate-fade-in">
      <div>
        <h1 className="text-2xl font-bold text-white">Patient Assignment</h1>
        <p className="text-surface-400 mt-1">Link patients to their healthcare providers</p>
      </div>

      <DataTable columns={columns} data={data.assignments} emptyMessage="No patients found" />

      <Modal isOpen={!!assignModal} onClose={() => setAssignModal(null)} title="Assign Doctor" size="sm">
        {assignModal && (
          <div className="space-y-4">
            <p className="text-surface-300">Assign <strong className="text-white">{assignModal.patientName}</strong> to a doctor:</p>
            <select className="input-secure" value={selectedDoctor} onChange={(e) => setSelectedDoctor(e.target.value)}>
              <option value="">Select a doctor</option>
              {data.doctors.map((d) => <option key={d.id} value={d.id}>Dr. {d.firstName} {d.lastName} — {d.specialty}</option>)}
            </select>
            <div className="flex gap-3">
              <button onClick={handleAssign} className="btn-primary flex-1">Confirm</button>
              <button onClick={() => setAssignModal(null)} className="btn-secondary">Cancel</button>
            </div>
          </div>
        )}
      </Modal>
    </div>
  );
}
