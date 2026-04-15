import { useState, useEffect } from 'react';
import { useAuth } from '../../context/AuthContext';
import { useToast } from '../../context/ToastContext';
import { PageLoader } from '../../components/ui/Components';
import { getAssignedPatients, addVisitNote, issuePrescription } from '../../services/doctorService';
import { validateRequired } from '../../utils/validators';

export default function ClinicalUpdates() {
  const { user } = useAuth();
  const { showToast } = useToast();
  const [patients, setPatients] = useState([]);
  const [loading, setLoading] = useState(true);
  const [tab, setTab] = useState('note');
  const [saving, setSaving] = useState(false);

  const [note, setNote] = useState({ patientId: '', diagnosis: '', notes: '', followUp: '', bp: '', hr: '', temp: '', weight: '' });
  const [rx, setRx] = useState({ patientId: '', medication: '', dosage: '', frequency: '', duration: '', instructions: '' });

  useEffect(() => {
    async function load() {
      try {
        const pts = await getAssignedPatients(user.id);
        setPatients(pts);
        if (pts.length > 0) { setNote((n) => ({ ...n, patientId: pts[0].id })); setRx((r) => ({ ...r, patientId: pts[0].id })); }
      } catch {}
      setLoading(false);
    }
    load();
  }, [user.id]);

  const handleSaveNote = async (e) => {
    e.preventDefault();
    if (validateRequired(note.diagnosis, 'Diagnosis') || validateRequired(note.notes, 'Notes')) {
      showToast('Please fill in all required fields.', 'warning'); return;
    }
    setSaving(true);
    try {
      await addVisitNote({ ...note, doctorId: user.id, vitals: { bp: note.bp, hr: note.hr, temp: note.temp, weight: note.weight } });
      showToast('Visit note saved successfully.', 'success');
      setNote({ ...note, diagnosis: '', notes: '', followUp: '', bp: '', hr: '', temp: '', weight: '' });
    } catch { showToast('Failed to save note.', 'error'); }
    setSaving(false);
  };

  const handleSaveRx = async (e) => {
    e.preventDefault();
    if (validateRequired(rx.medication, 'Medication') || validateRequired(rx.dosage, 'Dosage')) {
      showToast('Please fill in all required fields.', 'warning'); return;
    }
    setSaving(true);
    try {
      await issuePrescription({ ...rx, doctorId: user.id, startDate: new Date().toISOString().split('T')[0] });
      showToast('Prescription issued successfully.', 'success');
      setRx({ ...rx, medication: '', dosage: '', frequency: '', duration: '', instructions: '' });
    } catch { showToast('Failed to issue prescription.', 'error'); }
    setSaving(false);
  };

  if (loading) return <PageLoader />;

  const Field = ({ label, value, onChange, required, type = 'text', placeholder, rows }) => (
    <div>
      <label className="block text-sm font-medium text-surface-300 mb-1.5">{label} {required && <span className="text-red-400">*</span>}</label>
      {rows ? (
        <textarea className="input-secure resize-none" rows={rows} value={value} onChange={(e) => onChange(e.target.value)} placeholder={placeholder} />
      ) : (
        <input type={type} className="input-secure" value={value} onChange={(e) => onChange(e.target.value)} placeholder={placeholder} />
      )}
    </div>
  );

  return (
    <div className="space-y-6 animate-fade-in">
      <div>
        <h1 className="text-2xl font-bold text-white">Clinical Updates</h1>
        <p className="text-surface-400 mt-1">Add visit notes and issue prescriptions</p>
      </div>

      <div className="flex gap-1 p-1 rounded-xl bg-surface-800/40 border border-surface-700/20 w-fit">
        <button onClick={() => setTab('note')} className={`px-4 py-2 rounded-lg text-sm font-medium transition-all ${tab === 'note' ? 'bg-primary-500/20 text-primary-400' : 'text-surface-400 hover:text-white'}`}>Visit Note</button>
        <button onClick={() => setTab('rx')} className={`px-4 py-2 rounded-lg text-sm font-medium transition-all ${tab === 'rx' ? 'bg-primary-500/20 text-primary-400' : 'text-surface-400 hover:text-white'}`}>Prescription</button>
      </div>

      {tab === 'note' ? (
        <form onSubmit={handleSaveNote} className="card space-y-5 max-w-2xl">
          <h2 className="text-lg font-semibold text-white">New Visit Note</h2>
          <div>
            <label className="block text-sm font-medium text-surface-300 mb-1.5">Patient <span className="text-red-400">*</span></label>
            <select className="input-secure" value={note.patientId} onChange={(e) => setNote({ ...note, patientId: e.target.value })}>
              {patients.map((p) => <option key={p.id} value={p.id}>{p.firstName} {p.lastName}</option>)}
            </select>
          </div>
          <Field label="Diagnosis" value={note.diagnosis} onChange={(v) => setNote({ ...note, diagnosis: v })} required placeholder="Primary diagnosis" />
          <Field label="Clinical Notes" value={note.notes} onChange={(v) => setNote({ ...note, notes: v })} required placeholder="Detailed visit notes…" rows={4} />
          <div>
            <label className="block text-sm font-medium text-surface-300 mb-3">Vitals</label>
            <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
              <Field label="BP" value={note.bp} onChange={(v) => setNote({ ...note, bp: v })} placeholder="120/80" />
              <Field label="HR (bpm)" value={note.hr} onChange={(v) => setNote({ ...note, hr: v })} placeholder="72" />
              <Field label="Temp" value={note.temp} onChange={(v) => setNote({ ...note, temp: v })} placeholder="98.6°F" />
              <Field label="Weight" value={note.weight} onChange={(v) => setNote({ ...note, weight: v })} placeholder="150 lbs" />
            </div>
          </div>
          <Field label="Follow-up Date" value={note.followUp} onChange={(v) => setNote({ ...note, followUp: v })} type="date" />
          <button type="submit" disabled={saving} className="btn-primary">{saving ? 'Saving…' : 'Save Visit Note'}</button>
        </form>
      ) : (
        <form onSubmit={handleSaveRx} className="card space-y-5 max-w-2xl">
          <h2 className="text-lg font-semibold text-white">Issue Prescription</h2>
          <div>
            <label className="block text-sm font-medium text-surface-300 mb-1.5">Patient <span className="text-red-400">*</span></label>
            <select className="input-secure" value={rx.patientId} onChange={(e) => setRx({ ...rx, patientId: e.target.value })}>
              {patients.map((p) => <option key={p.id} value={p.id}>{p.firstName} {p.lastName}</option>)}
            </select>
          </div>
          <Field label="Medication" value={rx.medication} onChange={(v) => setRx({ ...rx, medication: v })} required placeholder="e.g., Amoxicillin 500mg" />
          <div className="grid grid-cols-2 gap-4">
            <Field label="Dosage" value={rx.dosage} onChange={(v) => setRx({ ...rx, dosage: v })} required placeholder="1 tablet" />
            <Field label="Frequency" value={rx.frequency} onChange={(v) => setRx({ ...rx, frequency: v })} placeholder="Twice daily" />
          </div>
          <Field label="Duration" value={rx.duration} onChange={(v) => setRx({ ...rx, duration: v })} placeholder="e.g., 14 days" />
          <Field label="Instructions" value={rx.instructions} onChange={(v) => setRx({ ...rx, instructions: v })} placeholder="Take with food…" rows={3} />
          <button type="submit" disabled={saving} className="btn-primary">{saving ? 'Issuing…' : 'Issue Prescription'}</button>
        </form>
      )}
    </div>
  );
}
