import { useState, useEffect } from 'react';
import { useAuth } from '../../context/AuthContext';
import { useToast } from '../../context/ToastContext';
import { PageLoader, Badge, Modal } from '../../components/ui/Components';
import { getPatientProfile, updatePatientProfile, getPatientMedicalHistory } from '../../services/patientService';
import { formatDate, maskPHI } from '../../utils/formatters';
import { validateName, validatePhone } from '../../utils/validators';

export default function Profile() {
  const { user } = useAuth();
  const { showToast } = useToast();
  const [profile, setProfile] = useState(null);
  const [records, setRecords] = useState([]);
  const [loading, setLoading] = useState(true);
  const [editing, setEditing] = useState(false);
  const [editData, setEditData] = useState({});
  const [showPHI, setShowPHI] = useState({});
  const [saving, setSaving] = useState(false);
  const [recordModal, setRecordModal] = useState(null);

  useEffect(() => {
    async function load() {
      try {
        const [p, r] = await Promise.all([
          getPatientProfile(user.id),
          getPatientMedicalHistory(user.id),
        ]);
        setProfile(p);
        setRecords(r);
      } catch {}
      setLoading(false);
    }
    load();
  }, [user.id]);

  const handleSave = async () => {
    const errors = [];
    if (validateName(editData.firstName, 'First name')) errors.push(validateName(editData.firstName, 'First name'));
    if (validatePhone(editData.phone)) errors.push(validatePhone(editData.phone));
    if (errors.length) { showToast(errors[0], 'error'); return; }
    setSaving(true);
    try {
      await updatePatientProfile(user.id, editData);
      setProfile({ ...profile, ...editData });
      setEditing(false);
      showToast('Profile updated successfully.', 'success');
    } catch { showToast('Failed to update profile.', 'error'); }
    setSaving(false);
  };

  if (loading) return <PageLoader />;

  const fields = [
    { label: 'Full Name', value: `${profile.firstName} ${profile.lastName}`, key: 'name' },
    { label: 'Email', value: profile.email, sensitive: true, key: 'email' },
    { label: 'Phone', value: profile.phone, sensitive: true, key: 'phone' },
    { label: 'Date of Birth', value: formatDate(profile.dob), key: 'dob' },
    { label: 'Gender', value: profile.gender, key: 'gender' },
    { label: 'Blood Type', value: profile.bloodType, key: 'bloodType' },
    { label: 'Address', value: profile.address, sensitive: true, key: 'address' },
    { label: 'Emergency Contact', value: profile.emergencyContact, sensitive: true, key: 'emergencyContact' },
  ];

  return (
    <div className="space-y-6 animate-fade-in">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">Profile & Medical History</h1>
          <p className="text-surface-400 mt-1">Manage your personal information and health records</p>
        </div>
        <button onClick={() => { setEditing(!editing); setEditData({ firstName: profile.firstName, lastName: profile.lastName, phone: profile.phone, address: profile.address, emergencyContact: profile.emergencyContact }); }}
          className={editing ? 'btn-secondary' : 'btn-primary'}>
          {editing ? 'Cancel' : 'Edit Profile'}
        </button>
      </div>

      {/* Profile Card */}
      <div className="card">
        <div className="flex items-center gap-4 mb-6 pb-6 border-b border-surface-700/30">
          <div className="w-16 h-16 rounded-2xl gradient-primary flex items-center justify-center text-white text-xl font-bold">
            {profile.firstName[0]}{profile.lastName[0]}
          </div>
          <div>
            <h2 className="text-xl font-semibold text-white">{profile.firstName} {profile.lastName}</h2>
            <p className="text-sm text-surface-400">Patient ID: {maskPHI(profile.id, 6)}</p>
          </div>
        </div>

        {editing ? (
          <div className="space-y-4">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {[
                { label: 'First Name', key: 'firstName' },
                { label: 'Last Name', key: 'lastName' },
                { label: 'Phone', key: 'phone' },
                { label: 'Address', key: 'address' },
                { label: 'Emergency Contact', key: 'emergencyContact' },
              ].map((f) => (
                <div key={f.key}>
                  <label className="block text-sm font-medium text-surface-300 mb-1">{f.label}</label>
                  <input className="input-secure" value={editData[f.key] || ''} onChange={(e) => setEditData({ ...editData, [f.key]: e.target.value })} />
                </div>
              ))}
            </div>
            <div className="flex gap-3 pt-4">
              <button onClick={handleSave} disabled={saving} className="btn-primary">{saving ? 'Saving…' : 'Save Changes'}</button>
              <button onClick={() => setEditing(false)} className="btn-secondary">Cancel</button>
            </div>
          </div>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {fields.map((f) => (
              <div key={f.key} className="p-3 rounded-xl bg-surface-800/30">
                <p className="text-xs text-surface-500 mb-1">{f.label}</p>
                <div className="flex items-center gap-2">
                  <p className="text-sm text-white font-medium">
                    {f.sensitive && !showPHI[f.key] ? maskPHI(f.value || '', 4) : (f.value || '—')}
                  </p>
                  {f.sensitive && (
                    <button onClick={() => setShowPHI({ ...showPHI, [f.key]: !showPHI[f.key] })}
                      className="text-xs text-primary-400 hover:text-primary-300">
                      {showPHI[f.key] ? 'Hide' : 'Show'}
                    </button>
                  )}
                </div>
              </div>
            ))}
          </div>
        )}

        {/* Allergies */}
        <div className="mt-6 pt-6 border-t border-surface-700/30">
          <h3 className="text-sm font-semibold text-surface-300 mb-3">Known Allergies</h3>
          <div className="flex flex-wrap gap-2">
            {profile.allergies?.length > 0 ? profile.allergies.map((a) => (
              <Badge key={a} variant="danger">{a}</Badge>
            )) : <p className="text-sm text-surface-500">No known allergies</p>}
          </div>
        </div>
      </div>

      {/* Medical History */}
      <div className="card">
        <h2 className="text-lg font-semibold text-white mb-4">Medical History</h2>
        {records.length === 0 ? (
          <p className="text-surface-500 text-sm">No medical records available</p>
        ) : (
          <div className="space-y-3">
            {records.map((rec) => (
              <button key={rec.id} onClick={() => setRecordModal(rec)}
                className="w-full flex items-center justify-between p-4 rounded-xl bg-surface-800/30 border border-surface-700/20 hover:border-primary-500/20 transition-all text-left">
                <div>
                  <p className="text-sm font-medium text-white">{rec.type}</p>
                  <p className="text-xs text-surface-400">{rec.diagnosis} · {formatDate(rec.date)}</p>
                </div>
                <svg className="w-5 h-5 text-surface-500" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" />
                </svg>
              </button>
            ))}
          </div>
        )}
      </div>

      {/* Record Detail Modal */}
      <Modal isOpen={!!recordModal} onClose={() => setRecordModal(null)} title="Medical Record" size="lg">
        {recordModal && (
          <div className="space-y-4">
            <div className="grid grid-cols-2 gap-3">
              <div className="p-3 rounded-xl bg-surface-800/30"><p className="text-xs text-surface-500">Type</p><p className="text-sm text-white">{recordModal.type}</p></div>
              <div className="p-3 rounded-xl bg-surface-800/30"><p className="text-xs text-surface-500">Date</p><p className="text-sm text-white">{formatDate(recordModal.date)}</p></div>
            </div>
            <div className="p-3 rounded-xl bg-surface-800/30"><p className="text-xs text-surface-500">Diagnosis</p><p className="text-sm text-white">{recordModal.diagnosis}</p></div>
            <div className="p-3 rounded-xl bg-surface-800/30"><p className="text-xs text-surface-500">Notes</p><p className="text-sm text-surface-300">{recordModal.notes}</p></div>
            {recordModal.vitals && (
              <div>
                <p className="text-sm font-medium text-surface-300 mb-2">Vitals</p>
                <div className="grid grid-cols-2 md:grid-cols-4 gap-2">
                  {Object.entries(recordModal.vitals).map(([k, v]) => (
                    <div key={k} className="p-2 rounded-lg bg-surface-800/40 text-center">
                      <p className="text-xs text-surface-500 uppercase">{k}</p>
                      <p className="text-sm font-semibold text-primary-400">{v}</p>
                    </div>
                  ))}
                </div>
              </div>
            )}
            {recordModal.followUp && (
              <div className="p-3 rounded-xl bg-primary-500/5 border border-primary-500/10">
                <p className="text-xs text-surface-500">Follow-up Date</p>
                <p className="text-sm text-primary-400">{formatDate(recordModal.followUp)}</p>
              </div>
            )}
          </div>
        )}
      </Modal>
    </div>
  );
}
