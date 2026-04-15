import { useState, useEffect } from 'react';
import { useAuth } from '../../context/AuthContext';
import { PageLoader, Badge, Modal } from '../../components/ui/Components';
import { getAssignedPatients, getPatientFullRecord } from '../../services/doctorService';
import { formatDate } from '../../utils/formatters';

export default function PatientRecords() {
  const { user } = useAuth();
  const [patients, setPatients] = useState([]);
  const [selectedPatient, setSelectedPatient] = useState(null);
  const [record, setRecord] = useState(null);
  const [loading, setLoading] = useState(true);
  const [loadingRecord, setLoadingRecord] = useState(false);
  const [tab, setTab] = useState('history');

  useEffect(() => {
    async function load() {
      try { setPatients(await getAssignedPatients(user.id)); } catch {}
      setLoading(false);
    }
    load();
  }, [user.id]);

  const loadRecord = async (patient) => {
    setSelectedPatient(patient);
    setLoadingRecord(true);
    try {
      const r = await getPatientFullRecord(patient.id, user.id);
      setRecord(r);
    } catch {}
    setLoadingRecord(false);
  };

  if (loading) return <PageLoader />;

  return (
    <div className="space-y-6 animate-fade-in">
      <div>
        <h1 className="text-2xl font-bold text-white">Patient Records</h1>
        <p className="text-surface-400 mt-1">View detailed records for your assigned patients</p>
      </div>

      {!selectedPatient ? (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {patients.map((p) => (
            <button key={p.id} onClick={() => loadRecord(p)} className="card-hover text-left">
              <div className="flex items-center gap-3 mb-3">
                <div className="w-10 h-10 rounded-xl bg-primary-500/20 flex items-center justify-center text-primary-400 font-bold text-sm">{p.firstName[0]}{p.lastName[0]}</div>
                <div><p className="font-medium text-white">{p.firstName} {p.lastName}</p><p className="text-xs text-surface-400">{p.gender} · {p.bloodType}</p></div>
              </div>
              <div className="flex gap-1 flex-wrap">{p.allergies?.map((a) => <Badge key={a} variant="danger">{a}</Badge>)}</div>
            </button>
          ))}
        </div>
      ) : (
        <div>
          <button onClick={() => { setSelectedPatient(null); setRecord(null); }}
            className="flex items-center gap-1 text-sm text-surface-400 hover:text-white transition-colors mb-4">
            <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 19l-7-7 7-7" /></svg>
            Back to patients
          </button>

          {loadingRecord ? <PageLoader /> : record && (
            <div className="space-y-6">
              {/* Patient header */}
              <div className="card flex items-center gap-4">
                <div className="w-14 h-14 rounded-2xl gradient-primary flex items-center justify-center text-white text-lg font-bold">
                  {selectedPatient.firstName[0]}{selectedPatient.lastName[0]}
                </div>
                <div>
                  <h2 className="text-xl font-semibold text-white">{selectedPatient.firstName} {selectedPatient.lastName}</h2>
                  <p className="text-sm text-surface-400">{selectedPatient.gender} · DOB: {formatDate(selectedPatient.dob)} · Blood: {selectedPatient.bloodType}</p>
                </div>
              </div>

              {/* Tabs */}
              <div className="flex gap-1 p-1 rounded-xl bg-surface-800/40 border border-surface-700/20 w-fit">
                {['history', 'reports', 'prescriptions', 'appointments'].map((t) => (
                  <button key={t} onClick={() => setTab(t)} className={`px-4 py-2 rounded-lg text-sm font-medium capitalize transition-all ${tab === t ? 'bg-primary-500/20 text-primary-400' : 'text-surface-400 hover:text-white'}`}>
                    {t}
                  </button>
                ))}
              </div>

              {/* Tab content */}
              {tab === 'history' && (
                <div className="space-y-3">
                  {record.medicalHistory.map((r) => (
                    <div key={r.id} className="card">
                      <div className="flex items-center justify-between mb-2">
                        <Badge variant="info">{r.type}</Badge>
                        <span className="text-xs text-surface-500">{formatDate(r.date)}</span>
                      </div>
                      <p className="text-sm font-medium text-white mb-1">{r.diagnosis}</p>
                      <p className="text-sm text-surface-400">{r.notes}</p>
                      {r.vitals && (
                        <div className="flex gap-3 mt-3 flex-wrap">
                          {Object.entries(r.vitals).map(([k, v]) => (
                            <span key={k} className="px-2 py-1 rounded-lg bg-surface-800/40 text-xs text-surface-300">
                              <span className="text-surface-500 uppercase">{k}:</span> {v}
                            </span>
                          ))}
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              )}
              {tab === 'reports' && (
                <div className="space-y-3">
                  {record.reports.map((r) => (
                    <div key={r.id} className="card">
                      <div className="flex items-center justify-between mb-2">
                        <p className="font-medium text-white">{r.title}</p>
                        <span className="text-xs text-surface-500">{formatDate(r.date)}</span>
                      </div>
                      <div className="overflow-x-auto">
                        <table className="w-full text-sm">
                          <thead><tr className="text-left text-xs text-surface-500"><th className="pr-4 py-1">Test</th><th className="pr-4 py-1">Value</th><th className="pr-4 py-1">Range</th><th className="py-1">Flag</th></tr></thead>
                          <tbody>{r.results.map((res, i) => (
                            <tr key={i}><td className="pr-4 py-1 text-surface-300">{res.test}</td><td className="pr-4 py-1 text-white font-medium">{res.value} {res.unit}</td><td className="pr-4 py-1 text-surface-400">{res.range}</td><td className="py-1"><Badge variant={res.flag === 'normal' ? 'success' : 'danger'}>{res.flag}</Badge></td></tr>
                          ))}</tbody>
                        </table>
                      </div>
                    </div>
                  ))}
                </div>
              )}
              {tab === 'prescriptions' && (
                <div className="space-y-3">
                  {record.prescriptions.map((rx) => (
                    <div key={rx.id} className="card flex items-center justify-between">
                      <div>
                        <p className="font-medium text-white">{rx.medication}</p>
                        <p className="text-sm text-surface-400">{rx.dosage} · {rx.frequency}</p>
                        <p className="text-xs text-surface-500 mt-1">{rx.instructions}</p>
                      </div>
                      <Badge variant={rx.status === 'active' ? 'success' : 'default'}>{rx.status}</Badge>
                    </div>
                  ))}
                </div>
              )}
              {tab === 'appointments' && (
                <div className="space-y-3">
                  {record.appointments.map((a) => (
                    <div key={a.id} className="card flex items-center justify-between">
                      <div><p className="font-medium text-white">{a.type}</p><p className="text-sm text-surface-400">{formatDate(a.date)} at {a.time}</p></div>
                      <Badge variant={a.status === 'upcoming' ? 'primary' : a.status === 'completed' ? 'success' : 'danger'}>{a.status}</Badge>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
