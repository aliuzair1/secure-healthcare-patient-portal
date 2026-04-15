import { useState, useEffect } from 'react';
import { useAuth } from '../../context/AuthContext';
import { PageLoader, DataTable, Badge } from '../../components/ui/Components';
import { getAssignedPatients } from '../../services/doctorService';
import { formatDate } from '../../utils/formatters';

export default function PatientRoster() {
  const { user } = useAuth();
  const [patients, setPatients] = useState([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState('');

  useEffect(() => {
    async function load() {
      try { setPatients(await getAssignedPatients(user.id)); } catch {}
      setLoading(false);
    }
    load();
  }, [user.id]);

  if (loading) return <PageLoader />;

  const filtered = patients.filter((p) =>
    `${p.firstName} ${p.lastName}`.toLowerCase().includes(search.toLowerCase()) ||
    p.email.toLowerCase().includes(search.toLowerCase())
  );

  const columns = [
    { key: 'name', label: 'Patient', render: (p) => (
      <div className="flex items-center gap-3">
        <div className="w-8 h-8 rounded-lg bg-primary-500/20 flex items-center justify-center text-primary-400 text-xs font-bold">{p.firstName[0]}{p.lastName[0]}</div>
        <div><p className="font-medium text-white">{p.firstName} {p.lastName}</p><p className="text-xs text-surface-500">{p.email}</p></div>
      </div>
    )},
    { key: 'gender', label: 'Gender' },
    { key: 'dob', label: 'DOB', render: (p) => formatDate(p.dob) },
    { key: 'bloodType', label: 'Blood Type', render: (p) => <Badge variant="info">{p.bloodType}</Badge> },
    { key: 'allergies', label: 'Allergies', render: (p) => (
      <div className="flex flex-wrap gap-1">{p.allergies?.map((a) => <Badge key={a} variant="danger">{a}</Badge>) || '—'}</div>
    )},
    { key: 'status', label: 'Status', render: (p) => <Badge variant={p.isActive ? 'success' : 'danger'}>{p.isActive ? 'Active' : 'Inactive'}</Badge> },
  ];

  return (
    <div className="space-y-6 animate-fade-in">
      <div>
        <h1 className="text-2xl font-bold text-white">Patient Roster</h1>
        <p className="text-surface-400 mt-1">Patients assigned to your care</p>
      </div>
      <div className="flex items-center gap-4">
        <div className="relative flex-1 max-w-md">
          <svg className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-surface-400" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" /></svg>
          <input className="input-secure pl-10" placeholder="Search patients…" value={search} onChange={(e) => setSearch(e.target.value)} />
        </div>
        <Badge variant="primary">{filtered.length} patient{filtered.length !== 1 ? 's' : ''}</Badge>
      </div>
      <DataTable columns={columns} data={filtered} emptyMessage="No patients found" />
    </div>
  );
}
