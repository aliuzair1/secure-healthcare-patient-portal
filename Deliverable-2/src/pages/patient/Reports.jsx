import { useState, useEffect } from 'react';
import { useAuth } from '../../context/AuthContext';
import { PageLoader, Badge, DataTable, Modal } from '../../components/ui/Components';
import { getPatientReports, getPatientPrescriptions } from '../../services/patientService';
import { formatDate } from '../../utils/formatters';

export default function Reports() {
  const { user } = useAuth();
  const [reports, setReports] = useState([]);
  const [prescriptions, setPrescriptions] = useState([]);
  const [loading, setLoading] = useState(true);
  const [tab, setTab] = useState('reports');
  const [selectedReport, setSelectedReport] = useState(null);

  useEffect(() => {
    async function load() {
      try {
        const [r, p] = await Promise.all([getPatientReports(user.id), getPatientPrescriptions(user.id)]);
        setReports(r);
        setPrescriptions(p);
      } catch {}
      setLoading(false);
    }
    load();
  }, [user.id]);

  if (loading) return <PageLoader />;

  const reportColumns = [
    { key: 'title', label: 'Report', render: (r) => <span className="font-medium text-white">{r.title}</span> },
    { key: 'category', label: 'Category', render: (r) => <Badge variant="info">{r.category}</Badge> },
    { key: 'date', label: 'Date', render: (r) => formatDate(r.date) },
    { key: 'status', label: 'Status', render: (r) => <Badge variant={r.status === 'completed' ? 'success' : 'warning'}>{r.status}</Badge> },
    { key: 'action', label: '', render: (r) => (
      <button onClick={(e) => { e.stopPropagation(); setSelectedReport(r); }} className="text-primary-400 hover:text-primary-300 text-sm">View</button>
    )},
  ];

  const rxColumns = [
    { key: 'medication', label: 'Medication', render: (r) => <span className="font-medium text-white">{r.medication}</span> },
    { key: 'dosage', label: 'Dosage', render: (r) => r.dosage },
    { key: 'frequency', label: 'Frequency', render: (r) => r.frequency },
    { key: 'status', label: 'Status', render: (r) => <Badge variant={r.status === 'active' ? 'success' : 'default'}>{r.status}</Badge> },
    { key: 'endDate', label: 'Until', render: (r) => formatDate(r.endDate) },
    { key: 'refills', label: 'Refills', render: (r) => <span className="text-primary-400">{r.refillsRemaining}</span> },
  ];

  return (
    <div className="space-y-6 animate-fade-in">
      <div>
        <h1 className="text-2xl font-bold text-white">Reports & Prescriptions</h1>
        <p className="text-surface-400 mt-1">Access your lab results and active medications</p>
      </div>

      {/* Tabs */}
      <div className="flex gap-1 p-1 rounded-xl bg-surface-800/40 border border-surface-700/20 w-fit">
        {[{ key: 'reports', label: 'Lab Reports', count: reports.length }, { key: 'prescriptions', label: 'Prescriptions', count: prescriptions.length }].map((t) => (
          <button key={t.key} onClick={() => setTab(t.key)}
            className={`px-4 py-2 rounded-lg text-sm font-medium transition-all ${tab === t.key ? 'bg-primary-500/20 text-primary-400' : 'text-surface-400 hover:text-white'}`}>
            {t.label} <span className="ml-1 text-xs opacity-60">({t.count})</span>
          </button>
        ))}
      </div>

      {tab === 'reports' ? (
        <DataTable columns={reportColumns} data={reports} emptyMessage="No lab reports available" onRowClick={setSelectedReport} />
      ) : (
        <DataTable columns={rxColumns} data={prescriptions} emptyMessage="No prescriptions available" />
      )}

      {/* Report Detail Modal */}
      <Modal isOpen={!!selectedReport} onClose={() => setSelectedReport(null)} title={selectedReport?.title || 'Report'} size="lg">
        {selectedReport && (
          <div className="space-y-4">
            <div className="grid grid-cols-2 gap-3">
              <div className="p-3 rounded-xl bg-surface-800/30"><p className="text-xs text-surface-500">Category</p><p className="text-sm text-white">{selectedReport.category}</p></div>
              <div className="p-3 rounded-xl bg-surface-800/30"><p className="text-xs text-surface-500">Date</p><p className="text-sm text-white">{formatDate(selectedReport.date)}</p></div>
            </div>
            <div className="overflow-x-auto rounded-xl border border-surface-700/30">
              <table className="w-full">
                <thead>
                  <tr className="border-b border-surface-700/30 bg-surface-800/30">
                    <th className="px-4 py-2 text-left text-xs font-semibold text-surface-400">Test</th>
                    <th className="px-4 py-2 text-left text-xs font-semibold text-surface-400">Result</th>
                    <th className="px-4 py-2 text-left text-xs font-semibold text-surface-400">Unit</th>
                    <th className="px-4 py-2 text-left text-xs font-semibold text-surface-400">Range</th>
                    <th className="px-4 py-2 text-left text-xs font-semibold text-surface-400">Flag</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-surface-700/20">
                  {selectedReport.results?.map((r, i) => (
                    <tr key={i}>
                      <td className="px-4 py-2 text-sm text-white">{r.test}</td>
                      <td className="px-4 py-2 text-sm font-semibold text-white">{r.value}</td>
                      <td className="px-4 py-2 text-sm text-surface-400">{r.unit}</td>
                      <td className="px-4 py-2 text-sm text-surface-400">{r.range}</td>
                      <td className="px-4 py-2"><Badge variant={r.flag === 'normal' ? 'success' : 'danger'}>{r.flag}</Badge></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <button className="btn-secondary flex items-center gap-2">
              <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 10v6m0 0l-3-3m3 3l3-3m2 8H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" /></svg>
              Download PDF
            </button>
          </div>
        )}
      </Modal>
    </div>
  );
}
