import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../../context/AuthContext';
import { StatCard, PageLoader } from '../../components/ui/Components';
import { getSystemStats } from '../../services/adminService';

export default function AdminDashboard() {
  const { user } = useAuth();
  const navigate = useNavigate();
  const [stats, setStats] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    async function load() {
      try { setStats(await getSystemStats()); } catch {}
      setLoading(false);
    }
    load();
  }, []);

  if (loading) return <PageLoader />;

  return (
    <div className="space-y-6 animate-fade-in">
      <div>
        <h1 className="text-2xl font-bold text-white">Admin Dashboard</h1>
        <p className="text-surface-400 mt-1">System overview and management</p>
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard icon={<svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M17 20h5v-2a3 3 0 00-5.356-1.857M17 20H7m10 0v-2c0-.656-.126-1.283-.356-1.857M7 20H2v-2a3 3 0 015.356-1.857M7 20v-2c0-.656.126-1.283.356-1.857m0 0a5.002 5.002 0 019.288 0M15 7a3 3 0 11-6 0 3 3 0 016 0z" /></svg>}
          label="Total Patients" value={stats?.totalPatients || 0} />
        <StatCard icon={<svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5.121 17.804A13.937 13.937 0 0112 16c2.5 0 4.847.655 6.879 1.804M15 10a3 3 0 11-6 0 3 3 0 016 0zm6 2a9 9 0 11-18 0 9 9 0 0118 0z" /></svg>}
          label="Active Doctors" value={stats?.activeDoctors || 0} />
        <StatCard icon={<svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z" /></svg>}
          label="Pending Approvals" value={stats?.pendingApprovals || 0} trend={stats?.pendingApprovals > 0 ? 'Action needed' : undefined} />
        <StatCard icon={<svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" /></svg>}
          label="System Health" value="Healthy" />
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        {[
          { label: 'User Management', desc: 'Manage all user accounts', path: '/admin/users', icon: 'M12 4.354a4 4 0 110 5.292M15 21H3v-1a6 6 0 0112 0v1zm0 0h6v-1a6 6 0 00-9-5.197M13 7a4 4 0 11-8 0 4 4 0 018 0z', color: 'from-primary-600 to-primary-700' },
          { label: 'Doctor Approvals', desc: 'Review pending approvals', path: '/admin/approvals', icon: 'M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z', color: 'from-emerald-600 to-emerald-700' },
          { label: 'Patient Assignment', desc: 'Link patients to doctors', path: '/admin/assignments', icon: 'M13.828 10.172a4 4 0 00-5.656 0l-4 4a4 4 0 105.656 5.656l1.102-1.101m-.758-4.899a4 4 0 005.656 0l4-4a4 4 0 00-5.656-5.656l-1.1 1.1', color: 'from-blue-600 to-blue-700' },
          { label: 'Scheduling', desc: 'Configure appointment slots', path: '/admin/scheduling', icon: 'M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z', color: 'from-violet-600 to-violet-700' },
        ].map((item) => (
          <button key={item.path} onClick={() => navigate(item.path)} className="card-hover text-left group">
            <div className={`w-10 h-10 rounded-xl bg-gradient-to-br ${item.color} flex items-center justify-center mb-3 group-hover:scale-110 transition-transform`}>
              <svg className="w-5 h-5 text-white" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d={item.icon} /></svg>
            </div>
            <h3 className="text-white font-semibold">{item.label}</h3>
            <p className="text-sm text-surface-400 mt-1">{item.desc}</p>
          </button>
        ))}
      </div>

      {/* Activity feed */}
      <div className="card">
        <h2 className="text-lg font-semibold text-white mb-4">Recent Activity</h2>
        <div className="space-y-3">
          {[
            { action: 'New patient registration', detail: 'Maria Garcia registered as a patient', time: '2 hours ago', color: 'bg-emerald-500' },
            { action: 'Doctor approval pending', detail: 'Dr. Anna Kowalski — Neurology', time: '1 day ago', color: 'bg-amber-500' },
            { action: 'Patient assigned', detail: 'James Wilson assigned to Dr. Emily Brooks', time: '3 days ago', color: 'bg-blue-500' },
            { action: 'System configuration updated', detail: 'Appointment slot duration changed to 30 minutes', time: '1 week ago', color: 'bg-primary-500' },
          ].map((activity, i) => (
            <div key={i} className="flex items-center gap-3 p-3 rounded-xl bg-surface-800/30">
              <div className={`w-2 h-2 rounded-full ${activity.color} flex-shrink-0`} />
              <div className="flex-1 min-w-0">
                <p className="text-sm font-medium text-white">{activity.action}</p>
                <p className="text-xs text-surface-400">{activity.detail}</p>
              </div>
              <span className="text-xs text-surface-500 flex-shrink-0">{activity.time}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
