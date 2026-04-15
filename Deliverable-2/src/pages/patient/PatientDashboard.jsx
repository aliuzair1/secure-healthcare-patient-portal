import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../../context/AuthContext';
import { StatCard, PageLoader, Badge } from '../../components/ui/Components';
import { getPatientAppointments } from '../../services/patientService';
import { getConversations } from '../../services/messagingService';
import { formatDate } from '../../utils/formatters';

export default function PatientDashboard() {
  const { user } = useAuth();
  const navigate = useNavigate();
  const [appointments, setAppointments] = useState([]);
  const [unreadMessages, setUnreadMessages] = useState(0);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    async function load() {
      try {
        const [appts, convos] = await Promise.all([
          getPatientAppointments(user.id),
          getConversations(user.id),
        ]);
        setAppointments(appts);
        setUnreadMessages(convos.reduce((sum, c) => sum + c.unreadCount, 0));
      } catch {}
      setLoading(false);
    }
    load();
  }, [user.id]);

  if (loading) return <PageLoader />;

  const upcoming = appointments.filter((a) => a.status === 'upcoming');
  const completed = appointments.filter((a) => a.status === 'completed');

  return (
    <div className="space-y-6 animate-fade-in">
      <div>
        <h1 className="text-2xl font-bold text-white">Welcome back, {user.firstName}</h1>
        <p className="text-surface-400 mt-1">Here's an overview of your health portal</p>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard
          icon={<svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 7V3m8 4V3m-9 8h10M5 21h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v12a2 2 0 002 2z" /></svg>}
          label="Upcoming Appointments" value={upcoming.length}
        />
        <StatCard
          icon={<svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" /></svg>}
          label="Total Visits" value={completed.length}
        />
        <StatCard
          icon={<svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 12h.01M12 12h.01M16 12h.01M21 12c0 4.418-4.03 8-9 8a9.863 9.863 0 01-4.255-.949L3 20l1.395-3.72C3.512 15.042 3 13.574 3 12c0-4.418 4.03-8 9-8s9 3.582 9 8z" /></svg>}
          label="Unread Messages" value={unreadMessages}
        />
        <StatCard
          icon={<svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2" /></svg>}
          label="Blood Type" value={user.bloodType || 'N/A'}
        />
      </div>

      {/* Quick Actions */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {[
          { label: 'Book Appointment', desc: 'Schedule a visit with your doctor', path: '/patient/appointments', color: 'from-primary-600 to-primary-700', icon: 'M8 7V3m8 4V3m-9 8h10M5 21h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v12a2 2 0 002 2z' },
          { label: 'View Reports', desc: 'Access your lab results and prescriptions', path: '/patient/reports', color: 'from-blue-600 to-blue-700', icon: 'M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z' },
          { label: 'Send Message', desc: 'Securely message your healthcare team', path: '/patient/messages', color: 'from-violet-600 to-violet-700', icon: 'M8 12h.01M12 12h.01M16 12h.01M21 12c0 4.418-4.03 8-9 8a9.863 9.863 0 01-4.255-.949L3 20l1.395-3.72C3.512 15.042 3 13.574 3 12c0-4.418 4.03-8 9-8s9 3.582 9 8z' },
        ].map((action) => (
          <button
            key={action.path}
            onClick={() => navigate(action.path)}
            className="card-hover text-left group"
          >
            <div className={`w-10 h-10 rounded-xl bg-gradient-to-br ${action.color} flex items-center justify-center mb-3 group-hover:scale-110 transition-transform`}>
              <svg className="w-5 h-5 text-white" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d={action.icon} />
              </svg>
            </div>
            <h3 className="text-white font-semibold">{action.label}</h3>
            <p className="text-sm text-surface-400 mt-1">{action.desc}</p>
          </button>
        ))}
      </div>

      {/* Upcoming Appointments */}
      <div className="card">
        <h2 className="text-lg font-semibold text-white mb-4">Upcoming Appointments</h2>
        {upcoming.length === 0 ? (
          <p className="text-surface-500 text-sm">No upcoming appointments</p>
        ) : (
          <div className="space-y-3">
            {upcoming.slice(0, 3).map((apt) => (
              <div key={apt.id} className="flex items-center justify-between p-3 rounded-xl bg-surface-800/30 border border-surface-700/20">
                <div className="flex items-center gap-3">
                  <div className="w-10 h-10 rounded-xl bg-primary-500/10 flex items-center justify-center text-primary-400">
                    <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 7V3m8 4V3m-9 8h10M5 21h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v12a2 2 0 002 2z" />
                    </svg>
                  </div>
                  <div>
                    <p className="text-sm font-medium text-white">{apt.type} — {apt.doctorName}</p>
                    <p className="text-xs text-surface-400">{formatDate(apt.date)} at {apt.time}</p>
                  </div>
                </div>
                <Badge variant="primary">{apt.status}</Badge>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
