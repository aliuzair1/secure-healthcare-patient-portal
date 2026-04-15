import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../../context/AuthContext';
import { StatCard, PageLoader, Badge } from '../../components/ui/Components';
import { getAssignedPatients, getDoctorAppointments } from '../../services/doctorService';
import { getConversations } from '../../services/messagingService';
import { formatDate } from '../../utils/formatters';

export default function DoctorDashboard() {
  const { user } = useAuth();
  const navigate = useNavigate();
  const [patients, setPatients] = useState([]);
  const [appointments, setAppointments] = useState([]);
  const [unread, setUnread] = useState(0);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    async function load() {
      try {
        const [pts, appts, convos] = await Promise.all([
          getAssignedPatients(user.id),
          getDoctorAppointments(user.id),
          getConversations(user.id),
        ]);
        setPatients(pts);
        setAppointments(appts);
        setUnread(convos.reduce((s, c) => s + c.unreadCount, 0));
      } catch {}
      setLoading(false);
    }
    load();
  }, [user.id]);

  if (loading) return <PageLoader />;

  const todayAppts = appointments.filter((a) => a.status === 'upcoming');

  return (
    <div className="space-y-6 animate-fade-in">
      <div>
        <h1 className="text-2xl font-bold text-white">Good {new Date().getHours() < 12 ? 'morning' : 'afternoon'}, Dr. {user.lastName}</h1>
        <p className="text-surface-400 mt-1">{user.specialty} · {user.department}</p>
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard icon={<svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M17 20h5v-2a3 3 0 00-5.356-1.857M17 20H7m10 0v-2c0-.656-.126-1.283-.356-1.857M7 20H2v-2a3 3 0 015.356-1.857M7 20v-2c0-.656.126-1.283.356-1.857m0 0a5.002 5.002 0 019.288 0M15 7a3 3 0 11-6 0 3 3 0 016 0z" /></svg>}
          label="Assigned Patients" value={patients.length} />
        <StatCard icon={<svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 7V3m8 4V3m-9 8h10M5 21h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v12a2 2 0 002 2z" /></svg>}
          label="Upcoming Appointments" value={todayAppts.length} />
        <StatCard icon={<svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 12h.01M12 12h.01M16 12h.01M21 12c0 4.418-4.03 8-9 8a9.863 9.863 0 01-4.255-.949L3 20l1.395-3.72C3.512 15.042 3 13.574 3 12c0-4.418 4.03-8 9-8s9 3.582 9 8z" /></svg>}
          label="Unread Messages" value={unread} />
        <StatCard icon={<svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2" /></svg>}
          label="Specialty" value={user.specialty || 'General'} />
      </div>

      {/* Quick Actions */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {[
          { label: 'Patient Roster', desc: 'View your assigned patients', path: '/doctor/patients', color: 'from-primary-600 to-primary-700' },
          { label: 'Clinical Updates', desc: 'Add visit notes and prescriptions', path: '/doctor/clinical', color: 'from-blue-600 to-blue-700' },
          { label: 'Messages', desc: 'Respond to patient messages', path: '/doctor/messages', color: 'from-violet-600 to-violet-700' },
        ].map((a) => (
          <button key={a.path} onClick={() => navigate(a.path)} className="card-hover text-left group">
            <div className={`w-10 h-10 rounded-xl bg-gradient-to-br ${a.color} flex items-center justify-center mb-3 group-hover:scale-110 transition-transform`}>
              <svg className="w-5 h-5 text-white" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 7l5 5m0 0l-5 5m5-5H6" /></svg>
            </div>
            <h3 className="text-white font-semibold">{a.label}</h3>
            <p className="text-sm text-surface-400 mt-1">{a.desc}</p>
          </button>
        ))}
      </div>

      {/* Upcoming Appointments */}
      <div className="card">
        <h2 className="text-lg font-semibold text-white mb-4">Upcoming Appointments</h2>
        {todayAppts.length === 0 ? (
          <p className="text-surface-500 text-sm">No upcoming appointments</p>
        ) : (
          <div className="space-y-3">
            {todayAppts.slice(0, 5).map((apt) => (
              <div key={apt.id} className="flex items-center justify-between p-3 rounded-xl bg-surface-800/30 border border-surface-700/20">
                <div>
                  <p className="text-sm font-medium text-white">{apt.patientName}</p>
                  <p className="text-xs text-surface-400">{apt.type} · {formatDate(apt.date)} at {apt.time}</p>
                </div>
                <Badge variant="primary">{apt.duration} min</Badge>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
