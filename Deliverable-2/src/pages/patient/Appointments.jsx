import { useState, useEffect } from 'react';
import { useAuth } from '../../context/AuthContext';
import { useToast } from '../../context/ToastContext';
import { PageLoader, Badge, Modal } from '../../components/ui/Components';
import { getPatientAppointments, getAvailableSlots, getAssignedDoctors, bookAppointment, cancelAppointment } from '../../services/patientService';
import { formatDate } from '../../utils/formatters';

export default function Appointments() {
  const { user } = useAuth();
  const { showToast } = useToast();
  const [appointments, setAppointments] = useState([]);
  const [loading, setLoading] = useState(true);
  const [tab, setTab] = useState('upcoming');
  const [showBook, setShowBook] = useState(false);
  const [cancelModal, setCancelModal] = useState(null);
  const [cancelReason, setCancelReason] = useState('');

  // Booking state
  const [doctors, setDoctors] = useState([]);
  const [selectedDoctor, setSelectedDoctor] = useState('');
  const [slots, setSlots] = useState([]);
  const [selectedDate, setSelectedDate] = useState('');
  const [selectedTime, setSelectedTime] = useState('');
  const [bookingType, setBookingType] = useState('Follow-up');
  const [bookingNotes, setBookingNotes] = useState('');
  const [booking, setBooking] = useState(false);

  useEffect(() => {
    async function load() {
      try {
        const [appts, docs] = await Promise.all([getPatientAppointments(user.id), getAssignedDoctors(user.id)]);
        setAppointments(appts);
        setDoctors(docs);
        if (docs.length > 0) setSelectedDoctor(docs[0].id);
      } catch {}
      setLoading(false);
    }
    load();
  }, [user.id]);

  useEffect(() => {
    if (!selectedDoctor) return;
    getAvailableSlots(selectedDoctor).then(setSlots).catch(() => {});
  }, [selectedDoctor]);

  const handleBook = async () => {
    if (!selectedDate || !selectedTime) { showToast('Please select a date and time.', 'warning'); return; }
    setBooking(true);
    try {
      const newApt = await bookAppointment({
        patientId: user.id, doctorId: selectedDoctor,
        date: selectedDate, time: selectedTime,
        type: bookingType, notes: bookingNotes,
      });
      const doc = doctors.find((d) => d.id === selectedDoctor);
      setAppointments([...appointments, { ...newApt, doctorName: doc ? `Dr. ${doc.firstName} ${doc.lastName}` : '' }]);
      setShowBook(false);
      setSelectedDate(''); setSelectedTime(''); setBookingNotes('');
      showToast('Appointment booked successfully!', 'success');
    } catch { showToast('Failed to book appointment.', 'error'); }
    setBooking(false);
  };

  const handleCancel = async () => {
    try {
      await cancelAppointment(cancelModal.id, cancelReason);
      setAppointments(appointments.map((a) => a.id === cancelModal.id ? { ...a, status: 'cancelled' } : a));
      setCancelModal(null); setCancelReason('');
      showToast('Appointment cancelled.', 'info');
    } catch { showToast('Failed to cancel.', 'error'); }
  };

  if (loading) return <PageLoader />;

  const filtered = appointments.filter((a) => a.status === tab);
  const statusColors = { upcoming: 'primary', completed: 'success', cancelled: 'danger' };
  const availableTimes = slots.find((s) => s.date === selectedDate)?.times || [];

  return (
    <div className="space-y-6 animate-fade-in">
      <div className="flex items-center justify-between flex-wrap gap-4">
        <div>
          <h1 className="text-2xl font-bold text-white">Appointments</h1>
          <p className="text-surface-400 mt-1">Manage your healthcare appointments</p>
        </div>
        <button onClick={() => setShowBook(true)} className="btn-primary flex items-center gap-2">
          <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 4v16m8-8H4" /></svg>
          Book Appointment
        </button>
      </div>

      {/* Tabs */}
      <div className="flex gap-1 p-1 rounded-xl bg-surface-800/40 border border-surface-700/20 w-fit">
        {['upcoming', 'completed', 'cancelled'].map((t) => (
          <button key={t} onClick={() => setTab(t)}
            className={`px-4 py-2 rounded-lg text-sm font-medium capitalize transition-all ${tab === t ? 'bg-primary-500/20 text-primary-400' : 'text-surface-400 hover:text-white'}`}>
            {t} <span className="ml-1 text-xs opacity-60">({appointments.filter((a) => a.status === t).length})</span>
          </button>
        ))}
      </div>

      {/* List */}
      {filtered.length === 0 ? (
        <div className="card text-center py-12">
          <p className="text-surface-500">No {tab} appointments</p>
        </div>
      ) : (
        <div className="space-y-3">
          {filtered.map((apt) => (
            <div key={apt.id} className="card-hover flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
              <div className="flex items-center gap-4">
                <div className="w-12 h-12 rounded-xl bg-primary-500/10 flex items-center justify-center text-primary-400 flex-shrink-0">
                  <svg className="w-6 h-6" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 7V3m8 4V3m-9 8h10M5 21h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v12a2 2 0 002 2z" /></svg>
                </div>
                <div>
                  <p className="font-medium text-white">{apt.type}</p>
                  <p className="text-sm text-surface-400">{apt.doctorName} · {apt.location}</p>
                  <p className="text-sm text-surface-500">{formatDate(apt.date)} at {apt.time} · {apt.duration} min</p>
                </div>
              </div>
              <div className="flex items-center gap-3">
                <Badge variant={statusColors[apt.status]}>{apt.status}</Badge>
                {apt.status === 'upcoming' && (
                  <button onClick={() => setCancelModal(apt)} className="text-sm text-red-400 hover:text-red-300 transition-colors">Cancel</button>
                )}
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Booking Modal */}
      <Modal isOpen={showBook} onClose={() => setShowBook(false)} title="Book New Appointment" size="lg">
        <div className="space-y-5">
          <div>
            <label className="block text-sm font-medium text-surface-300 mb-1.5">Doctor</label>
            <select className="input-secure" value={selectedDoctor} onChange={(e) => { setSelectedDoctor(e.target.value); setSelectedDate(''); setSelectedTime(''); }}>
              {doctors.map((d) => <option key={d.id} value={d.id}>Dr. {d.firstName} {d.lastName} — {d.specialty}</option>)}
            </select>
          </div>
          <div>
            <label className="block text-sm font-medium text-surface-300 mb-1.5">Appointment Type</label>
            <select className="input-secure" value={bookingType} onChange={(e) => setBookingType(e.target.value)}>
              {['Follow-up', 'Consultation', 'Check-up', 'Annual Physical', 'Urgent'].map((t) => <option key={t} value={t}>{t}</option>)}
            </select>
          </div>
          <div>
            <label className="block text-sm font-medium text-surface-300 mb-3">Available Dates</label>
            <div className="flex flex-wrap gap-2">
              {slots.map((s) => (
                <button key={s.date} onClick={() => { setSelectedDate(s.date); setSelectedTime(''); }}
                  className={`px-4 py-2 rounded-xl text-sm border transition-all ${selectedDate === s.date ? 'border-primary-500 bg-primary-500/10 text-primary-400' : 'border-surface-600/30 text-surface-300 hover:border-primary-500/30'}`}>
                  {formatDate(s.date)}
                </button>
              ))}
            </div>
          </div>
          {selectedDate && (
            <div>
              <label className="block text-sm font-medium text-surface-300 mb-3">Available Times</label>
              <div className="flex flex-wrap gap-2">
                {availableTimes.map((t) => (
                  <button key={t} onClick={() => setSelectedTime(t)}
                    className={`px-4 py-2 rounded-xl text-sm border transition-all ${selectedTime === t ? 'border-primary-500 bg-primary-500/10 text-primary-400' : 'border-surface-600/30 text-surface-300 hover:border-primary-500/30'}`}>
                    {t}
                  </button>
                ))}
              </div>
            </div>
          )}
          <div>
            <label className="block text-sm font-medium text-surface-300 mb-1.5">Notes (optional)</label>
            <textarea className="input-secure h-20 resize-none" value={bookingNotes} onChange={(e) => setBookingNotes(e.target.value)} placeholder="Reason for visit…" />
          </div>
          <div className="flex gap-3 pt-2">
            <button onClick={handleBook} disabled={booking || !selectedTime} className="btn-primary flex-1">
              {booking ? 'Booking…' : 'Confirm Booking'}
            </button>
            <button onClick={() => setShowBook(false)} className="btn-secondary">Cancel</button>
          </div>
        </div>
      </Modal>

      {/* Cancel Modal */}
      <Modal isOpen={!!cancelModal} onClose={() => setCancelModal(null)} title="Cancel Appointment" size="sm">
        <div className="space-y-4">
          <p className="text-surface-300">Are you sure you want to cancel your <strong className="text-white">{cancelModal?.type}</strong> on <strong className="text-white">{formatDate(cancelModal?.date)}</strong>?</p>
          <div>
            <label className="block text-sm font-medium text-surface-300 mb-1.5">Reason (optional)</label>
            <textarea className="input-secure h-20 resize-none" value={cancelReason} onChange={(e) => setCancelReason(e.target.value)} placeholder="Reason for cancellation…" />
          </div>
          <div className="flex gap-3">
            <button onClick={handleCancel} className="btn-danger flex-1">Cancel Appointment</button>
            <button onClick={() => setCancelModal(null)} className="btn-secondary">Keep</button>
          </div>
        </div>
      </Modal>
    </div>
  );
}
