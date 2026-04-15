import { supabase } from '../lib/supabaseClient';

// ---- helpers ----
function mapProfile(row) {
  return {
    id: row.id,
    role: row.role,
    firstName: row.first_name,
    lastName: row.last_name,
    phone: row.phone,
    dob: row.dob,
    gender: row.gender,
    address: row.address,
    emergencyContact: row.emergency_contact,
    allergies: row.allergies ?? [],
    bloodType: row.blood_type,
    assignedDoctorId: row.assigned_doctor_id,
    isActive: row.is_active,
    mfaEnabled: row.mfa_enabled,
    createdAt: row.created_at,
  };
}

function mapAppointment(row, doctorRow) {
  return {
    id: row.id,
    patientId: row.patient_id,
    doctorId: row.doctor_id,
    doctorName: doctorRow
      ? `Dr. ${doctorRow.first_name} ${doctorRow.last_name}`
      : 'Unknown',
    date: row.date,
    time: row.time,
    duration: row.duration,
    type: row.type,
    status: row.status,
    notes: row.notes,
    location: row.location,
  };
}

// ---- profile ----
export async function getPatientProfile(patientId) {
  const { data, error } = await supabase
    .from('profiles')
    .select('*')
    .eq('id', patientId)
    .eq('role', 'patient')
    .single();

  if (error || !data) throw { status: 404, message: 'Patient not found.' };
  return mapProfile(data);
}

export async function updatePatientProfile(patientId, updates) {
  const { error } = await supabase
    .from('profiles')
    .update({
      first_name: updates.firstName,
      last_name: updates.lastName,
      phone: updates.phone,
      dob: updates.dob,
      gender: updates.gender,
      address: updates.address,
      emergency_contact: updates.emergencyContact,
      allergies: updates.allergies,
      blood_type: updates.bloodType,
    })
    .eq('id', patientId);

  if (error) throw { status: 500, message: 'Failed to update profile.' };
  return { message: 'Profile updated successfully.' };
}

// ---- medical records ----
export async function getPatientMedicalHistory(patientId) {
  const { data, error } = await supabase
    .from('medical_records')
    .select('*')
    .eq('patient_id', patientId)
    .order('date', { ascending: false });

  if (error) throw { status: 500, message: 'Failed to load medical records.' };
  return (data ?? []).map((r) => ({
    id: r.id,
    patientId: r.patient_id,
    doctorId: r.doctor_id,
    date: r.date,
    type: r.type,
    diagnosis: r.diagnosis,
    notes: r.notes,
    vitals: r.vitals,
    followUp: r.follow_up,
  }));
}

// ---- lab reports ----
export async function getPatientReports(patientId) {
  const { data, error } = await supabase
    .from('lab_reports')
    .select('*')
    .eq('patient_id', patientId)
    .order('date', { ascending: false });

  if (error) throw { status: 500, message: 'Failed to load lab reports.' };
  return (data ?? []).map((r) => ({
    id: r.id,
    patientId: r.patient_id,
    doctorId: r.doctor_id,
    title: r.title,
    date: r.date,
    status: r.status,
    category: r.category,
    results: r.results ?? [],
  }));
}

// ---- prescriptions ----
export async function getPatientPrescriptions(patientId) {
  const { data, error } = await supabase
    .from('prescriptions')
    .select('*')
    .eq('patient_id', patientId)
    .order('created_at', { ascending: false });

  if (error) throw { status: 500, message: 'Failed to load prescriptions.' };
  return (data ?? []).map((r) => ({
    id: r.id,
    patientId: r.patient_id,
    doctorId: r.doctor_id,
    medication: r.medication,
    dosage: r.dosage,
    frequency: r.frequency,
    startDate: r.start_date,
    endDate: r.end_date,
    status: r.status,
    instructions: r.instructions,
    refillsRemaining: r.refills_remaining,
  }));
}

// ---- appointments ----
export async function getPatientAppointments(patientId) {
  const { data, error } = await supabase
    .from('appointments')
    .select('*, doctor:profiles!appointments_doctor_id_fkey(first_name, last_name)')
    .eq('patient_id', patientId)
    .order('date', { ascending: false });

  if (error) throw { status: 500, message: 'Failed to load appointments.' };
  return (data ?? []).map((r) => mapAppointment(r, r.doctor));
}

export async function getAvailableSlots(doctorId) {
  const { data, error } = await supabase
    .from('available_slots')
    .select('*')
    .eq('doctor_id', doctorId)
    .gte('date', new Date().toISOString().split('T')[0])
    .order('date', { ascending: true });

  if (error) throw { status: 500, message: 'Failed to load available slots.' };
  return (data ?? []).map((s) => ({
    doctorId: s.doctor_id,
    date: s.date,
    times: s.times ?? [],
  }));
}

export async function bookAppointment(appointmentData) {
  const { data, error } = await supabase
    .from('appointments')
    .insert({
      patient_id: appointmentData.patientId,
      doctor_id: appointmentData.doctorId,
      date: appointmentData.date,
      time: appointmentData.time,
      duration: appointmentData.duration ?? 30,
      type: appointmentData.type,
      status: 'upcoming',
      notes: appointmentData.notes ?? null,
      location: appointmentData.location ?? null,
    })
    .select()
    .single();

  if (error) throw { status: 500, message: 'Failed to book appointment.' };
  return { id: data.id, ...appointmentData, status: 'upcoming' };
}

export async function cancelAppointment(appointmentId) {
  const { error } = await supabase
    .from('appointments')
    .update({ status: 'cancelled' })
    .eq('id', appointmentId);

  if (error) throw { status: 500, message: 'Failed to cancel appointment.' };
  return { message: 'Appointment cancelled successfully.' };
}

export async function getAssignedDoctors(patientId) {
  const { data: patient, error: pErr } = await supabase
    .from('profiles')
    .select('assigned_doctor_id')
    .eq('id', patientId)
    .single();

  if (pErr || !patient?.assigned_doctor_id) return [];

  const { data: doctor, error: dErr } = await supabase
    .from('profiles')
    .select('*')
    .eq('id', patient.assigned_doctor_id)
    .single();

  if (dErr || !doctor) return [];
  return [mapProfile(doctor)];
}
