import { supabase } from '../lib/supabaseClient';

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
    specialty: row.specialty,
    licenseNumber: row.license_number,
    department: row.department,
    isApproved: row.is_approved,
    isActive: row.is_active,
    createdAt: row.created_at,
  };
}

export async function getAssignedPatients(doctorId) {
  const { data, error } = await supabase
    .from('profiles')
    .select('*')
    .eq('role', 'patient')
    .eq('assigned_doctor_id', doctorId);

  if (error) throw { status: 500, message: 'Failed to load patient list.' };
  return (data ?? []).map(mapProfile);
}

export async function getPatientFullRecord(patientId, doctorId) {
  // Verify this patient is assigned to the requesting doctor (enforced by RLS too)
  const { data: patient, error: pErr } = await supabase
    .from('profiles')
    .select('*')
    .eq('id', patientId)
    .eq('assigned_doctor_id', doctorId)
    .single();

  if (pErr || !patient) {
    throw { status: 403, message: 'Not authorized to view this patient.' };
  }

  const [records, reports, prescriptions, appointments] = await Promise.all([
    supabase.from('medical_records').select('*').eq('patient_id', patientId).order('date', { ascending: false }),
    supabase.from('lab_reports').select('*').eq('patient_id', patientId).order('date', { ascending: false }),
    supabase.from('prescriptions').select('*').eq('patient_id', patientId).order('created_at', { ascending: false }),
    supabase.from('appointments').select('*').eq('patient_id', patientId).order('date', { ascending: false }),
  ]);

  return {
    profile: mapProfile(patient),
    medicalHistory: (records.data ?? []).map((r) => ({
      id: r.id, patientId: r.patient_id, doctorId: r.doctor_id,
      date: r.date, type: r.type, diagnosis: r.diagnosis,
      notes: r.notes, vitals: r.vitals, followUp: r.follow_up,
    })),
    reports: (reports.data ?? []).map((r) => ({
      id: r.id, patientId: r.patient_id, doctorId: r.doctor_id,
      title: r.title, date: r.date, status: r.status,
      category: r.category, results: r.results ?? [],
    })),
    prescriptions: (prescriptions.data ?? []).map((r) => ({
      id: r.id, patientId: r.patient_id, doctorId: r.doctor_id,
      medication: r.medication, dosage: r.dosage, frequency: r.frequency,
      startDate: r.start_date, endDate: r.end_date,
      status: r.status, instructions: r.instructions,
      refillsRemaining: r.refills_remaining,
    })),
    appointments: (appointments.data ?? []).map((r) => ({
      id: r.id, patientId: r.patient_id, doctorId: r.doctor_id,
      date: r.date, time: r.time, duration: r.duration,
      type: r.type, status: r.status, notes: r.notes, location: r.location,
    })),
  };
}

export async function addVisitNote(data) {
  const { data: record, error } = await supabase
    .from('medical_records')
    .insert({
      patient_id: data.patientId,
      doctor_id: data.doctorId,
      date: data.date || new Date().toISOString().split('T')[0],
      type: data.type,
      diagnosis: data.diagnosis,
      notes: data.notes,
      vitals: data.vitals ?? null,
      follow_up: data.followUp ?? null,
    })
    .select()
    .single();

  if (error) throw { status: 500, message: 'Failed to save visit note.' };
  return {
    id: record.id,
    patientId: record.patient_id,
    doctorId: record.doctor_id,
    date: record.date,
    type: record.type,
    diagnosis: record.diagnosis,
    notes: record.notes,
    vitals: record.vitals,
    followUp: record.follow_up,
  };
}

export async function issuePrescription(data) {
  const { data: rx, error } = await supabase
    .from('prescriptions')
    .insert({
      patient_id: data.patientId,
      doctor_id: data.doctorId,
      medication: data.medication,
      dosage: data.dosage,
      frequency: data.frequency,
      start_date: data.startDate,
      end_date: data.endDate,
      status: 'active',
      instructions: data.instructions ?? null,
      refills_remaining: data.refillsRemaining ?? 0,
    })
    .select()
    .single();

  if (error) throw { status: 500, message: 'Failed to issue prescription.' };
  return {
    id: rx.id,
    patientId: rx.patient_id,
    doctorId: rx.doctor_id,
    medication: rx.medication,
    dosage: rx.dosage,
    frequency: rx.frequency,
    startDate: rx.start_date,
    endDate: rx.end_date,
    status: rx.status,
    instructions: rx.instructions,
    refillsRemaining: rx.refills_remaining,
  };
}

export async function getDoctorAppointments(doctorId) {
  const { data, error } = await supabase
    .from('appointments')
    .select('*, patient:profiles!appointments_patient_id_fkey(first_name, last_name)')
    .eq('doctor_id', doctorId)
    .order('date', { ascending: false });

  if (error) throw { status: 500, message: 'Failed to load appointments.' };
  return (data ?? []).map((r) => ({
    id: r.id,
    patientId: r.patient_id,
    doctorId: r.doctor_id,
    patientName: r.patient
      ? `${r.patient.first_name} ${r.patient.last_name}`
      : 'Unknown',
    date: r.date,
    time: r.time,
    duration: r.duration,
    type: r.type,
    status: r.status,
    notes: r.notes,
    location: r.location,
  }));
}
