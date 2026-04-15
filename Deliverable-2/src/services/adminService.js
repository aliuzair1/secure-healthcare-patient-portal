import { supabase } from '../lib/supabaseClient';

function mapProfile(row) {
  return {
    id: row.id,
    role: row.role,
    firstName: row.first_name,
    lastName: row.last_name,
    phone: row.phone,
    specialty: row.specialty,
    licenseNumber: row.license_number,
    department: row.department,
    assignedDoctorId: row.assigned_doctor_id,
    isApproved: row.is_approved,
    isActive: row.is_active,
    mfaEnabled: row.mfa_enabled,
    createdAt: row.created_at,
  };
}

export async function getAllUsers() {
  const { data, error } = await supabase
    .from('profiles')
    .select('*')
    .order('created_at', { ascending: false });

  if (error) throw { status: 500, message: 'Failed to load users.' };
  return (data ?? []).map(mapProfile);
}

export async function toggleUserStatus(userId, isActive) {
  const { error } = await supabase
    .from('profiles')
    .update({ is_active: isActive })
    .eq('id', userId);

  if (error) throw { status: 500, message: 'Failed to update user status.' };
  return { message: `User ${isActive ? 'activated' : 'deactivated'} successfully.` };
}

export async function getPendingDoctors() {
  const { data, error } = await supabase
    .from('profiles')
    .select('*')
    .eq('role', 'doctor')
    .eq('is_approved', false);

  if (error) throw { status: 500, message: 'Failed to load pending doctors.' };
  return (data ?? []).map(mapProfile);
}

export async function approveDoctor(doctorId) {
  const { error } = await supabase
    .from('profiles')
    .update({ is_approved: true })
    .eq('id', doctorId)
    .eq('role', 'doctor');

  if (error) throw { status: 500, message: 'Failed to approve doctor.' };
  return { message: 'Doctor account approved successfully.' };
}

export async function rejectDoctor(doctorId) {
  // Deactivate the account rather than hard-delete for audit trail
  const { error } = await supabase
    .from('profiles')
    .update({ is_active: false })
    .eq('id', doctorId)
    .eq('role', 'doctor');

  if (error) throw { status: 500, message: 'Failed to reject doctor.' };
  return { message: 'Doctor account has been rejected.' };
}

export async function assignPatientToDoctor(patientId, doctorId) {
  const { error } = await supabase
    .from('profiles')
    .update({ assigned_doctor_id: doctorId })
    .eq('id', patientId)
    .eq('role', 'patient');

  if (error) throw { status: 500, message: 'Failed to assign patient.' };
  return { message: 'Patient assigned to doctor successfully.' };
}

export async function getPatientAssignments() {
  const [pResult, dResult] = await Promise.all([
    supabase.from('profiles').select('*').eq('role', 'patient'),
    supabase.from('profiles').select('*').eq('role', 'doctor').eq('is_approved', true),
  ]);

  if (pResult.error || dResult.error) {
    throw { status: 500, message: 'Failed to load assignments.' };
  }

  const patients = (pResult.data ?? []).map(mapProfile);
  const doctors = (dResult.data ?? []).map(mapProfile);
  const doctorMap = Object.fromEntries(doctors.map((d) => [d.id, d]));

  const assignments = patients.map((p) => {
    const doc = doctorMap[p.assignedDoctorId];
    return {
      patientId: p.id,
      patientName: `${p.firstName} ${p.lastName}`,
      doctorId: p.assignedDoctorId ?? null,
      doctorName: doc
        ? `Dr. ${doc.firstName} ${doc.lastName}`
        : 'Unassigned',
    };
  });

  return { patients, doctors, assignments };
}

export async function getSchedulingConfig() {
  const { data, error } = await supabase
    .from('scheduling_config')
    .select('*')
    .eq('id', 1)
    .single();

  if (error || !data) {
    // Return sensible defaults if no row exists yet
    return {
      slotDurationMinutes: 30,
      maxAppointmentsPerDay: 16,
      workingHours: { start: '09:00', end: '17:00' },
      blackoutDates: [],
      lunchBreak: { start: '12:00', end: '13:00' },
    };
  }

  return {
    slotDurationMinutes: data.slot_duration_minutes,
    maxAppointmentsPerDay: data.max_appointments_per_day,
    workingHours: data.working_hours,
    blackoutDates: data.blackout_dates ?? [],
    lunchBreak: data.lunch_break,
  };
}

export async function updateSchedulingConfig(config) {
  const { error } = await supabase
    .from('scheduling_config')
    .upsert({
      id: 1,
      slot_duration_minutes: config.slotDurationMinutes,
      max_appointments_per_day: config.maxAppointmentsPerDay,
      working_hours: config.workingHours,
      blackout_dates: config.blackoutDates ?? [],
      lunch_break: config.lunchBreak,
      updated_at: new Date().toISOString(),
    });

  if (error) throw { status: 500, message: 'Failed to update scheduling config.' };
  return { message: 'Scheduling configuration updated.', ...config };
}

export async function getSystemStats() {
  const { data, error } = await supabase
    .from('profiles')
    .select('role, is_approved, is_active');

  if (error) throw { status: 500, message: 'Failed to load system stats.' };

  const rows = data ?? [];
  const patients = rows.filter((r) => r.role === 'patient');
  const doctors = rows.filter((r) => r.role === 'doctor');

  return {
    totalPatients: patients.length,
    totalDoctors: doctors.length,
    activeDoctors: doctors.filter((d) => d.is_approved && d.is_active).length,
    pendingApprovals: doctors.filter((d) => !d.is_approved).length,
    totalStaff: rows.filter((r) => r.role === 'admin').length,
  };
}
