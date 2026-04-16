/**
 * patientService.js
 *
 * All calls go through the Axios `api` instance, which routes every
 * request via:  Client → Nginx reverse proxy → Custom WAF → Flask backend → Supabase
 *
 * The Bearer token (Supabase JWT) is attached automatically by the
 * request interceptor in src/config/api.js.
 */
import api from '../config/api';

// ---- profile ----
export async function getPatientProfile(patientId) {
  const { data } = await api.get(`/patient/${patientId}/profile`);
  return data;
}

export async function updatePatientProfile(patientId, updates) {
  const { data } = await api.patch(`/patient/${patientId}/profile`, updates);
  return data;
}

// ---- medical records ----
export async function getPatientMedicalHistory(patientId) {
  const { data } = await api.get(`/patient/${patientId}/medical-records`);
  return data.records ?? [];
}

// ---- lab reports ----
export async function getPatientReports(patientId) {
  const { data } = await api.get(`/patient/${patientId}/lab-reports`);
  return data.reports ?? [];
}

// ---- prescriptions ----
export async function getPatientPrescriptions(patientId) {
  const { data } = await api.get(`/patient/${patientId}/prescriptions`);
  return data.prescriptions ?? [];
}

// ---- appointments ----
export async function getPatientAppointments(patientId) {
  const { data } = await api.get(`/patient/${patientId}/appointments`);
  return data.appointments ?? [];
}

export async function getAvailableSlots(doctorId) {
  const { data } = await api.get(`/slots/${doctorId}`);
  return data.slots ?? [];
}

export async function bookAppointment(appointmentData) {
  const { data } = await api.post(
    `/patient/${appointmentData.patientId}/appointments`,
    appointmentData,
  );
  return data;
}

export async function cancelAppointment(appointmentId) {
  const { data } = await api.patch(`/appointments/${appointmentId}/cancel`);
  return data;
}

// ---- assigned doctors ----
export async function getAssignedDoctors(patientId) {
  const { data } = await api.get(`/patient/${patientId}/doctors`);
  return data.doctors ?? [];
}
