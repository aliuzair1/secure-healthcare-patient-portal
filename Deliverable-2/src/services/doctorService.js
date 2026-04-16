/**
 * doctorService.js — all requests route through Flask backend.
 */
import api from '../config/api';

// ---- patient roster ----
export async function getAssignedPatients(doctorId) {
  const { data } = await api.get(`/doctor/${doctorId}/patients`);
  return data.patients ?? [];
}

// ---- full patient record ----
export async function getPatientFullRecord(patientId, doctorId) {
  const { data } = await api.get(`/doctor/${doctorId}/patients/${patientId}/record`);
  return data;
}

// ---- visit notes ----
export async function addVisitNote(noteData) {
  const { data } = await api.post(`/doctor/${noteData.doctorId}/visit-notes`, noteData);
  return data;
}

// ---- prescriptions ----
export async function issuePrescription(rxData) {
  const { data } = await api.post(`/doctor/${rxData.doctorId}/prescriptions`, rxData);
  return data;
}

// ---- appointments ----
export async function getDoctorAppointments(doctorId) {
  const { data } = await api.get(`/doctor/${doctorId}/appointments`);
  return data.appointments ?? [];
}
