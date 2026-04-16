/**
 * adminService.js — all requests route through Flask backend.
 */
import api from '../config/api';

// ---- users ----
export async function getAllUsers() {
  const { data } = await api.get('/admin/users');
  return data.users ?? [];
}

export async function toggleUserStatus(userId, isActive) {
  const { data } = await api.patch(`/admin/users/${userId}/status`, { isActive });
  return data;
}

// ---- doctor approvals ----
export async function getPendingDoctors() {
  const { data } = await api.get('/admin/doctors/pending');
  return data.doctors ?? [];
}

export async function approveDoctor(doctorId) {
  const { data } = await api.patch(`/admin/doctors/${doctorId}/approve`);
  return data;
}

export async function rejectDoctor(doctorId) {
  const { data } = await api.patch(`/admin/doctors/${doctorId}/reject`);
  return data;
}

// ---- patient assignment ----
export async function assignPatientToDoctor(patientId, doctorId) {
  const { data } = await api.patch(`/admin/patients/${patientId}/assign`, { doctorId });
  return data;
}

export async function getPatientAssignments() {
  const { data } = await api.get('/admin/assignments');
  return data;
}

// ---- scheduling config ----
export async function getSchedulingConfig() {
  const { data } = await api.get('/admin/scheduling/config');
  return data;
}

export async function updateSchedulingConfig(config) {
  const { data } = await api.post('/admin/scheduling/config', config);
  return data;
}

// ---- stats ----
export async function getSystemStats() {
  const { data } = await api.get('/admin/stats');
  return data;
}
