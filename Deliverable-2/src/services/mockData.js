import { ROLES, APPOINTMENT_STATUSES, MESSAGE_STATUS } from '../config/constants';

// ==================== USERS ====================
export const MOCK_USERS = [
  {
    id: 'usr-p-001', email: 'sarah.chen@email.com', password: 'Patient@123',
    role: ROLES.PATIENT, firstName: 'Sarah', lastName: 'Chen',
    phone: '+1-555-0101', dob: '1990-03-15', gender: 'Female',
    address: '742 Evergreen Terrace, Springfield, IL 62704',
    emergencyContact: 'Michael Chen — +1-555-0102',
    allergies: ['Penicillin', 'Latex'], bloodType: 'A+',
    assignedDoctorId: 'usr-d-001', isActive: true, mfaEnabled: true,
    createdAt: '2024-01-15T10:00:00Z',
  },
  {
    id: 'usr-p-002', email: 'james.wilson@email.com', password: 'Patient@123',
    role: ROLES.PATIENT, firstName: 'James', lastName: 'Wilson',
    phone: '+1-555-0201', dob: '1985-07-22', gender: 'Male',
    address: '123 Oak Drive, Portland, OR 97201',
    emergencyContact: 'Emily Wilson — +1-555-0202',
    allergies: ['Sulfa drugs'], bloodType: 'O-',
    assignedDoctorId: 'usr-d-001', isActive: true, mfaEnabled: true,
    createdAt: '2024-02-20T14:30:00Z',
  },
  {
    id: 'usr-p-003', email: 'maria.garcia@email.com', password: 'Patient@123',
    role: ROLES.PATIENT, firstName: 'Maria', lastName: 'Garcia',
    phone: '+1-555-0301', dob: '1978-11-05', gender: 'Female',
    address: '456 Maple Ave, Austin, TX 78701',
    emergencyContact: 'Carlos Garcia — +1-555-0302',
    allergies: [], bloodType: 'B+',
    assignedDoctorId: 'usr-d-002', isActive: true, mfaEnabled: true,
    createdAt: '2024-03-10T09:15:00Z',
  },
  {
    id: 'usr-d-001', email: 'dr.emily.brooks@medvault.com', password: 'Doctor@123',
    role: ROLES.DOCTOR, firstName: 'Emily', lastName: 'Brooks',
    phone: '+1-555-0401', specialty: 'Internal Medicine',
    licenseNumber: 'MD-2015-4821', department: 'General Medicine',
    isActive: true, isApproved: true, mfaEnabled: true,
    createdAt: '2023-06-01T08:00:00Z',
  },
  {
    id: 'usr-d-002', email: 'dr.raj.patel@medvault.com', password: 'Doctor@123',
    role: ROLES.DOCTOR, firstName: 'Raj', lastName: 'Patel',
    phone: '+1-555-0501', specialty: 'Cardiology',
    licenseNumber: 'MD-2012-7293', department: 'Cardiology',
    isActive: true, isApproved: true, mfaEnabled: true,
    createdAt: '2023-07-15T08:00:00Z',
  },
  {
    id: 'usr-d-003', email: 'dr.anna.kowalski@medvault.com', password: 'Doctor@123',
    role: ROLES.DOCTOR, firstName: 'Anna', lastName: 'Kowalski',
    phone: '+1-555-0601', specialty: 'Neurology',
    licenseNumber: 'MD-2018-1056', department: 'Neurology',
    isActive: true, isApproved: false, mfaEnabled: true,
    createdAt: '2024-04-01T08:00:00Z',
  },
  {
    id: 'usr-a-001', email: 'admin@medvault.com', password: 'Admin@1234',
    role: ROLES.ADMIN, firstName: 'System', lastName: 'Administrator',
    phone: '+1-555-0001', isActive: true, mfaEnabled: true,
    createdAt: '2023-01-01T00:00:00Z',
  },
];

// ==================== MEDICAL RECORDS ====================
export const MOCK_MEDICAL_RECORDS = [
  {
    id: 'rec-001', patientId: 'usr-p-001', doctorId: 'usr-d-001',
    date: '2024-11-15', type: 'Visit Note',
    diagnosis: 'Seasonal allergic rhinitis',
    notes: 'Patient presents with nasal congestion, sneezing, and watery eyes for the past 2 weeks. Symptoms consistent with seasonal allergies. Prescribed antihistamine.',
    vitals: { bp: '118/76', hr: 72, temp: '98.4°F', weight: '135 lbs' },
    followUp: '2025-02-15',
  },
  {
    id: 'rec-002', patientId: 'usr-p-001', doctorId: 'usr-d-001',
    date: '2024-08-20', type: 'Annual Physical',
    diagnosis: 'Routine examination — no abnormalities',
    notes: 'Complete physical examination performed. All vitals within normal range. Blood work ordered.',
    vitals: { bp: '120/80', hr: 68, temp: '98.6°F', weight: '133 lbs' },
    followUp: '2025-08-20',
  },
  {
    id: 'rec-003', patientId: 'usr-p-002', doctorId: 'usr-d-001',
    date: '2024-10-10', type: 'Follow-up',
    diagnosis: 'Hypertension — controlled',
    notes: 'Blood pressure well controlled on current medication. Continue Lisinopril 10mg daily. Diet and exercise counseling provided.',
    vitals: { bp: '132/84', hr: 76, temp: '98.2°F', weight: '185 lbs' },
    followUp: '2025-01-10',
  },
  {
    id: 'rec-004', patientId: 'usr-p-003', doctorId: 'usr-d-002',
    date: '2024-12-05', type: 'Consultation',
    diagnosis: 'Atypical chest pain — cardiac workup pending',
    notes: 'Patient reports intermittent chest discomfort during moderate exercise. EKG normal. Stress test and echocardiogram ordered.',
    vitals: { bp: '140/88', hr: 82, temp: '98.6°F', weight: '155 lbs' },
    followUp: '2025-01-05',
  },
];

// ==================== LAB REPORTS ====================
export const MOCK_REPORTS = [
  {
    id: 'rpt-001', patientId: 'usr-p-001', doctorId: 'usr-d-001',
    title: 'Complete Blood Count (CBC)', date: '2024-08-22',
    status: 'completed', category: 'Blood Work',
    results: [
      { test: 'WBC', value: '7.2', unit: 'K/uL', range: '4.5-11.0', flag: 'normal' },
      { test: 'RBC', value: '4.8', unit: 'M/uL', range: '4.0-5.5', flag: 'normal' },
      { test: 'Hemoglobin', value: '14.2', unit: 'g/dL', range: '12.0-16.0', flag: 'normal' },
      { test: 'Platelet Count', value: '250', unit: 'K/uL', range: '150-400', flag: 'normal' },
    ],
  },
  {
    id: 'rpt-002', patientId: 'usr-p-001', doctorId: 'usr-d-001',
    title: 'Lipid Panel', date: '2024-08-22',
    status: 'completed', category: 'Blood Work',
    results: [
      { test: 'Total Cholesterol', value: '195', unit: 'mg/dL', range: '<200', flag: 'normal' },
      { test: 'LDL', value: '120', unit: 'mg/dL', range: '<100', flag: 'high' },
      { test: 'HDL', value: '55', unit: 'mg/dL', range: '>40', flag: 'normal' },
      { test: 'Triglycerides', value: '142', unit: 'mg/dL', range: '<150', flag: 'normal' },
    ],
  },
  {
    id: 'rpt-003', patientId: 'usr-p-002', doctorId: 'usr-d-001',
    title: 'Metabolic Panel', date: '2024-10-12',
    status: 'completed', category: 'Blood Work',
    results: [
      { test: 'Glucose', value: '102', unit: 'mg/dL', range: '70-100', flag: 'high' },
      { test: 'Creatinine', value: '0.9', unit: 'mg/dL', range: '0.7-1.3', flag: 'normal' },
      { test: 'Potassium', value: '4.1', unit: 'mEq/L', range: '3.5-5.0', flag: 'normal' },
    ],
  },
  {
    id: 'rpt-004', patientId: 'usr-p-003', doctorId: 'usr-d-002',
    title: 'EKG Report', date: '2024-12-05',
    status: 'completed', category: 'Cardiology',
    results: [
      { test: 'Heart Rate', value: '78', unit: 'bpm', range: '60-100', flag: 'normal' },
      { test: 'Rhythm', value: 'Normal Sinus', unit: '', range: 'NSR', flag: 'normal' },
      { test: 'QRS Duration', value: '88', unit: 'ms', range: '80-120', flag: 'normal' },
    ],
  },
];

// ==================== PRESCRIPTIONS ====================
export const MOCK_PRESCRIPTIONS = [
  {
    id: 'rx-001', patientId: 'usr-p-001', doctorId: 'usr-d-001',
    medication: 'Cetirizine 10mg', dosage: '1 tablet daily',
    frequency: 'Once daily', startDate: '2024-11-15', endDate: '2025-02-15',
    status: 'active', instructions: 'Take in the evening. May cause drowsiness.',
    refillsRemaining: 2,
  },
  {
    id: 'rx-002', patientId: 'usr-p-002', doctorId: 'usr-d-001',
    medication: 'Lisinopril 10mg', dosage: '1 tablet daily',
    frequency: 'Once daily, morning', startDate: '2024-06-01', endDate: '2025-06-01',
    status: 'active', instructions: 'Take in the morning with water. Monitor blood pressure regularly.',
    refillsRemaining: 5,
  },
  {
    id: 'rx-003', patientId: 'usr-p-002', doctorId: 'usr-d-001',
    medication: 'Metformin 500mg', dosage: '1 tablet twice daily',
    frequency: 'Twice daily with meals', startDate: '2024-10-10', endDate: '2025-04-10',
    status: 'active', instructions: 'Take with breakfast and dinner. Report any GI symptoms.',
    refillsRemaining: 3,
  },
  {
    id: 'rx-004', patientId: 'usr-p-003', doctorId: 'usr-d-002',
    medication: 'Aspirin 81mg', dosage: '1 tablet daily',
    frequency: 'Once daily', startDate: '2024-12-05', endDate: '2025-06-05',
    status: 'active', instructions: 'Low-dose aspirin for cardiac protection. Take with food.',
    refillsRemaining: 4,
  },
];

// ==================== APPOINTMENTS ====================
export const MOCK_APPOINTMENTS = [
  {
    id: 'apt-001', patientId: 'usr-p-001', doctorId: 'usr-d-001',
    date: '2025-05-20', time: '10:00 AM', duration: 30,
    type: 'Follow-up', status: APPOINTMENT_STATUSES.UPCOMING,
    notes: 'Follow-up for allergic rhinitis', location: 'Room 204',
  },
  {
    id: 'apt-002', patientId: 'usr-p-002', doctorId: 'usr-d-001',
    date: '2025-05-18', time: '02:30 PM', duration: 30,
    type: 'Check-up', status: APPOINTMENT_STATUSES.UPCOMING,
    notes: 'BP monitoring and medication review', location: 'Room 204',
  },
  {
    id: 'apt-003', patientId: 'usr-p-001', doctorId: 'usr-d-001',
    date: '2024-11-15', time: '09:00 AM', duration: 45,
    type: 'Visit', status: APPOINTMENT_STATUSES.COMPLETED,
    notes: 'Seasonal allergy consultation', location: 'Room 204',
  },
  {
    id: 'apt-004', patientId: 'usr-p-003', doctorId: 'usr-d-002',
    date: '2025-05-25', time: '11:00 AM', duration: 60,
    type: 'Consultation', status: APPOINTMENT_STATUSES.UPCOMING,
    notes: 'Cardiac workup results review', location: 'Cardiology Suite B',
  },
  {
    id: 'apt-005', patientId: 'usr-p-001', doctorId: 'usr-d-001',
    date: '2024-08-20', time: '10:00 AM', duration: 60,
    type: 'Annual Physical', status: APPOINTMENT_STATUSES.COMPLETED,
    notes: 'Yearly health screening', location: 'Room 204',
  },
  {
    id: 'apt-006', patientId: 'usr-p-002', doctorId: 'usr-d-001',
    date: '2024-09-15', time: '03:00 PM', duration: 30,
    type: 'Follow-up', status: APPOINTMENT_STATUSES.CANCELLED,
    notes: 'Patient requested cancellation', location: 'Room 204',
  },
];

// ==================== MESSAGES ====================
export const MOCK_MESSAGES = [
  {
    id: 'msg-001', senderId: 'usr-p-001', receiverId: 'usr-d-001',
    content: 'Hi Dr. Brooks, my allergy symptoms have improved significantly with the Cetirizine. Thank you!',
    timestamp: '2024-12-20T14:30:00Z', status: MESSAGE_STATUS.READ, encrypted: true,
  },
  {
    id: 'msg-002', senderId: 'usr-d-001', receiverId: 'usr-p-001',
    content: "That's great to hear, Sarah! Continue the medication as prescribed. Let me know if symptoms return.",
    timestamp: '2024-12-20T15:45:00Z', status: MESSAGE_STATUS.READ, encrypted: true,
  },
  {
    id: 'msg-003', senderId: 'usr-p-001', receiverId: 'usr-d-001',
    content: 'Will do. Also, should I schedule my follow-up appointment now or wait until February?',
    timestamp: '2024-12-21T09:10:00Z', status: MESSAGE_STATUS.READ, encrypted: true,
  },
  {
    id: 'msg-004', senderId: 'usr-d-001', receiverId: 'usr-p-001',
    content: "Let's schedule it for mid-February. You can book through the portal. If anything changes before then, don't hesitate to message me.",
    timestamp: '2024-12-21T10:30:00Z', status: MESSAGE_STATUS.DELIVERED, encrypted: true,
  },
  {
    id: 'msg-005', senderId: 'usr-p-002', receiverId: 'usr-d-001',
    content: 'Dr. Brooks, I have been experiencing occasional dizziness in the mornings. Could it be related to the Lisinopril?',
    timestamp: '2024-12-22T08:15:00Z', status: MESSAGE_STATUS.READ, encrypted: true,
  },
  {
    id: 'msg-006', senderId: 'usr-d-001', receiverId: 'usr-p-002',
    content: 'James, dizziness can sometimes occur with blood pressure medication. Please monitor your BP in the morning before taking the medication and share the readings with me. If severe, come in for an urgent visit.',
    timestamp: '2024-12-22T09:30:00Z', status: MESSAGE_STATUS.DELIVERED, encrypted: true,
  },
  {
    id: 'msg-007', senderId: 'usr-p-003', receiverId: 'usr-d-002',
    content: 'Dr. Patel, when will my stress test results be available?',
    timestamp: '2024-12-23T11:00:00Z', status: MESSAGE_STATUS.READ, encrypted: true,
  },
  {
    id: 'msg-008', senderId: 'usr-d-002', receiverId: 'usr-p-003',
    content: 'Hi Maria, the results should be ready by next week. I will review them and discuss during your upcoming appointment on January 5th.',
    timestamp: '2024-12-23T13:45:00Z', status: MESSAGE_STATUS.SENT, encrypted: true,
  },
];

// ==================== AVAILABLE SLOTS ====================
export const MOCK_AVAILABLE_SLOTS = [
  { doctorId: 'usr-d-001', date: '2025-05-22', times: ['09:00 AM', '10:00 AM', '11:00 AM', '02:00 PM', '03:00 PM'] },
  { doctorId: 'usr-d-001', date: '2025-05-23', times: ['09:00 AM', '10:30 AM', '01:00 PM', '03:30 PM'] },
  { doctorId: 'usr-d-001', date: '2025-05-26', times: ['09:00 AM', '10:00 AM', '11:00 AM', '01:00 PM', '02:00 PM', '03:00 PM'] },
  { doctorId: 'usr-d-002', date: '2025-05-22', times: ['10:00 AM', '11:30 AM', '02:00 PM'] },
  { doctorId: 'usr-d-002', date: '2025-05-23', times: ['09:00 AM', '11:00 AM', '02:30 PM', '04:00 PM'] },
  { doctorId: 'usr-d-002', date: '2025-05-26', times: ['10:00 AM', '01:00 PM', '03:00 PM'] },
];

// ==================== SCHEDULING CONFIG ====================
export const MOCK_SCHEDULING_CONFIG = {
  slotDurationMinutes: 30,
  maxAppointmentsPerDay: 16,
  workingHours: { start: '09:00', end: '17:00' },
  blackoutDates: ['2025-12-25', '2025-01-01', '2025-07-04'],
  lunchBreak: { start: '12:00', end: '13:00' },
};

// ==================== HELPER: Simulate API delay ====================
export function simulateDelay(ms = 800) {
  return new Promise((resolve) => setTimeout(resolve, ms + Math.random() * 400));
}
