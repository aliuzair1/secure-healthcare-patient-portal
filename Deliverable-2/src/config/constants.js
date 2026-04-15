export const APP_NAME = 'MedVault';
export const APP_TAGLINE = 'Secure Healthcare Portal';

export const TOKEN_EXPIRY_MS = 15 * 60 * 1000;   // 15 min (Supabase default)
export const REFRESH_BUFFER_MS = 30 * 1000;        // 30 s before expiry
export const INACTIVITY_TIMEOUT_MS = 15 * 60 * 1000; // 15 min
export const MFA_CODE_LENGTH = 6;
export const MFA_MAX_ATTEMPTS = 3;
export const MFA_RESEND_COOLDOWN_S = 60;
export const PASSWORD_MIN_LENGTH = 8;
export const PASSWORD_MAX_LENGTH = 128;

export const ROLES = {
  PATIENT: 'patient',
  DOCTOR: 'doctor',
  ADMIN: 'admin',
};

export const ROLE_LABELS = {
  [ROLES.PATIENT]: 'Patient',
  [ROLES.DOCTOR]: 'Doctor',
  [ROLES.ADMIN]: 'Admin / Staff',
};

export const ALLOWED_FILE_TYPES = [
  'application/pdf',
  'image/jpeg',
  'image/png',
  'image/webp',
  'text/plain',
];

export const MAX_FILE_SIZE_MB = 10;
export const MAX_FILE_SIZE_BYTES = MAX_FILE_SIZE_MB * 1024 * 1024;

// Base URL for any custom API / WAF proxy routes (Vercel serverless functions).
// Supabase calls go through the Supabase client directly — not this URL.
export const API_BASE_URL = import.meta.env.VITE_API_URL || '/api';

export const APPOINTMENT_STATUSES = {
  UPCOMING: 'upcoming',
  COMPLETED: 'completed',
  CANCELLED: 'cancelled',
};

export const MESSAGE_STATUS = {
  SENT: 'sent',
  DELIVERED: 'delivered',
  READ: 'read',
};
