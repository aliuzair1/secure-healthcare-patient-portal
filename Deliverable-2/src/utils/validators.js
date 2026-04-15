import { PASSWORD_MIN_LENGTH, PASSWORD_MAX_LENGTH, MFA_CODE_LENGTH } from '../config/constants';

const EMAIL_REGEX = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
const PHONE_REGEX = /^\+?[\d\s\-()]{7,20}$/;
const NAME_REGEX = /^[a-zA-Z\s'-]{2,100}$/;
const DANGEROUS_PATTERNS = [
  /<script\b[^>]*>/gi,
  /javascript:/gi,
  /on\w+\s*=/gi,
  /eval\s*\(/gi,
  /expression\s*\(/gi,
  /url\s*\(/gi,
  /<iframe/gi,
  /<object/gi,
  /<embed/gi,
  /data:\s*text\/html/gi,
  /vbscript:/gi,
  /'.*--/g,
  /;\s*DROP\s/gi,
  /UNION\s+SELECT/gi,
  /INSERT\s+INTO/gi,
  /DELETE\s+FROM/gi,
];

export function validateEmail(email) {
  if (!email || typeof email !== 'string') return 'Email is required';
  const trimmed = email.trim();
  if (trimmed.length > 254) return 'Email is too long';
  if (!EMAIL_REGEX.test(trimmed)) return 'Please enter a valid email address';
  if (containsDangerousContent(trimmed)) return 'Invalid characters detected';
  return null;
}

export function validatePassword(password) {
  if (!password || typeof password !== 'string') return 'Password is required';
  if (password.length < PASSWORD_MIN_LENGTH) return `Password must be at least ${PASSWORD_MIN_LENGTH} characters`;
  if (password.length > PASSWORD_MAX_LENGTH) return `Password must be less than ${PASSWORD_MAX_LENGTH} characters`;
  if (!/[A-Z]/.test(password)) return 'Password must contain at least one uppercase letter';
  if (!/[a-z]/.test(password)) return 'Password must contain at least one lowercase letter';
  if (!/[0-9]/.test(password)) return 'Password must contain at least one number';
  if (!/[!@#$%^&*()_+\-=[\]{};':"\\|,.<>/?]/.test(password)) return 'Password must contain at least one special character';
  return null;
}

export function validateName(name, fieldLabel = 'Name') {
  if (!name || typeof name !== 'string') return `${fieldLabel} is required`;
  const trimmed = name.trim();
  if (trimmed.length < 2) return `${fieldLabel} must be at least 2 characters`;
  if (trimmed.length > 100) return `${fieldLabel} is too long`;
  if (!NAME_REGEX.test(trimmed)) return `${fieldLabel} contains invalid characters`;
  if (containsDangerousContent(trimmed)) return 'Invalid characters detected';
  return null;
}

export function validatePhone(phone) {
  if (!phone || typeof phone !== 'string') return 'Phone number is required';
  const trimmed = phone.trim();
  if (!PHONE_REGEX.test(trimmed)) return 'Please enter a valid phone number';
  if (containsDangerousContent(trimmed)) return 'Invalid characters detected';
  return null;
}

export function validateMFACode(code) {
  if (!code || typeof code !== 'string') return 'Verification code is required';
  const trimmed = code.trim();
  if (trimmed.length !== MFA_CODE_LENGTH) return `Code must be ${MFA_CODE_LENGTH} digits`;
  if (!/^\d+$/.test(trimmed)) return 'Code must contain only numbers';
  return null;
}

export function validateRequired(value, fieldLabel = 'This field') {
  if (value === null || value === undefined || (typeof value === 'string' && !value.trim())) {
    return `${fieldLabel} is required`;
  }
  if (containsDangerousContent(String(value))) return 'Invalid characters detected';
  return null;
}

export function validateDate(dateStr, fieldLabel = 'Date') {
  if (!dateStr) return `${fieldLabel} is required`;
  const date = new Date(dateStr);
  if (isNaN(date.getTime())) return `Please enter a valid ${fieldLabel.toLowerCase()}`;
  return null;
}

export function validateDOB(dateStr) {
  const baseErr = validateDate(dateStr, 'Date of birth');
  if (baseErr) return baseErr;
  const date = new Date(dateStr);
  const now = new Date();
  if (date > now) return 'Date of birth cannot be in the future';
  const age = (now - date) / (365.25 * 24 * 60 * 60 * 1000);
  if (age > 150) return 'Please enter a valid date of birth';
  return null;
}

export function getPasswordStrength(password) {
  if (!password) return { score: 0, label: '', color: '' };
  let score = 0;
  if (password.length >= 8) score++;
  if (password.length >= 12) score++;
  if (/[A-Z]/.test(password) && /[a-z]/.test(password)) score++;
  if (/[0-9]/.test(password)) score++;
  if (/[^A-Za-z0-9]/.test(password)) score++;

  const levels = [
    { label: 'Very Weak', color: 'bg-red-500' },
    { label: 'Weak', color: 'bg-orange-500' },
    { label: 'Fair', color: 'bg-yellow-500' },
    { label: 'Strong', color: 'bg-emerald-500' },
    { label: 'Very Strong', color: 'bg-primary-500' },
  ];

  const idx = Math.min(score, levels.length) - 1;
  return { score, ...levels[Math.max(0, idx)] };
}

export function containsDangerousContent(str) {
  if (typeof str !== 'string') return false;
  return DANGEROUS_PATTERNS.some((pattern) => pattern.test(str));
}
