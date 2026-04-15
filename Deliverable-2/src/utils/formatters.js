/**
 * Format a date string for display.
 */
export function formatDate(dateStr) {
  if (!dateStr) return '—';
  const date = new Date(dateStr);
  if (isNaN(date.getTime())) return '—';
  return date.toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric' });
}

export function formatDateTime(dateStr) {
  if (!dateStr) return '—';
  const date = new Date(dateStr);
  if (isNaN(date.getTime())) return '—';
  return date.toLocaleString('en-US', {
    year: 'numeric', month: 'short', day: 'numeric',
    hour: '2-digit', minute: '2-digit',
  });
}

export function formatTime(dateStr) {
  if (!dateStr) return '—';
  const date = new Date(dateStr);
  if (isNaN(date.getTime())) return '—';
  return date.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' });
}

export function formatRelativeTime(dateStr) {
  if (!dateStr) return '';
  const diff = Date.now() - new Date(dateStr).getTime();
  const seconds = Math.floor(diff / 1000);
  if (seconds < 60) return 'just now';
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.floor(hours / 24);
  if (days < 7) return `${days}d ago`;
  return formatDate(dateStr);
}

/**
 * Mask PHI data (e.g., SSN, phone).
 */
export function maskPHI(value, visibleChars = 4) {
  if (!value || typeof value !== 'string') return '••••';
  if (value.length <= visibleChars) return '•'.repeat(value.length);
  return '•'.repeat(value.length - visibleChars) + value.slice(-visibleChars);
}

export function maskEmail(email) {
  if (!email || !email.includes('@')) return '••••@••••';
  const [local, domain] = email.split('@');
  const masked = local.length > 2
    ? local[0] + '•'.repeat(local.length - 2) + local.slice(-1)
    : '••';
  return `${masked}@${domain}`;
}

export function capitalizeFirst(str) {
  if (!str) return '';
  return str.charAt(0).toUpperCase() + str.slice(1).toLowerCase();
}

export function getInitials(name) {
  if (!name) return '?';
  return name
    .split(' ')
    .filter(Boolean)
    .map((w) => w[0])
    .slice(0, 2)
    .join('')
    .toUpperCase();
}
