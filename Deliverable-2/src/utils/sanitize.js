const ENTITY_MAP = {
  '&': '&amp;',
  '<': '&lt;',
  '>': '&gt;',
  '"': '&quot;',
  "'": '&#x27;',
  '/': '&#x2F;',
  '`': '&#96;',
};

/**
 * Sanitize a string to prevent XSS.
 * Encodes special HTML chars.
 */
export function sanitizeHTML(str) {
  if (typeof str !== 'string') return '';
  return str.replace(/[&<>"'`/]/g, (char) => ENTITY_MAP[char] || char);
}

/**
 * Strip all HTML tags from a string.
 */
export function stripTags(str) {
  if (typeof str !== 'string') return '';
  return str.replace(/<[^>]*>/g, '');
}

/**
 * Sanitize an object's string values recursively.
 */
export function sanitizeObject(obj) {
  if (obj === null || obj === undefined) return obj;
  if (typeof obj === 'string') return sanitizeHTML(obj);
  if (Array.isArray(obj)) return obj.map(sanitizeObject);
  if (typeof obj === 'object') {
    const cleaned = {};
    for (const [key, value] of Object.entries(obj)) {
      cleaned[sanitizeHTML(key)] = sanitizeObject(value);
    }
    return cleaned;
  }
  return obj;
}

/**
 * Truncate text safely (no mid-entity truncation).
 */
export function truncate(str, maxLen = 100) {
  if (typeof str !== 'string') return '';
  const clean = stripTags(str);
  if (clean.length <= maxLen) return clean;
  return clean.slice(0, maxLen).replace(/\s+\S*$/, '') + '…';
}
