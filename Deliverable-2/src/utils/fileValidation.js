import { ALLOWED_FILE_TYPES, MAX_FILE_SIZE_BYTES, MAX_FILE_SIZE_MB } from '../config/constants';

/**
 * Validate a file before upload.
 * Returns null if valid, or an error message string.
 */
export function validateFile(file, options = {}) {
  const {
    allowedTypes = ALLOWED_FILE_TYPES,
    maxSize = MAX_FILE_SIZE_BYTES,
    maxSizeMB = MAX_FILE_SIZE_MB,
  } = options;

  if (!file) return 'No file selected';

  if (!allowedTypes.includes(file.type)) {
    const extensions = allowedTypes.map(t => {
      const ext = t.split('/')[1];
      return `.${ext}`;
    }).join(', ');
    return `File type not allowed. Accepted: ${extensions}`;
  }

  if (file.size > maxSize) {
    return `File exceeds maximum size of ${maxSizeMB}MB`;
  }

  if (file.size === 0) {
    return 'File is empty';
  }

  // Check filename for dangerous patterns
  const dangerousExtensions = ['.exe', '.bat', '.cmd', '.sh', '.ps1', '.vbs', '.js', '.html', '.htm', '.svg'];
  const fileName = file.name.toLowerCase();
  if (dangerousExtensions.some(ext => fileName.endsWith(ext))) {
    return 'This file type is not allowed for security reasons';
  }

  return null;
}

/**
 * Format file size for display.
 */
export function formatFileSize(bytes) {
  if (bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return `${parseFloat((bytes / Math.pow(k, i)).toFixed(1))} ${sizes[i]}`;
}
