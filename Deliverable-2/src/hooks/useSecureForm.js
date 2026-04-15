import { useState, useCallback } from 'react';
import { sanitizeHTML } from '../utils/sanitize';
import { containsDangerousContent } from '../utils/validators';

/**
 * Custom hook for secure form handling.
 * Provides field state, validation, sanitized values, and submission handling.
 */
export function useSecureForm(initialValues = {}, validationRules = {}) {
  const [values, setValues] = useState(initialValues);
  const [errors, setErrors] = useState({});
  const [touched, setTouched] = useState({});
  const [isSubmitting, setIsSubmitting] = useState(false);

  const setValue = useCallback((field, value) => {
    // Sanitize string inputs
    const sanitized = typeof value === 'string' ? sanitizeHTML(value) : value;
    setValues((prev) => ({ ...prev, [field]: sanitized }));
    // Clear error on change
    setErrors((prev) => ({ ...prev, [field]: null }));
  }, []);

  const setRawValue = useCallback((field, value) => {
    setValues((prev) => ({ ...prev, [field]: value }));
    setErrors((prev) => ({ ...prev, [field]: null }));
  }, []);

  const handleChange = useCallback((e) => {
    const { name, value, type, checked } = e.target;
    const val = type === 'checkbox' ? checked : value;
    setValues((prev) => ({ ...prev, [name]: val }));
    setErrors((prev) => ({ ...prev, [name]: null }));
  }, []);

  const handleBlur = useCallback((e) => {
    const { name } = e.target;
    setTouched((prev) => ({ ...prev, [name]: true }));
    // Validate single field
    if (validationRules[name]) {
      const error = validationRules[name](values[name], values);
      setErrors((prev) => ({ ...prev, [name]: error }));
    }
  }, [validationRules, values]);

  const validateAll = useCallback(() => {
    const newErrors = {};
    let isValid = true;
    for (const [field, validator] of Object.entries(validationRules)) {
      const error = validator(values[field], values);
      if (error) {
        newErrors[field] = error;
        isValid = false;
      }
    }
    // Global dangerous content check
    for (const [field, value] of Object.entries(values)) {
      if (typeof value === 'string' && containsDangerousContent(value)) {
        newErrors[field] = 'Invalid characters detected';
        isValid = false;
      }
    }
    setErrors(newErrors);
    setTouched(Object.keys(validationRules).reduce((acc, k) => ({ ...acc, [k]: true }), {}));
    return isValid;
  }, [validationRules, values]);

  const handleSubmit = useCallback(
    (onSubmit) => async (e) => {
      e.preventDefault();
      if (!validateAll()) return;
      setIsSubmitting(true);
      try {
        await onSubmit(values);
      } finally {
        setIsSubmitting(false);
      }
    },
    [validateAll, values]
  );

  const reset = useCallback(() => {
    setValues(initialValues);
    setErrors({});
    setTouched({});
    setIsSubmitting(false);
  }, [initialValues]);

  return {
    values,
    errors,
    touched,
    isSubmitting,
    setValue,
    setRawValue,
    handleChange,
    handleBlur,
    handleSubmit,
    validateAll,
    reset,
    setErrors,
  };
}

export default useSecureForm;
