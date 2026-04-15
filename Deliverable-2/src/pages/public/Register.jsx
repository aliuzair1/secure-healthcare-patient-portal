import { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { useToast } from '../../context/ToastContext';
import { useSecureForm } from '../../hooks/useSecureForm';
import { validateEmail, validatePassword, validateName, validatePhone, validateDOB, getPasswordStrength } from '../../utils/validators';
import { registerPatient } from '../../services/authService';
import { Spinner } from '../../components/ui/Components';
import { APP_NAME } from '../../config/constants';

export default function Register() {
  const navigate = useNavigate();
  const { showToast } = useToast();
  const [showPassword, setShowPassword] = useState(false);

  const { values, errors, touched, isSubmitting, handleChange, handleBlur, handleSubmit, setErrors } = useSecureForm(
    { firstName: '', lastName: '', email: '', phone: '', dob: '', gender: '', password: '', confirmPassword: '', agreeTerms: false },
    {
      firstName: (v) => validateName(v, 'First name'),
      lastName: (v) => validateName(v, 'Last name'),
      email: (v) => validateEmail(v),
      phone: (v) => validatePhone(v),
      dob: (v) => validateDOB(v),
      gender: (v) => (!v ? 'Please select your gender' : null),
      password: (v) => validatePassword(v),
      confirmPassword: (v, all) => {
        if (!v) return 'Please confirm your password';
        if (v !== all.password) return 'Passwords do not match';
        return null;
      },
      agreeTerms: (v) => (!v ? 'You must agree to the terms' : null),
    }
  );

  const strength = getPasswordStrength(values.password);

  const onSubmit = async (data) => {
    try {
      await registerPatient(data);
      showToast('Registration successful! Please check your email to verify your account.', 'success');
      navigate('/login');
    } catch (err) {
      showToast(err.message || 'Registration failed.', 'error');
    }
  };

  const Field = ({ label, name, type = 'text', placeholder, children }) => (
    <div>
      <label htmlFor={`reg-${name}`} className="block text-sm font-medium text-surface-300 mb-1.5">{label}</label>
      {children || (
        <input
          id={`reg-${name}`} name={name} type={type} placeholder={placeholder}
          className={`input-secure ${touched[name] && errors[name] ? 'border-red-500/50' : ''}`}
          value={values[name]} onChange={handleChange} onBlur={handleBlur}
        />
      )}
      {touched[name] && errors[name] && <p className="mt-1 text-xs text-red-400">{errors[name]}</p>}
    </div>
  );

  return (
    <div className="min-h-screen flex items-center justify-center px-4 py-12 bg-surface-950 relative overflow-hidden">
      <div className="absolute top-0 right-1/4 w-96 h-96 bg-primary-500/5 rounded-full blur-3xl" />
      <div className="w-full max-w-lg relative z-10">
        <div className="text-center mb-8">
          <div className="w-14 h-14 mx-auto rounded-2xl gradient-primary flex items-center justify-center mb-4 glow-primary">
            <svg className="w-8 h-8 text-white" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2.5} d="M12 6v12M6 12h12" />
            </svg>
          </div>
          <h1 className="text-2xl font-bold text-white">Create Your Account</h1>
          <p className="text-surface-400 text-sm mt-1">Register as a new patient on {APP_NAME}</p>
        </div>

        <div className="glass rounded-2xl p-8 border border-surface-700/20">
          <form onSubmit={handleSubmit(onSubmit)} className="space-y-5" noValidate>
            <div className="grid grid-cols-2 gap-4">
              <Field label="First Name" name="firstName" placeholder="Sarah" />
              <Field label="Last Name" name="lastName" placeholder="Chen" />
            </div>
            <Field label="Email Address" name="email" type="email" placeholder="you@example.com" />
            <Field label="Phone Number" name="phone" type="tel" placeholder="+1-555-0123" />
            <div className="grid grid-cols-2 gap-4">
              <Field label="Date of Birth" name="dob" type="date" />
              <Field label="Gender" name="gender">
                <select
                  id="reg-gender" name="gender"
                  className={`input-secure ${touched.gender && errors.gender ? 'border-red-500/50' : ''}`}
                  value={values.gender} onChange={handleChange} onBlur={handleBlur}
                >
                  <option value="">Select</option>
                  <option value="Male">Male</option>
                  <option value="Female">Female</option>
                  <option value="Other">Other</option>
                  <option value="Prefer not to say">Prefer not to say</option>
                </select>
              </Field>
            </div>
            <div>
              <Field label="Password" name="password" type={showPassword ? 'text' : 'password'} placeholder="••••••••" />
              {values.password && (
                <div className="mt-2">
                  <div className="flex gap-1 mb-1">
                    {[1, 2, 3, 4, 5].map((i) => (
                      <div key={i} className={`h-1 flex-1 rounded-full transition-colors ${i <= strength.score ? strength.color : 'bg-surface-700'}`} />
                    ))}
                  </div>
                  <p className="text-xs text-surface-400">{strength.label}</p>
                </div>
              )}
            </div>
            <Field label="Confirm Password" name="confirmPassword" type="password" placeholder="••••••••" />
            <div className="flex items-start gap-3">
              <input
                id="reg-agreeTerms" name="agreeTerms" type="checkbox"
                className="mt-1 w-4 h-4 rounded border-surface-600 bg-surface-800 text-primary-500 focus:ring-primary-500/40"
                checked={values.agreeTerms} onChange={handleChange}
              />
              <label htmlFor="reg-agreeTerms" className="text-sm text-surface-400">
                I agree to the <a href="#" className="text-primary-400 hover:text-primary-300">Terms of Service</a> and <a href="#" className="text-primary-400 hover:text-primary-300">Privacy Policy</a>
              </label>
            </div>
            {touched.agreeTerms && errors.agreeTerms && <p className="text-xs text-red-400">{errors.agreeTerms}</p>}
            <button type="submit" className="btn-primary w-full flex items-center justify-center gap-2" disabled={isSubmitting}>
              {isSubmitting ? <Spinner size="sm" /> : null}
              {isSubmitting ? 'Creating Account…' : 'Create Account'}
            </button>
          </form>
          <p className="text-center text-sm text-surface-500 mt-6">
            Already have an account? <Link to="/login" className="text-primary-400 hover:text-primary-300">Sign in</Link>
          </p>
        </div>
      </div>
    </div>
  );
}
