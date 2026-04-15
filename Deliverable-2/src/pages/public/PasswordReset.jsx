import { useState } from 'react';
import { Link } from 'react-router-dom';
import { useToast } from '../../context/ToastContext';
import { validateEmail, validateMFACode, validatePassword } from '../../utils/validators';
import { requestPasswordReset, resetPassword } from '../../services/authService';
import { Spinner } from '../../components/ui/Components';
import { APP_NAME } from '../../config/constants';

export default function PasswordReset() {
  const [step, setStep] = useState(1); // 1: email, 2: code+newpass
  const [email, setEmail] = useState('');
  const [token, setToken] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [errors, setErrors] = useState({});
  const [isLoading, setIsLoading] = useState(false);
  const [success, setSuccess] = useState(false);
  const { showToast } = useToast();

  const handleRequestReset = async (e) => {
    e.preventDefault();
    const emailErr = validateEmail(email);
    if (emailErr) { setErrors({ email: emailErr }); return; }
    setIsLoading(true);
    try {
      await requestPasswordReset(email);
      showToast('If an account exists, a reset code has been sent.', 'info');
      setStep(2);
    } catch (err) {
      showToast(err.message, 'error');
    } finally {
      setIsLoading(false);
    }
  };

  const handleReset = async (e) => {
    e.preventDefault();
    const newErrors = {};
    const tokenErr = validateMFACode(token);
    const passErr = validatePassword(newPassword);
    if (tokenErr) newErrors.token = tokenErr;
    if (passErr) newErrors.newPassword = passErr;
    if (newPassword !== confirmPassword) newErrors.confirmPassword = 'Passwords do not match';
    if (Object.keys(newErrors).length) { setErrors(newErrors); return; }

    setIsLoading(true);
    try {
      await resetPassword(token, newPassword);
      setSuccess(true);
      showToast('Password reset successfully!', 'success');
    } catch (err) {
      showToast(err.message, 'error');
      setErrors({ token: 'Invalid or expired token' });
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center px-4 py-12 bg-surface-950 relative overflow-hidden">
      <div className="absolute bottom-0 left-1/3 w-80 h-80 bg-primary-500/5 rounded-full blur-3xl" />
      <div className="w-full max-w-md relative z-10">
        <div className="text-center mb-8">
          <div className="w-14 h-14 mx-auto rounded-2xl gradient-primary flex items-center justify-center mb-4 glow-primary">
            <svg className="w-8 h-8 text-white" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 7a2 2 0 012 2m4 0a6 6 0 01-7.743 5.743L11 17H9v2H7v2H4a1 1 0 01-1-1v-2.586a1 1 0 01.293-.707l5.964-5.964A6 6 0 1121 9z" />
            </svg>
          </div>
          <h1 className="text-2xl font-bold text-white">Reset Password</h1>
          <p className="text-surface-400 text-sm mt-1">{step === 1 ? 'Enter your email to receive a reset code' : 'Enter the code and your new password'}</p>
        </div>

        <div className="glass rounded-2xl p-8 border border-surface-700/20">
          {success ? (
            <div className="text-center">
              <div className="w-16 h-16 mx-auto mb-4 rounded-full bg-emerald-500/10 flex items-center justify-center">
                <svg className="w-8 h-8 text-emerald-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
                </svg>
              </div>
              <h2 className="text-lg font-semibold text-white mb-2">Password Reset Complete</h2>
              <p className="text-sm text-surface-400 mb-6">You can now sign in with your new password.</p>
              <Link to="/login" className="btn-primary inline-block">Go to Login</Link>
            </div>
          ) : step === 1 ? (
            <form onSubmit={handleRequestReset} className="space-y-5" noValidate>
              <div>
                <label htmlFor="reset-email" className="block text-sm font-medium text-surface-300 mb-1.5">Email Address</label>
                <input id="reset-email" type="email" className={`input-secure ${errors.email ? 'border-red-500/50' : ''}`}
                  placeholder="you@example.com" value={email}
                  onChange={(e) => { setEmail(e.target.value); setErrors({}); }} />
                {errors.email && <p className="mt-1 text-xs text-red-400">{errors.email}</p>}
              </div>
              <button type="submit" className="btn-primary w-full flex items-center justify-center gap-2" disabled={isLoading}>
                {isLoading ? <Spinner size="sm" /> : null}
                {isLoading ? 'Sending…' : 'Send Reset Code'}
              </button>
              <div className="mt-4 p-3 rounded-xl bg-surface-800/40 border border-surface-700/20 text-center">
                <p className="text-xs text-surface-500">Demo reset code: <span className="text-primary-400 font-mono font-bold">654321</span></p>
              </div>
            </form>
          ) : (
            <form onSubmit={handleReset} className="space-y-5" noValidate>
              <div>
                <label htmlFor="reset-token" className="block text-sm font-medium text-surface-300 mb-1.5">Reset Code</label>
                <input id="reset-token" type="text" inputMode="numeric" maxLength={6}
                  className={`input-secure font-mono text-center text-lg tracking-widest ${errors.token ? 'border-red-500/50' : ''}`}
                  placeholder="000000" value={token}
                  onChange={(e) => { setToken(e.target.value.replace(/\D/g, '')); setErrors((p) => ({ ...p, token: null })); }} />
                {errors.token && <p className="mt-1 text-xs text-red-400">{errors.token}</p>}
                <p className="mt-1 text-xs text-surface-500">Code expires in 15 minutes</p>
              </div>
              <div>
                <label htmlFor="reset-new-password" className="block text-sm font-medium text-surface-300 mb-1.5">New Password</label>
                <input id="reset-new-password" type="password" className={`input-secure ${errors.newPassword ? 'border-red-500/50' : ''}`}
                  placeholder="••••••••" value={newPassword}
                  onChange={(e) => { setNewPassword(e.target.value); setErrors((p) => ({ ...p, newPassword: null })); }} />
                {errors.newPassword && <p className="mt-1 text-xs text-red-400">{errors.newPassword}</p>}
              </div>
              <div>
                <label htmlFor="reset-confirm-password" className="block text-sm font-medium text-surface-300 mb-1.5">Confirm Password</label>
                <input id="reset-confirm-password" type="password" className={`input-secure ${errors.confirmPassword ? 'border-red-500/50' : ''}`}
                  placeholder="••••••••" value={confirmPassword}
                  onChange={(e) => { setConfirmPassword(e.target.value); setErrors((p) => ({ ...p, confirmPassword: null })); }} />
                {errors.confirmPassword && <p className="mt-1 text-xs text-red-400">{errors.confirmPassword}</p>}
              </div>
              <button type="submit" className="btn-primary w-full flex items-center justify-center gap-2" disabled={isLoading}>
                {isLoading ? <Spinner size="sm" /> : null}
                {isLoading ? 'Resetting…' : 'Reset Password'}
              </button>
            </form>
          )}
          {!success && (
            <p className="text-center text-sm text-surface-500 mt-6">
              <Link to="/login" className="text-primary-400 hover:text-primary-300">Back to login</Link>
            </p>
          )}
        </div>
      </div>
    </div>
  );
}
