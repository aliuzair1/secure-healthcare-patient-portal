import { useState, useRef, useEffect } from 'react';
import { Link } from 'react-router-dom';
import { useAuth } from '../../context/AuthContext';
import { useToast } from '../../context/ToastContext';
import { validateEmail, validatePassword, validateMFACode } from '../../utils/validators';
import { MFA_CODE_LENGTH, MFA_MAX_ATTEMPTS, MFA_RESEND_COOLDOWN_S, APP_NAME } from '../../config/constants';
import { resendMFACode } from '../../services/authService';
import { Spinner } from '../../components/ui/Components';

export default function Login() {
  const { loginStep1, loginStep2, authState, AUTH_STATES, backToCredentials } = useAuth();
  const { showToast } = useToast();

  // Step 1: Credentials
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [errors, setErrors] = useState({});
  const [isLoading, setIsLoading] = useState(false);

  // Step 2: MFA
  const [mfaCode, setMfaCode] = useState(['', '', '', '', '', '']);
  const [mfaError, setMfaError] = useState('');
  const [mfaAttempts, setMfaAttempts] = useState(0);
  const [resendCooldown, setResendCooldown] = useState(0);
  const otpRefs = useRef([]);

  const isMfaStep = authState === AUTH_STATES.MFA_REQUIRED;

  // Resend cooldown timer
  useEffect(() => {
    if (resendCooldown <= 0) return;
    const timer = setInterval(() => setResendCooldown((c) => c - 1), 1000);
    return () => clearInterval(timer);
  }, [resendCooldown]);

  // Focus first OTP input when MFA step shows
  useEffect(() => {
    if (isMfaStep && otpRefs.current[0]) {
      otpRefs.current[0].focus();
    }
  }, [isMfaStep]);

  const handleStep1 = async (e) => {
    e.preventDefault();
    const newErrors = {};
    const emailErr = validateEmail(email);
    const passErr = validatePassword(password);
    if (emailErr) newErrors.email = emailErr;
    if (passErr) newErrors.password = passErr;
    if (Object.keys(newErrors).length > 0) { setErrors(newErrors); return; }

    setIsLoading(true);
    setErrors({});
    try {
      await loginStep1(email, password);
      setResendCooldown(MFA_RESEND_COOLDOWN_S);
      showToast('Verification code sent to your email.', 'info');
    } catch (err) {
      showToast(err.message || 'Invalid credentials.', 'error');
    } finally {
      setIsLoading(false);
    }
  };

  const handleOtpChange = (index, value) => {
    if (!/^\d*$/.test(value)) return;
    const newCode = [...mfaCode];
    newCode[index] = value.slice(-1);
    setMfaCode(newCode);
    setMfaError('');

    if (value && index < MFA_CODE_LENGTH - 1) {
      otpRefs.current[index + 1]?.focus();
    }

    // Auto-submit when all filled
    if (newCode.every((d) => d) && newCode.join('').length === MFA_CODE_LENGTH) {
      handleStep2(newCode.join(''));
    }
  };

  const handleOtpKeyDown = (index, e) => {
    if (e.key === 'Backspace' && !mfaCode[index] && index > 0) {
      otpRefs.current[index - 1]?.focus();
    }
  };

  const handleOtpPaste = (e) => {
    e.preventDefault();
    const pasted = e.clipboardData.getData('text').replace(/\D/g, '').slice(0, MFA_CODE_LENGTH);
    if (pasted.length === MFA_CODE_LENGTH) {
      const newCode = pasted.split('');
      setMfaCode(newCode);
      handleStep2(pasted);
    }
  };

  const handleStep2 = async (code) => {
    if (mfaAttempts >= MFA_MAX_ATTEMPTS) {
      setMfaError('Maximum attempts exceeded. Please request a new code.');
      return;
    }
    const err = validateMFACode(code);
    if (err) { setMfaError(err); return; }

    setIsLoading(true);
    try {
      await loginStep2(code);
    } catch (err) {
      setMfaAttempts((a) => a + 1);
      setMfaError(err.message || 'Invalid code.');
      setMfaCode(['', '', '', '', '', '']);
      otpRefs.current[0]?.focus();
    } finally {
      setIsLoading(false);
    }
  };

  const handleResend = async () => {
    if (resendCooldown > 0) return;
    try {
      await resendMFACode();
      setResendCooldown(MFA_RESEND_COOLDOWN_S);
      setMfaAttempts(0);
      setMfaCode(['', '', '', '', '', '']);
      showToast('New code sent.', 'success');
    } catch {
      showToast('Failed to resend code.', 'error');
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center px-4 py-12 bg-surface-950 relative overflow-hidden">
      {/* Background decorations */}
      <div className="absolute top-0 left-1/4 w-96 h-96 bg-primary-500/5 rounded-full blur-3xl" />
      <div className="absolute bottom-0 right-1/4 w-80 h-80 bg-primary-600/5 rounded-full blur-3xl" />

      <div className="w-full max-w-md relative z-10">
        {/* Logo */}
        <div className="text-center mb-8">
          <div className="w-14 h-14 mx-auto rounded-2xl gradient-primary flex items-center justify-center mb-4 glow-primary">
            <svg className="w-8 h-8 text-white" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2.5} d="M12 6v12M6 12h12" />
            </svg>
          </div>
          <h1 className="text-2xl font-bold text-white">{APP_NAME}</h1>
          <p className="text-surface-400 text-sm mt-1">Secure Healthcare Portal</p>
        </div>

        {/* Card */}
        <div className="glass rounded-2xl p-8 border border-surface-700/20">
          {!isMfaStep ? (
            <>
              <div className="mb-6">
                <h2 className="text-xl font-semibold text-white">Welcome back</h2>
                <p className="text-sm text-surface-400 mt-1">Sign in to access your portal</p>
              </div>
              <form onSubmit={handleStep1} className="space-y-5" noValidate>
                <div>
                  <label htmlFor="login-email" className="block text-sm font-medium text-surface-300 mb-1.5">Email Address</label>
                  <input
                    id="login-email" type="email" autoComplete="email"
                    className={`input-secure ${errors.email ? 'border-red-500/50 focus:ring-red-500/40' : ''}`}
                    placeholder="you@example.com"
                    value={email} onChange={(e) => { setEmail(e.target.value); setErrors((p) => ({ ...p, email: null })); }}
                  />
                  {errors.email && <p className="mt-1 text-xs text-red-400">{errors.email}</p>}
                </div>
                <div>
                  <label htmlFor="login-password" className="block text-sm font-medium text-surface-300 mb-1.5">Password</label>
                  <div className="relative">
                    <input
                      id="login-password" type={showPassword ? 'text' : 'password'} autoComplete="current-password"
                      className={`input-secure pr-10 ${errors.password ? 'border-red-500/50 focus:ring-red-500/40' : ''}`}
                      placeholder="••••••••"
                      value={password} onChange={(e) => { setPassword(e.target.value); setErrors((p) => ({ ...p, password: null })); }}
                    />
                    <button type="button" onClick={() => setShowPassword(!showPassword)}
                      className="absolute right-3 top-1/2 -translate-y-1/2 text-surface-400 hover:text-white transition-colors"
                      aria-label={showPassword ? 'Hide password' : 'Show password'}>
                      {showPassword ? (
                        <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M13.875 18.825A10.05 10.05 0 0112 19c-4.478 0-8.268-2.943-9.543-7a9.97 9.97 0 011.563-3.029m5.858.908a3 3 0 114.243 4.243M9.878 9.878l4.242 4.242M9.88 9.88l-3.29-3.29m7.532 7.532l3.29 3.29M3 3l3.59 3.59m0 0A9.953 9.953 0 0112 5c4.478 0 8.268 2.943 9.543 7a10.025 10.025 0 01-4.132 5.411m0 0L21 21" /></svg>
                      ) : (
                        <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" /><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z" /></svg>
                      )}
                    </button>
                  </div>
                  {errors.password && <p className="mt-1 text-xs text-red-400">{errors.password}</p>}
                </div>
                <button type="submit" className="btn-primary w-full flex items-center justify-center gap-2" disabled={isLoading}>
                  {isLoading ? <Spinner size="sm" /> : null}
                  {isLoading ? 'Authenticating…' : 'Sign In'}
                </button>
              </form>
              <div className="mt-6 flex flex-col gap-2 text-center">
                <Link to="/forgot-password" className="text-sm text-primary-400 hover:text-primary-300 transition-colors">Forgot password?</Link>
                <p className="text-sm text-surface-500">
                  New patient? <Link to="/register" className="text-primary-400 hover:text-primary-300 transition-colors">Create account</Link>
                </p>
              </div>
              {/* Demo credentials */}
              <div className="mt-6 p-3 rounded-xl bg-surface-800/40 border border-surface-700/20">
                <p className="text-xs text-surface-500 mb-2">Demo credentials (MFA code: 123456)</p>
                <div className="space-y-1 text-xs text-surface-400">
                  <p>Patient: sarah.chen@email.com / Patient@123</p>
                  <p>Doctor: dr.emily.brooks@medvault.com / Doctor@123</p>
                  <p>Admin: admin@medvault.com / Admin@1234</p>
                </div>
              </div>
            </>
          ) : (
            <>
              <button onClick={backToCredentials} className="flex items-center gap-1 text-sm text-surface-400 hover:text-white transition-colors mb-4">
                <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 19l-7-7 7-7" /></svg>
                Back
              </button>
              <div className="mb-6">
                <h2 className="text-xl font-semibold text-white">Two-Factor Authentication</h2>
                <p className="text-sm text-surface-400 mt-1">Enter the 6-digit code sent to your email</p>
              </div>
              <div className="flex justify-center gap-3 mb-4" onPaste={handleOtpPaste}>
                {mfaCode.map((digit, i) => (
                  <input
                    key={i}
                    ref={(el) => (otpRefs.current[i] = el)}
                    type="text" inputMode="numeric" maxLength={1}
                    className="w-12 h-14 text-center text-xl font-bold input-secure"
                    value={digit}
                    onChange={(e) => handleOtpChange(i, e.target.value)}
                    onKeyDown={(e) => handleOtpKeyDown(i, e)}
                    aria-label={`Digit ${i + 1}`}
                  />
                ))}
              </div>
              {mfaError && <p className="text-sm text-red-400 text-center mb-3">{mfaError}</p>}
              {mfaAttempts > 0 && mfaAttempts < MFA_MAX_ATTEMPTS && (
                <p className="text-xs text-surface-500 text-center mb-3">
                  {MFA_MAX_ATTEMPTS - mfaAttempts} attempt{MFA_MAX_ATTEMPTS - mfaAttempts !== 1 ? 's' : ''} remaining
                </p>
              )}
              {isLoading && (
                <div className="flex justify-center mb-3"><Spinner size="sm" /></div>
              )}
              <div className="text-center">
                <button
                  onClick={handleResend}
                  disabled={resendCooldown > 0}
                  className="text-sm text-primary-400 hover:text-primary-300 disabled:text-surface-600 transition-colors"
                >
                  {resendCooldown > 0 ? `Resend code in ${resendCooldown}s` : 'Resend code'}
                </button>
              </div>
              <div className="mt-6 p-3 rounded-xl bg-surface-800/40 border border-surface-700/20 text-center">
                <p className="text-xs text-surface-500">Demo MFA code: <span className="text-primary-400 font-mono font-bold">123456</span></p>
              </div>
            </>
          )}
        </div>

        <p className="text-center text-xs text-surface-600 mt-6">
          Protected by 256-bit encryption · HIPAA Compliant
        </p>
      </div>
    </div>
  );
}
