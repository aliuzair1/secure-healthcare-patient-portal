import { createContext, useContext, useState, useCallback, useEffect, useRef } from 'react';
import { useNavigate } from 'react-router-dom';
import { INACTIVITY_TIMEOUT_MS } from '../config/constants';
import { supabase } from '../lib/supabaseClient';
import * as authService from '../services/authService';
import { useToast } from './ToastContext';

const AuthContext = createContext(null);

const AUTH_STATES = {
  IDLE: 'idle',
  CREDENTIALS_SUBMITTED: 'credentials_submitted',
  MFA_REQUIRED: 'mfa_required',
  AUTHENTICATED: 'authenticated',
  LOADING: 'loading',
};

export function AuthProvider({ children }) {
  const [user, setUser] = useState(null);
  const [authState, setAuthState] = useState(AUTH_STATES.LOADING);
  // mfaChallenge holds { userId, factorId, challengeId } during step-2
  const [mfaChallenge, setMfaChallenge] = useState(null);
  const navigate = useNavigate();
  const { showToast } = useToast();

  const inactivityTimer = useRef(null);

  // ---- Inactivity timeout ----
  const resetInactivityTimer = useCallback(() => {
    if (inactivityTimer.current) clearTimeout(inactivityTimer.current);
    inactivityTimer.current = setTimeout(() => {
      handleLogout('Your session expired due to inactivity.');
    }, INACTIVITY_TIMEOUT_MS);
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  const setupInactivityTracking = useCallback(() => {
    const events = ['mousedown', 'keydown', 'scroll', 'touchstart', 'mousemove'];
    const handler = () => resetInactivityTimer();
    events.forEach((e) => window.addEventListener(e, handler, { passive: true }));
    resetInactivityTimer();
    return () => {
      events.forEach((e) => window.removeEventListener(e, handler));
      if (inactivityTimer.current) clearTimeout(inactivityTimer.current);
    };
  }, [resetInactivityTimer]);

  // ---- Supabase auth state listener ----
  // Supabase handles token refresh automatically — we only need to react
  // to session changes here.
  useEffect(() => {
    // Load initial session on mount
    supabase.auth.getSession().then(async ({ data: { session } }) => {
      if (session) {
        const profile = await authService.getSessionUser();
        if (profile) {
          setUser(profile);
          setAuthState(AUTH_STATES.AUTHENTICATED);
        } else {
          setAuthState(AUTH_STATES.IDLE);
        }
      } else {
        setAuthState(AUTH_STATES.IDLE);
      }
    });

    // Subscribe to future auth changes (token refresh, sign-out, etc.)
    const { data: { subscription } } = supabase.auth.onAuthStateChange(
      async (event, session) => {
        if (event === 'SIGNED_OUT' || !session) {
          setUser(null);
          setMfaChallenge(null);
          setAuthState(AUTH_STATES.IDLE);
          if (inactivityTimer.current) clearTimeout(inactivityTimer.current);
          return;
        }

        if (event === 'SIGNED_IN' || event === 'TOKEN_REFRESHED') {
          const profile = await authService.getSessionUser();
          if (profile) {
            setUser(profile);
            setAuthState(AUTH_STATES.AUTHENTICATED);
          }
        }

        if (event === 'PASSWORD_RECOVERY') {
          navigate('/reset-password');
        }
      }
    );

    return () => subscription.unsubscribe();
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  // ---- Setup inactivity tracking when authenticated ----
  useEffect(() => {
    if (authState === AUTH_STATES.AUTHENTICATED) {
      return setupInactivityTracking();
    }
  }, [authState, setupInactivityTracking]);

  // ---- Auth actions ----
  const loginStep1 = async (email, password) => {
    setAuthState(AUTH_STATES.LOADING);
    try {
      const result = await authService.loginWithCredentials(email, password);

      if (result.mfaRequired) {
        setMfaChallenge({
          userId: result.userId,
          factorId: result.factorId,
          challengeId: result.challengeId,
        });
        setAuthState(AUTH_STATES.MFA_REQUIRED);
      } else {
        // No MFA enrolled — fetch profile and complete login
        const profile = await authService.getSessionUser();
        setUser(profile);
        setAuthState(AUTH_STATES.AUTHENTICATED);
        showToast('Login successful. Welcome back!', 'success');
        const roleRoutes = { patient: '/patient', doctor: '/doctor', admin: '/admin' };
        navigate(roleRoutes[profile?.role] || '/');
      }

      return result;
    } catch (err) {
      setAuthState(AUTH_STATES.IDLE);
      throw err;
    }
  };

  const loginStep2 = async (code) => {
    setAuthState(AUTH_STATES.LOADING);
    try {
      await authService.verifyMFA(mfaChallenge?.userId, code, {
        factorId: mfaChallenge?.factorId,
        challengeId: mfaChallenge?.challengeId,
      });

      const profile = await authService.getSessionUser();
      setUser(profile);
      setMfaChallenge(null);
      setAuthState(AUTH_STATES.AUTHENTICATED);
      showToast('Login successful. Welcome back!', 'success');
      const roleRoutes = { patient: '/patient', doctor: '/doctor', admin: '/admin' };
      navigate(roleRoutes[profile?.role] || '/');
    } catch (err) {
      setAuthState(AUTH_STATES.MFA_REQUIRED);
      throw err;
    }
  };

  const handleLogout = useCallback(async (message) => {
    try { await authService.logout(); } catch {}
    // onAuthStateChange will clear user state; we navigate here for immediacy
    setUser(null);
    setMfaChallenge(null);
    setAuthState(AUTH_STATES.IDLE);
    if (inactivityTimer.current) clearTimeout(inactivityTimer.current);
    navigate('/login');
    if (message) showToast(message, 'info');
  }, [navigate, showToast]);

  const backToCredentials = () => {
    setMfaChallenge(null);
    setAuthState(AUTH_STATES.IDLE);
  };

  const value = {
    user,
    authState,
    isAuthenticated: authState === AUTH_STATES.AUTHENTICATED,
    isLoading: authState === AUTH_STATES.LOADING,
    mfaUserId: mfaChallenge?.userId ?? null,
    loginStep1,
    loginStep2,
    logout: () => handleLogout('You have been logged out.'),
    backToCredentials,
    AUTH_STATES,
  };

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth() {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error('useAuth must be used within an AuthProvider');
  return ctx;
}

export default AuthContext;
