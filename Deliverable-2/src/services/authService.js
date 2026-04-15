/**
 * authService.js
 *
 * All auth operations use the Supabase Auth SDK directly.
 * Token refresh and session persistence are handled automatically
 * by the Supabase client — no manual refresh logic is needed here.
 *
 * MFA flow (TOTP):
 *   Step 1 — loginWithCredentials  → signInWithPassword → returns mfaRequired flag
 *   Step 2 — verifyMFA             → mfa.challengeAndVerify → elevates session to AAL2
 *
 * If a user has no TOTP factor enrolled, Step 2 is skipped and the
 * session is considered authenticated at AAL1.
 */
import { supabase } from '../lib/supabaseClient';

export async function loginWithCredentials(email, password) {
  const { data, error } = await supabase.auth.signInWithPassword({ email, password });

  if (error) {
    if (
      error.message.toLowerCase().includes('invalid login') ||
      error.message.toLowerCase().includes('invalid credentials')
    ) {
      throw { status: 401, message: 'Invalid email or password.' };
    }
    throw { status: 401, message: 'Login failed. Please try again.' };
  }

  // Validate profile is active and (for doctors) approved
  const { data: profile, error: profileError } = await supabase
    .from('profiles')
    .select('role, is_active, is_approved')
    .eq('id', data.user.id)
    .single();

  if (profileError || !profile) {
    await supabase.auth.signOut();
    throw { status: 403, message: 'Account not found. Please contact support.' };
  }

  if (!profile.is_active) {
    await supabase.auth.signOut();
    throw { status: 403, message: 'Your account has been deactivated. Please contact support.' };
  }

  if (profile.role === 'doctor' && !profile.is_approved) {
    await supabase.auth.signOut();
    throw { status: 403, message: 'Your account is pending approval.' };
  }

  // Check if MFA elevation is required (user has TOTP enrolled)
  const { data: aal } = await supabase.auth.mfa.getAuthenticatorAssuranceLevel();

  if (aal?.nextLevel === 'aal2' && aal?.currentLevel !== 'aal2') {
    const { data: factors } = await supabase.auth.mfa.listFactors();
    const totpFactor = factors?.totp?.[0];

    if (totpFactor) {
      const { data: challenge, error: challengeErr } = await supabase.auth.mfa.challenge({
        factorId: totpFactor.id,
      });

      if (challengeErr) {
        throw { status: 500, message: 'Failed to initiate MFA challenge. Please try again.' };
      }

      return {
        userId: data.user.id,
        mfaRequired: true,
        mfaMethod: 'totp',
        factorId: totpFactor.id,
        challengeId: challenge.id,
      };
    }
  }

  // No MFA enrolled — session is ready at AAL1
  return { userId: data.user.id, mfaRequired: false };
}

export async function verifyMFA(userId, code, { factorId, challengeId } = {}) {
  if (!factorId || !challengeId) {
    throw { status: 400, message: 'MFA session expired. Please log in again.' };
  }

  const { error } = await supabase.auth.mfa.verify({
    factorId,
    challengeId,
    code,
  });

  if (error) {
    if (error.message.toLowerCase().includes('invalid')) {
      throw { status: 401, message: 'Invalid verification code.' };
    }
    throw { status: 401, message: 'MFA verification failed. Please try again.' };
  }

  return { verified: true };
}

export async function getSessionUser() {
  const { data: { session } } = await supabase.auth.getSession();
  if (!session) return null;

  const { data: profile } = await supabase
    .from('profiles')
    .select('*')
    .eq('id', session.user.id)
    .single();

  if (!profile) return null;

  return {
    id: profile.id,
    email: session.user.email,
    role: profile.role,
    firstName: profile.first_name,
    lastName: profile.last_name,
    phone: profile.phone,
    dob: profile.dob,
    gender: profile.gender,
    address: profile.address,
    emergencyContact: profile.emergency_contact,
    allergies: profile.allergies,
    bloodType: profile.blood_type,
    assignedDoctorId: profile.assigned_doctor_id,
    specialty: profile.specialty,
    licenseNumber: profile.license_number,
    department: profile.department,
    isApproved: profile.is_approved,
    isActive: profile.is_active,
    mfaEnabled: profile.mfa_enabled,
    createdAt: profile.created_at,
  };
}

export async function requestPasswordReset(email) {
  const redirectTo = `${import.meta.env.VITE_APP_URL}/reset-password`;
  // Always return success to prevent email enumeration
  await supabase.auth.resetPasswordForEmail(email, { redirectTo });
  return { message: 'If an account exists with that email, a reset link has been sent.' };
}

export async function resetPassword(newPassword) {
  const { error } = await supabase.auth.updateUser({ password: newPassword });
  if (error) throw { status: 400, message: 'Failed to reset password. The link may have expired.' };
  return { message: 'Password has been reset successfully.' };
}

export async function registerPatient(data) {
  const { error } = await supabase.auth.signUp({
    email: data.email,
    password: data.password,
    options: {
      data: {
        role: 'patient',
        first_name: data.firstName,
        last_name: data.lastName,
      },
      emailRedirectTo: `${import.meta.env.VITE_APP_URL}/login`,
    },
  });

  if (error) {
    if (error.message.toLowerCase().includes('already registered')) {
      throw { status: 409, message: 'An account with this email already exists.' };
    }
    throw { status: 500, message: 'Registration failed. Please try again.' };
  }

  // Update additional profile fields after the trigger creates the base profile
  const { data: { user } } = await supabase.auth.getUser();
  if (user) {
    await supabase.from('profiles').update({
      phone: data.phone || null,
      dob: data.dob || null,
      gender: data.gender || null,
    }).eq('id', user.id);
  }

  return { message: 'Registration successful. Please check your email to verify your account.' };
}

export async function logout() {
  await supabase.auth.signOut();
  return { message: 'Logged out successfully.' };
}

export async function resendMFACode() {
  // TOTP codes are generated by the authenticator app — no server-side resend needed.
  // For email OTP, call supabase.auth.signInWithOtp({ email }) here instead.
  return { message: 'Please use your authenticator app to get a new code.' };
}
