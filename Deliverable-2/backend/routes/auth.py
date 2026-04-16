"""
/api/auth  — authentication endpoints.

Login, MFA verification, registration, password reset, and the
/me endpoint that returns the current user's profile.

Auth (token issuance) is delegated to Supabase; the JWT it returns
is then validated on every subsequent request by middleware/auth.py.
"""
import logging

import requests as http
from flask import Blueprint, current_app, g, request
from middleware.auth import require_auth
from services.supabase_client import get_supabase
from utils.responses import (
    bad_request,
    conflict,
    created,
    forbidden,
    server_error,
    success,
    unauthorized,
)
from utils.validators import (
    validate_email,
    validate_mfa_code,
    validate_name,
    validate_password,
    validate_phone,
    validate_dob,
    collect_errors,
)

bp = Blueprint("auth", __name__, url_prefix="/api/auth")
logger = logging.getLogger(__name__)


def _supabase_auth_url(path: str) -> str:
    base = current_app.config["SUPABASE_URL"].rstrip("/")
    return f"{base}/auth/v1/{path.lstrip('/')}"


def _supabase_headers() -> dict:
    return {
        "apikey": current_app.config["SUPABASE_SERVICE_ROLE_KEY"],
        "Content-Type": "application/json",
    }


# ------------------------------------------------------------------ #
#  POST /api/auth/login                                                #
# ------------------------------------------------------------------ #
@bp.post("/login")
def login():
    """
    Step 1 of login: validate credentials via Supabase Auth.
    Returns either a session (no MFA) or an MFA challenge.
    """
    data = request.get_json(silent=True) or {}
    email = (data.get("email") or "").strip().lower()
    password = data.get("password") or ""

    err = collect_errors(
        email=validate_email(email),
        password=validate_password(password),
    )
    if err:
        return bad_request(err)

    # Call Supabase Auth REST
    resp = http.post(
        _supabase_auth_url("token?grant_type=password"),
        json={"email": email, "password": password},
        headers=_supabase_headers(),
        timeout=10,
    )

    if resp.status_code == 400:
        return unauthorized("Invalid email or password.")
    if resp.status_code != 200:
        return unauthorized("Login failed. Please try again.")

    token_data = resp.json()
    access_token = token_data.get("access_token")
    refresh_token = token_data.get("refresh_token")
    user_id = token_data.get("user", {}).get("id")

    if not access_token or not user_id:
        return server_error()

    # Fetch our app profile to apply business-level checks
    sb = get_supabase()
    profile_res = (
        sb.table("profiles")
        .select("role, is_active, is_approved")
        .eq("id", user_id)
        .single()
        .execute()
    )
    profile = profile_res.data
    if not profile:
        return forbidden("Account not found. Please contact support.")

    if not profile.get("is_active"):
        return forbidden("Your account has been deactivated.")

    if profile.get("role") == "doctor" and not profile.get("is_approved"):
        return forbidden("Your account is pending approval.")

    # Check MFA requirement
    aal_resp = http.get(
        _supabase_auth_url("factors"),
        headers={**_supabase_headers(), "Authorization": f"Bearer {access_token}"},
        timeout=10,
    )
    totp_factor = None
    if aal_resp.status_code == 200:
        factors = aal_resp.json()
        totp_factors = [
            f for f in (factors.get("totp") or []) if f.get("status") == "verified"
        ]
        if totp_factors:
            totp_factor = totp_factors[0]

    if totp_factor:
        # Initiate MFA challenge
        challenge_resp = http.post(
            _supabase_auth_url("factors/{}/challenge".format(totp_factor["id"])),
            headers={**_supabase_headers(), "Authorization": f"Bearer {access_token}"},
            timeout=10,
        )
        if challenge_resp.status_code != 200:
            return server_error("Failed to initiate MFA challenge.")
        challenge_data = challenge_resp.json()
        return success(
            {
                "mfaRequired": True,
                "mfaMethod": "totp",
                "factorId": totp_factor["id"],
                "challengeId": challenge_data.get("id"),
                "accessToken": access_token,   # needed for step 2
            }
        )

    # No MFA — return session directly
    return success(
        {
            "mfaRequired": False,
            "accessToken": access_token,
            "refreshToken": refresh_token,
        }
    )


# ------------------------------------------------------------------ #
#  POST /api/auth/mfa-verify                                           #
# ------------------------------------------------------------------ #
@bp.post("/mfa-verify")
def mfa_verify():
    """Step 2 of login: verify TOTP code and elevate to AAL2."""
    data = request.get_json(silent=True) or {}
    access_token = data.get("accessToken") or ""
    factor_id = data.get("factorId") or ""
    challenge_id = data.get("challengeId") or ""
    code = (data.get("code") or "").strip()

    if not access_token or not factor_id or not challenge_id:
        return bad_request("MFA session expired. Please log in again.")

    err = validate_mfa_code(code)
    if err:
        return bad_request(err)

    verify_resp = http.post(
        _supabase_auth_url(f"factors/{factor_id}/verify"),
        json={"challenge_id": challenge_id, "code": code},
        headers={**_supabase_headers(), "Authorization": f"Bearer {access_token}"},
        timeout=10,
    )

    if verify_resp.status_code != 200:
        body = verify_resp.json()
        msg = body.get("msg", "")
        if "invalid" in msg.lower():
            return unauthorized("Invalid verification code.")
        return unauthorized("MFA verification failed. Please try again.")

    token_data = verify_resp.json()
    return success(
        {
            "verified": True,
            "accessToken": token_data.get("access_token"),
            "refreshToken": token_data.get("refresh_token"),
        }
    )


# ------------------------------------------------------------------ #
#  POST /api/auth/register                                             #
# ------------------------------------------------------------------ #
@bp.post("/register")
def register():
    """Register a new patient account."""
    data = request.get_json(silent=True) or {}
    email = (data.get("email") or "").strip().lower()
    password = data.get("password") or ""
    first_name = (data.get("firstName") or "").strip()
    last_name = (data.get("lastName") or "").strip()
    phone = (data.get("phone") or "").strip() or None
    dob = (data.get("dob") or "").strip() or None
    gender = (data.get("gender") or "").strip() or None

    err = collect_errors(
        email=validate_email(email),
        password=validate_password(password),
        first_name=validate_name(first_name, "First name"),
        last_name=validate_name(last_name, "Last name"),
        phone=validate_phone(phone),
        dob=validate_dob(dob) if dob else None,
    )
    if err:
        return bad_request(err)

    app_url = current_app.config.get("APP_URL", "")

    resp = http.post(
        _supabase_auth_url("signup"),
        json={
            "email": email,
            "password": password,
            "options": {
                "data": {
                    "role": "patient",
                    "first_name": first_name,
                    "last_name": last_name,
                },
                "emailRedirectTo": f"{app_url}/login",
            },
        },
        headers=_supabase_headers(),
        timeout=10,
    )

    if resp.status_code == 422:
        body = resp.json()
        msg = (body.get("msg") or body.get("message") or "").lower()
        if "already registered" in msg or "already exists" in msg:
            return conflict("An account with this email already exists.")

    if resp.status_code not in (200, 201):
        return server_error("Registration failed. Please try again.")

    user_data = resp.json()
    user_id = (user_data.get("user") or {}).get("id") or user_data.get("id")

    # Update optional profile fields created by the DB trigger
    if user_id and any([phone, dob, gender]):
        updates = {}
        if phone:
            updates["phone"] = phone
        if dob:
            updates["dob"] = dob
        if gender:
            updates["gender"] = gender
        try:
            get_supabase().table("profiles").update(updates).eq("id", user_id).execute()
        except Exception as exc:
            logger.warning("Could not update profile extras for %s: %s", user_id, exc)

    return created(
        message="Registration successful. Please check your email to verify your account."
    )


# ------------------------------------------------------------------ #
#  POST /api/auth/forgot-password                                      #
# ------------------------------------------------------------------ #
@bp.post("/forgot-password")
def forgot_password():
    """Trigger a password-reset email. Always returns 200 to prevent enumeration."""
    data = request.get_json(silent=True) or {}
    email = (data.get("email") or "").strip().lower()

    # Silently ignore validation errors — don't leak whether email exists
    if not validate_email(email):
        app_url = current_app.config.get("APP_URL", "")
        http.post(
            _supabase_auth_url("recover"),
            json={"email": email, "options": {"redirectTo": f"{app_url}/reset-password"}},
            headers=_supabase_headers(),
            timeout=10,
        )

    return success(
        message="If an account exists with that email, a reset link has been sent."
    )


# ------------------------------------------------------------------ #
#  POST /api/auth/reset-password                                       #
# ------------------------------------------------------------------ #
@bp.post("/reset-password")
@require_auth
def reset_password():
    """Set a new password (requires a valid session from the reset link)."""
    data = request.get_json(silent=True) or {}
    new_password = data.get("newPassword") or ""

    err = validate_password(new_password)
    if err:
        return bad_request(err)

    resp = http.put(
        _supabase_auth_url("user"),
        json={"password": new_password},
        headers={
            **_supabase_headers(),
            "Authorization": request.headers.get("Authorization", ""),
        },
        timeout=10,
    )

    if resp.status_code != 200:
        return bad_request("Failed to reset password. The link may have expired.")

    return success(message="Password has been reset successfully.")


# ------------------------------------------------------------------ #
#  POST /api/auth/logout                                               #
# ------------------------------------------------------------------ #
@bp.post("/logout")
@require_auth
def logout():
    """Invalidate the current session."""
    http.post(
        _supabase_auth_url("logout"),
        headers={
            **_supabase_headers(),
            "Authorization": request.headers.get("Authorization", ""),
        },
        timeout=10,
    )
    return success(message="Logged out successfully.")


# ------------------------------------------------------------------ #
#  GET /api/auth/me                                                    #
# ------------------------------------------------------------------ #
@bp.get("/me")
@require_auth
def me():
    """Return the current user's full profile (populated by require_auth)."""
    p = g.user
    role = g.user_role

    profile = {
        "id": p.get("id"),
        "email": p.get("email"),
        "role": role,
        "firstName": p.get("first_name"),
        "lastName": p.get("last_name"),
        "phone": p.get("phone"),
        "dob": p.get("dob"),
        "gender": p.get("gender"),
        "address": p.get("address"),
        "emergencyContact": p.get("emergency_contact"),
        "allergies": p.get("allergies") or [],
        "bloodType": p.get("blood_type"),
        "assignedDoctorId": p.get("assigned_doctor_id"),
        "isActive": p.get("is_active"),
        "mfaEnabled": p.get("mfa_enabled"),
        "createdAt": p.get("created_at"),
    }

    if role == "doctor":
        profile.update(
            {
                "specialty": p.get("specialty"),
                "licenseNumber": p.get("license_number"),
                "department": p.get("department"),
                "isApproved": p.get("is_approved"),
            }
        )

    return success(profile)
