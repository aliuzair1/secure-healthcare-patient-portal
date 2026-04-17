"""
JWT authentication + role-based access control middleware.

Every protected route must be decorated with @require_auth.
Role-specific routes additionally use @require_role('patient'|'doctor'|'admin').

Flow:
  1. Extract Bearer token from Authorization header.
  2. Validate the Supabase-issued JWT (signature + expiry).
  3. Look up the user profile in the `profiles` table.
  4. Verify the account is active (and approved for doctors).
  5. Store user info in Flask's g object for route handlers to use.
"""
import logging
from functools import wraps

import jwt
from flask import current_app, g, request
from services.supabase_client import get_supabase
from utils.responses import forbidden, unauthorized
from functools import lru_cache

@lru_cache(maxsize=1)
def get_jwks_client():
    url = current_app.config.get("SUPABASE_URL", "").rstrip("/")
    jwks_url = f"{url}/auth/v1/jwks"
    return jwt.PyJWKClient(jwks_url)

logger = logging.getLogger(__name__)

VALID_ROLES = {"patient", "doctor", "admin"}


# ------------------------------------------------------------------ #
#  Internal helpers                                                    #
# ------------------------------------------------------------------ #

def _decode_jwt(token: str) -> dict | None:
    try:
        # First attempt: Decode via symmetric secret (HS256)
        secret = current_app.config.get("SUPABASE_JWT_SECRET", "")
        return jwt.decode(
            token, secret, algorithms=["HS256"], audience="authenticated", options={"verify_exp": True}
        )
    except jwt.InvalidTokenError:
        pass

    try:
        # Second attempt: Decode via Asymmetric Public Key (RS256, ES256) fetched from JWKS
        jwks_client = get_jwks_client()
        signing_key = jwks_client.get_signing_key_from_jwt(token)
        return jwt.decode(
            token,
            signing_key.key,
            algorithms=["RS256", "ES256"],
            audience="authenticated",
            options={"verify_exp": True}
        )
    except Exception as exc:
        logger.error("Token validation failed: %s", exc)
        return None



def _fetch_profile(user_id: str) -> dict | None:
    """Fetch the user profile from Supabase. Returns dict or None."""
    try:
        result = (
            get_supabase()
            .table("profiles")
            .select(
                "id, role, first_name, last_name, is_active, is_approved, "
                "mfa_enabled, specialty, license_number, department, "
                "assigned_doctor_id"
            )
            .eq("id", user_id)
            .single()
            .execute()
        )
        return result.data
    except Exception as exc:
        logger.warning("Profile lookup failed for %s: %s", user_id, exc)
        return None


# ------------------------------------------------------------------ #
#  Public decorators                                                   #
# ------------------------------------------------------------------ #

def require_auth(f):
    """
    Validates the Supabase JWT and populates g with:
      g.user_id   – UUID string
      g.user      – full profile dict from the profiles table
      g.user_role – 'patient' | 'doctor' | 'admin'
      g.aal       – Authenticator Assurance Level ('aal1' | 'aal2')
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return unauthorized()

        token = auth_header[7:].strip()
        if not token:
            return unauthorized()

        payload = _decode_jwt(token)
        if not payload:
            return unauthorized("Invalid or expired session.")

        user_id = payload.get("sub")
        if not user_id:
            return unauthorized("Invalid token.")

        profile = _fetch_profile(user_id)
        if not profile:
            return unauthorized("Account not found.")

        if not profile.get("is_active"):
            return forbidden("Your account has been deactivated.")

        role = profile.get("role")
        if role not in VALID_ROLES:
            return forbidden("Account role is not recognised.")

        # Doctors must be approved before accessing any data endpoint.
        if role == "doctor" and not profile.get("is_approved"):
            return forbidden("Your account is pending approval.")

        g.user_id = user_id
        g.user = profile
        g.user_role = role
        g.aal = payload.get("aal", "aal1")

        return f(*args, **kwargs)

    return decorated


def require_role(*roles):
    """
    Must be applied INSIDE @require_auth (i.e. closer to the function).

        @require_auth
        @require_role('admin')
        def my_view(): ...
    """
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            if not hasattr(g, "user_role") or g.user_role not in roles:
                return forbidden()
            return f(*args, **kwargs)
        return decorated
    return decorator


def require_mfa(f):
    """
    Require AAL2 (completed TOTP) for sensitive operations.
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        if getattr(g, "aal", "aal1") != "aal2":
            return forbidden("Multi-factor authentication is required.")
        return f(*args, **kwargs)
    return decorated


def require_self_or_role(param_name: str, *roles):
    """
    Allow access if the requesting user owns the resource OR has one of the
    given roles. The URL parameter `param_name` must match the user's own ID.

    Example:  GET /api/patient/<patient_id>/profile
      → patients can only read their own profile
      → doctors/admins can read any patient profile
    """
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            resource_id = kwargs.get(param_name)
            is_owner = resource_id and resource_id == getattr(g, "user_id", None)
            has_role = getattr(g, "user_role", None) in roles
            if not is_owner and not has_role:
                return forbidden()
            return f(*args, **kwargs)
        return decorated
    return decorator
