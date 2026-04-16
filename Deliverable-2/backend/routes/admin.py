"""
/api/admin  — admin-only management endpoints.

All routes require role == 'admin'.
"""
import logging

from flask import Blueprint, g, request
from middleware.auth import require_auth, require_role
from services.supabase_client import get_supabase
from utils.responses import bad_request, not_found, server_error, success
from utils.validators import (
    collect_errors,
    validate_boolean,
    validate_integer,
    validate_list_of_strings,
    validate_string,
    validate_uuid,
)

bp = Blueprint("admin", __name__, url_prefix="/api/admin")
logger = logging.getLogger(__name__)


# ------------------------------------------------------------------ #
#  User management                                                     #
# ------------------------------------------------------------------ #

@bp.get("/users")
@require_auth
@require_role("admin")
def get_all_users():
    try:
        res = (
            get_supabase()
            .table("profiles")
            .select("*")
            .order("created_at", desc=True)
            .execute()
        )
    except Exception as exc:
        logger.error("get_all_users failed: %s", exc)
        return server_error()

    return success({"users": [_map_profile(p) for p in (res.data or [])]})


@bp.patch("/users/<user_id>/status")
@require_auth
@require_role("admin")
def toggle_user_status(user_id):
    err = validate_uuid(user_id, "user_id")
    if err:
        return bad_request(err)

    # Prevent an admin from deactivating themselves
    if user_id == g.user_id:
        return bad_request("You cannot change your own account status.")

    data = request.get_json(silent=True) or {}
    is_active = data.get("isActive")

    err = validate_boolean(is_active, "isActive")
    if err:
        return bad_request(err)

    try:
        get_supabase().table("profiles").update({"is_active": is_active}).eq("id", user_id).execute()
    except Exception as exc:
        logger.error("toggle_user_status failed: %s", exc)
        return server_error()

    action = "activated" if is_active else "deactivated"
    return success(message=f"User {action} successfully.")


# ------------------------------------------------------------------ #
#  Doctor approvals                                                    #
# ------------------------------------------------------------------ #

@bp.get("/doctors/pending")
@require_auth
@require_role("admin")
def get_pending_doctors():
    try:
        res = (
            get_supabase()
            .table("profiles")
            .select("*")
            .eq("role", "doctor")
            .eq("is_approved", False)
            .execute()
        )
    except Exception as exc:
        logger.error("get_pending_doctors failed: %s", exc)
        return server_error()

    return success({"doctors": [_map_profile(p) for p in (res.data or [])]})


@bp.patch("/doctors/<doctor_id>/approve")
@require_auth
@require_role("admin")
def approve_doctor(doctor_id):
    err = validate_uuid(doctor_id, "doctor_id")
    if err:
        return bad_request(err)

    if not _doctor_exists(doctor_id):
        return not_found("Doctor not found.")

    try:
        get_supabase().table("profiles").update({"is_approved": True}).eq("id", doctor_id).eq("role", "doctor").execute()
    except Exception as exc:
        logger.error("approve_doctor failed: %s", exc)
        return server_error()

    return success(message="Doctor account approved successfully.")


@bp.patch("/doctors/<doctor_id>/reject")
@require_auth
@require_role("admin")
def reject_doctor(doctor_id):
    err = validate_uuid(doctor_id, "doctor_id")
    if err:
        return bad_request(err)

    if not _doctor_exists(doctor_id):
        return not_found("Doctor not found.")

    try:
        # Soft-deactivate — preserves audit trail
        get_supabase().table("profiles").update({"is_active": False}).eq("id", doctor_id).eq("role", "doctor").execute()
    except Exception as exc:
        logger.error("reject_doctor failed: %s", exc)
        return server_error()

    return success(message="Doctor account has been rejected.")


# ------------------------------------------------------------------ #
#  Patient assignment                                                  #
# ------------------------------------------------------------------ #

@bp.get("/assignments")
@require_auth
@require_role("admin")
def get_patient_assignments():
    sb = get_supabase()
    try:
        p_res = sb.table("profiles").select("*").eq("role", "patient").execute()
        d_res = (
            sb.table("profiles")
            .select("*")
            .eq("role", "doctor")
            .eq("is_approved", True)
            .execute()
        )
    except Exception as exc:
        logger.error("get_patient_assignments failed: %s", exc)
        return server_error()

    patients = [_map_profile(p) for p in (p_res.data or [])]
    doctors = [_map_profile(d) for d in (d_res.data or [])]
    doctor_map = {d["id"]: d for d in doctors}

    assignments = [
        {
            "patientId": p["id"],
            "patientName": f"{p['firstName']} {p['lastName']}",
            "doctorId": p.get("assignedDoctorId"),
            "doctorName": (
                f"Dr. {doctor_map[p['assignedDoctorId']]['firstName']} "
                f"{doctor_map[p['assignedDoctorId']]['lastName']}"
                if p.get("assignedDoctorId") and p["assignedDoctorId"] in doctor_map
                else "Unassigned"
            ),
        }
        for p in patients
    ]

    return success({"patients": patients, "doctors": doctors, "assignments": assignments})


@bp.patch("/patients/<patient_id>/assign")
@require_auth
@require_role("admin")
def assign_patient(patient_id):
    err = validate_uuid(patient_id, "patient_id")
    if err:
        return bad_request(err)

    data = request.get_json(silent=True) or {}
    doctor_id = (data.get("doctorId") or "").strip() or None

    if doctor_id:
        err = validate_uuid(doctor_id, "doctorId")
        if err:
            return bad_request(err)

    try:
        get_supabase().table("profiles").update({"assigned_doctor_id": doctor_id}).eq("id", patient_id).eq("role", "patient").execute()
    except Exception as exc:
        logger.error("assign_patient failed: %s", exc)
        return server_error()

    return success(message="Patient assigned to doctor successfully.")


# ------------------------------------------------------------------ #
#  Scheduling configuration                                            #
# ------------------------------------------------------------------ #

@bp.get("/scheduling/config")
@require_auth
@require_role("admin")
def get_scheduling_config():
    try:
        res = (
            get_supabase()
            .table("scheduling_config")
            .select("*")
            .eq("id", 1)
            .single()
            .execute()
        )
    except Exception:
        pass
    else:
        if res.data:
            return success(_map_config(res.data))

    # Return sensible defaults if no row exists
    return success(
        {
            "slotDurationMinutes": 30,
            "maxAppointmentsPerDay": 16,
            "workingHours": {"start": "09:00", "end": "17:00"},
            "blackoutDates": [],
            "lunchBreak": {"start": "12:00", "end": "13:00"},
        }
    )


@bp.post("/scheduling/config")
@require_auth
@require_role("admin")
def update_scheduling_config():
    data = request.get_json(silent=True) or {}

    slot_dur = data.get("slotDurationMinutes")
    max_appts = data.get("maxAppointmentsPerDay")
    working_hours = data.get("workingHours")
    blackout_dates = data.get("blackoutDates")
    lunch_break = data.get("lunchBreak")

    errors = []
    if slot_dur is not None:
        e = validate_integer(slot_dur, "Slot duration", min_val=5, max_val=240)
        if e:
            errors.append(e)
    if max_appts is not None:
        e = validate_integer(max_appts, "Max appointments per day", min_val=1, max_val=100)
        if e:
            errors.append(e)
    if blackout_dates is not None:
        e = validate_list_of_strings(blackout_dates, "Blackout dates", max_items=365, item_max_len=10)
        if e:
            errors.append(e)
    if working_hours is not None and not isinstance(working_hours, dict):
        errors.append("Working hours must be an object.")
    if lunch_break is not None and not isinstance(lunch_break, dict):
        errors.append("Lunch break must be an object.")

    if errors:
        return bad_request(errors[0])

    from datetime import datetime
    upsert_data = {"id": 1, "updated_at": datetime.utcnow().isoformat()}
    if slot_dur is not None:
        upsert_data["slot_duration_minutes"] = slot_dur
    if max_appts is not None:
        upsert_data["max_appointments_per_day"] = max_appts
    if working_hours is not None:
        upsert_data["working_hours"] = working_hours
    if blackout_dates is not None:
        upsert_data["blackout_dates"] = blackout_dates
    if lunch_break is not None:
        upsert_data["lunch_break"] = lunch_break

    try:
        get_supabase().table("scheduling_config").upsert(upsert_data).execute()
    except Exception as exc:
        logger.error("update_scheduling_config failed: %s", exc)
        return server_error()

    return success(message="Scheduling configuration updated.")


# ------------------------------------------------------------------ #
#  System statistics                                                   #
# ------------------------------------------------------------------ #

@bp.get("/stats")
@require_auth
@require_role("admin")
def get_system_stats():
    try:
        res = (
            get_supabase()
            .table("profiles")
            .select("role, is_approved, is_active")
            .execute()
        )
    except Exception as exc:
        logger.error("get_system_stats failed: %s", exc)
        return server_error()

    rows = res.data or []
    patients = [r for r in rows if r.get("role") == "patient"]
    doctors = [r for r in rows if r.get("role") == "doctor"]

    return success(
        {
            "totalPatients": len(patients),
            "totalDoctors": len(doctors),
            "activeDoctors": sum(
                1 for d in doctors if d.get("is_approved") and d.get("is_active")
            ),
            "pendingApprovals": sum(1 for d in doctors if not d.get("is_approved")),
            "totalStaff": sum(1 for r in rows if r.get("role") == "admin"),
        }
    )


# ------------------------------------------------------------------ #
#  Helpers                                                             #
# ------------------------------------------------------------------ #

def _doctor_exists(doctor_id: str) -> bool:
    res = (
        get_supabase()
        .table("profiles")
        .select("id")
        .eq("id", doctor_id)
        .eq("role", "doctor")
        .single()
        .execute()
    )
    return bool(res.data)


def _map_profile(p: dict) -> dict:
    return {
        "id": p.get("id"),
        "role": p.get("role"),
        "firstName": p.get("first_name"),
        "lastName": p.get("last_name"),
        "phone": p.get("phone"),
        "specialty": p.get("specialty"),
        "licenseNumber": p.get("license_number"),
        "department": p.get("department"),
        "assignedDoctorId": p.get("assigned_doctor_id"),
        "isApproved": p.get("is_approved"),
        "isActive": p.get("is_active"),
        "mfaEnabled": p.get("mfa_enabled"),
        "createdAt": p.get("created_at"),
    }


def _map_config(r: dict) -> dict:
    return {
        "slotDurationMinutes": r.get("slot_duration_minutes"),
        "maxAppointmentsPerDay": r.get("max_appointments_per_day"),
        "workingHours": r.get("working_hours"),
        "blackoutDates": r.get("blackout_dates") or [],
        "lunchBreak": r.get("lunch_break"),
    }
