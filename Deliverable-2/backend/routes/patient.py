"""
/api/patient  — patient-facing data endpoints.

Access rules:
  • Patients can only access their OWN records (enforced by require_self_or_role).
  • Doctors and admins may also read patient data.
  • Write operations (update profile, book/cancel appointment) are restricted
    to the patient who owns the record.
"""
import logging

from flask import Blueprint, g, request
from middleware.auth import require_auth, require_role, require_self_or_role
from services.supabase_client import get_supabase
from utils.responses import (
    bad_request,
    created,
    forbidden,
    not_found,
    server_error,
    success,
)
from utils.validators import (
    collect_errors,
    validate_date,
    validate_integer,
    validate_list_of_strings,
    validate_name,
    validate_phone,
    validate_dob,
    validate_string,
    validate_uuid,
    validate_time,
)

bp = Blueprint("patient", __name__, url_prefix="/api/patient")
logger = logging.getLogger(__name__)


# ------------------------------------------------------------------ #
#  Profile                                                             #
# ------------------------------------------------------------------ #

@bp.get("/<patient_id>/profile")
@require_auth
@require_self_or_role("patient_id", "doctor", "admin")
def get_profile(patient_id):
    err = validate_uuid(patient_id, "patient_id")
    if err:
        return bad_request(err)

    sb = get_supabase()
    res = (
        sb.table("profiles")
        .select("*")
        .eq("id", patient_id)
        .eq("role", "patient")
        .single()
        .execute()
    )
    if not res.data:
        return not_found("Patient not found.")

    p = res.data
    return success(_map_profile(p))


@bp.patch("/<patient_id>/profile")
@require_auth
@require_self_or_role("patient_id")     # only the patient themselves
def update_profile(patient_id):
    err = validate_uuid(patient_id, "patient_id")
    if err:
        return bad_request(err)

    # Double-check the JWT owner matches the path param
    if g.user_id != patient_id:
        return forbidden()

    data = request.get_json(silent=True) or {}
    updates = {}
    errors = {}

    if "firstName" in data:
        e = validate_name(data["firstName"], "First name")
        if e:
            errors["firstName"] = e
        else:
            updates["first_name"] = data["firstName"].strip()

    if "lastName" in data:
        e = validate_name(data["lastName"], "Last name")
        if e:
            errors["lastName"] = e
        else:
            updates["last_name"] = data["lastName"].strip()

    if "phone" in data:
        e = validate_phone(data["phone"])
        if e:
            errors["phone"] = e
        else:
            updates["phone"] = data["phone"].strip() if data["phone"] else None

    if "dob" in data:
        e = validate_dob(data["dob"]) if data["dob"] else None
        if e:
            errors["dob"] = e
        else:
            updates["dob"] = data["dob"] or None

    if "gender" in data:
        e = validate_string(data["gender"], "Gender", max_len=20) if data["gender"] else None
        if e:
            errors["gender"] = e
        else:
            updates["gender"] = data["gender"] or None

    if "address" in data:
        e = validate_string(data["address"], "Address", max_len=300) if data["address"] else None
        if e:
            errors["address"] = e
        else:
            updates["address"] = data["address"] or None

    if "emergencyContact" in data:
        e = validate_string(data["emergencyContact"], "Emergency contact", max_len=300) if data["emergencyContact"] else None
        if e:
            errors["emergencyContact"] = e
        else:
            updates["emergency_contact"] = data["emergencyContact"] or None

    if "allergies" in data:
        e = validate_list_of_strings(data["allergies"], "Allergies")
        if e:
            errors["allergies"] = e
        else:
            updates["allergies"] = data["allergies"] or []

    if "bloodType" in data:
        allowed = {"A+", "A-", "B+", "B-", "AB+", "AB-", "O+", "O-", "Unknown"}
        val = (data["bloodType"] or "").strip()
        if val and val not in allowed:
            errors["bloodType"] = "Invalid blood type."
        else:
            updates["blood_type"] = val or None

    if errors:
        return bad_request(next(iter(errors.values())))

    if not updates:
        return bad_request("No valid fields provided.")

    try:
        get_supabase().table("profiles").update(updates).eq("id", patient_id).execute()
    except Exception as exc:
        logger.error("Profile update failed for %s: %s", patient_id, exc)
        return server_error()

    return success(message="Profile updated successfully.")


# ------------------------------------------------------------------ #
#  Medical records                                                     #
# ------------------------------------------------------------------ #

@bp.get("/<patient_id>/medical-records")
@require_auth
@require_self_or_role("patient_id", "doctor", "admin")
def get_medical_records(patient_id):
    err = validate_uuid(patient_id, "patient_id")
    if err:
        return bad_request(err)

    # Doctors may only read records of patients assigned to them
    if g.user_role == "doctor":
        _assert_assigned(patient_id, g.user_id)

    try:
        res = (
            get_supabase()
            .table("medical_records")
            .select("*")
            .eq("patient_id", patient_id)
            .order("date", desc=True)
            .execute()
        )
    except Exception as exc:
        logger.error("medical_records fetch failed: %s", exc)
        return server_error()

    rows = res.data or []
    return success({"records": [_map_record(r) for r in rows]})


# ------------------------------------------------------------------ #
#  Lab reports                                                         #
# ------------------------------------------------------------------ #

@bp.get("/<patient_id>/lab-reports")
@require_auth
@require_self_or_role("patient_id", "doctor", "admin")
def get_lab_reports(patient_id):
    err = validate_uuid(patient_id, "patient_id")
    if err:
        return bad_request(err)

    if g.user_role == "doctor":
        _assert_assigned(patient_id, g.user_id)

    try:
        res = (
            get_supabase()
            .table("lab_reports")
            .select("*")
            .eq("patient_id", patient_id)
            .order("date", desc=True)
            .execute()
        )
    except Exception as exc:
        logger.error("lab_reports fetch failed: %s", exc)
        return server_error()

    return success({"reports": [_map_report(r) for r in (res.data or [])]})


# ------------------------------------------------------------------ #
#  Prescriptions                                                       #
# ------------------------------------------------------------------ #

@bp.get("/<patient_id>/prescriptions")
@require_auth
@require_self_or_role("patient_id", "doctor", "admin")
def get_prescriptions(patient_id):
    err = validate_uuid(patient_id, "patient_id")
    if err:
        return bad_request(err)

    if g.user_role == "doctor":
        _assert_assigned(patient_id, g.user_id)

    try:
        res = (
            get_supabase()
            .table("prescriptions")
            .select("*")
            .eq("patient_id", patient_id)
            .order("created_at", desc=True)
            .execute()
        )
    except Exception as exc:
        logger.error("prescriptions fetch failed: %s", exc)
        return server_error()

    return success({"prescriptions": [_map_prescription(r) for r in (res.data or [])]})


# ------------------------------------------------------------------ #
#  Appointments                                                        #
# ------------------------------------------------------------------ #

@bp.get("/<patient_id>/appointments")
@require_auth
@require_self_or_role("patient_id", "doctor", "admin")
def get_appointments(patient_id):
    err = validate_uuid(patient_id, "patient_id")
    if err:
        return bad_request(err)

    try:
        res = (
            get_supabase()
            .table("appointments")
            .select("*, doctor:profiles!appointments_doctor_id_fkey(first_name, last_name)")
            .eq("patient_id", patient_id)
            .order("date", desc=True)
            .execute()
        )
    except Exception as exc:
        logger.error("appointments fetch failed: %s", exc)
        return server_error()

    rows = res.data or []
    return success({"appointments": [_map_appointment(r) for r in rows]})


@bp.post("/<patient_id>/appointments")
@require_auth
@require_self_or_role("patient_id")
def book_appointment(patient_id):
    if g.user_id != patient_id:
        return forbidden()

    err = validate_uuid(patient_id, "patient_id")
    if err:
        return bad_request(err)

    data = request.get_json(silent=True) or {}
    doctor_id = (data.get("doctorId") or "").strip()
    appt_date = (data.get("date") or "").strip()
    appt_time = (data.get("time") or "").strip()
    appt_type = (data.get("type") or "").strip()
    duration = data.get("duration", 30)
    notes = (data.get("notes") or "").strip() or None
    location = (data.get("location") or "").strip() or None

    err = collect_errors(
        doctor_id=validate_uuid(doctor_id, "doctorId"),
        date=validate_date(appt_date, "Appointment date"),
        time=validate_time(appt_time, "Appointment time"),
        type=validate_string(appt_type, "Appointment type", max_len=100),
        duration=validate_integer(duration, "Duration", min_val=5, max_val=480),
    )
    if err:
        return bad_request(err)

    try:
        res = (
            get_supabase()
            .table("appointments")
            .insert(
                {
                    "patient_id": patient_id,
                    "doctor_id": doctor_id,
                    "date": appt_date,
                    "time": appt_time,
                    "duration": duration,
                    "type": appt_type,
                    "status": "upcoming",
                    "notes": notes,
                    "location": location,
                }
            )
            .select()
            .single()
            .execute()
        )
    except Exception as exc:
        logger.error("book_appointment failed: %s", exc)
        return server_error()

    return created(_map_appointment(res.data))


# ------------------------------------------------------------------ #
#  Assigned doctors                                                    #
# ------------------------------------------------------------------ #

@bp.get("/<patient_id>/doctors")
@require_auth
@require_self_or_role("patient_id", "admin")
def get_assigned_doctors(patient_id):
    err = validate_uuid(patient_id, "patient_id")
    if err:
        return bad_request(err)

    sb = get_supabase()
    try:
        p_res = (
            sb.table("profiles")
            .select("assigned_doctor_id")
            .eq("id", patient_id)
            .single()
            .execute()
        )
    except Exception:
        return server_error()

    if not p_res.data or not p_res.data.get("assigned_doctor_id"):
        return success({"doctors": []})

    doc_id = p_res.data["assigned_doctor_id"]
    try:
        d_res = (
            sb.table("profiles")
            .select("*")
            .eq("id", doc_id)
            .single()
            .execute()
        )
    except Exception:
        return server_error()

    doctors = [_map_profile(d_res.data)] if d_res.data else []
    return success({"doctors": doctors})


# ------------------------------------------------------------------ #
#  Internal helpers                                                    #
# ------------------------------------------------------------------ #

def _assert_assigned(patient_id: str, doctor_id: str):
    """Raise 403 if the patient is not assigned to this doctor."""
    from utils.responses import forbidden as _f
    res = (
        get_supabase()
        .table("profiles")
        .select("assigned_doctor_id")
        .eq("id", patient_id)
        .single()
        .execute()
    )
    if not res.data or res.data.get("assigned_doctor_id") != doctor_id:
        raise _AssignmentError()


class _AssignmentError(Exception):
    pass


def _map_profile(p: dict) -> dict:
    return {
        "id": p.get("id"),
        "role": p.get("role"),
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


def _map_record(r: dict) -> dict:
    return {
        "id": r.get("id"),
        "patientId": r.get("patient_id"),
        "doctorId": r.get("doctor_id"),
        "date": r.get("date"),
        "type": r.get("type"),
        "diagnosis": r.get("diagnosis"),
        "notes": r.get("notes"),
        "vitals": r.get("vitals"),
        "followUp": r.get("follow_up"),
    }


def _map_report(r: dict) -> dict:
    return {
        "id": r.get("id"),
        "patientId": r.get("patient_id"),
        "doctorId": r.get("doctor_id"),
        "title": r.get("title"),
        "date": r.get("date"),
        "status": r.get("status"),
        "category": r.get("category"),
        "results": r.get("results") or [],
    }


def _map_prescription(r: dict) -> dict:
    return {
        "id": r.get("id"),
        "patientId": r.get("patient_id"),
        "doctorId": r.get("doctor_id"),
        "medication": r.get("medication"),
        "dosage": r.get("dosage"),
        "frequency": r.get("frequency"),
        "startDate": r.get("start_date"),
        "endDate": r.get("end_date"),
        "status": r.get("status"),
        "instructions": r.get("instructions"),
        "refillsRemaining": r.get("refills_remaining"),
    }


def _map_appointment(r: dict) -> dict:
    doctor = r.get("doctor") or {}
    return {
        "id": r.get("id"),
        "patientId": r.get("patient_id"),
        "doctorId": r.get("doctor_id"),
        "doctorName": (
            f"Dr. {doctor.get('first_name')} {doctor.get('last_name')}"
            if doctor
            else "Unknown"
        ),
        "date": r.get("date"),
        "time": r.get("time"),
        "duration": r.get("duration"),
        "type": r.get("type"),
        "status": r.get("status"),
        "notes": r.get("notes"),
        "location": r.get("location"),
    }
