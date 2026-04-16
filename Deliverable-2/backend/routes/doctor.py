"""
/api/doctor  — doctor-facing data endpoints.

Access rules:
  • All routes require role == 'doctor'.
  • Doctors may only access patients assigned to them (enforced per-route).
  • Admins are NOT given access here; admin reads patient data via /api/patient.
"""
import logging
from datetime import date

from flask import Blueprint, g, request
from middleware.auth import require_auth, require_role
from services.supabase_client import get_supabase
from utils.responses import bad_request, created, forbidden, not_found, server_error, success
from utils.validators import (
    collect_errors,
    validate_date,
    validate_string,
    validate_uuid,
)

bp = Blueprint("doctor", __name__, url_prefix="/api/doctor")
logger = logging.getLogger(__name__)


# ------------------------------------------------------------------ #
#  Patient roster                                                      #
# ------------------------------------------------------------------ #

@bp.get("/<doctor_id>/patients")
@require_auth
@require_role("doctor", "admin")
def get_assigned_patients(doctor_id):
    err = validate_uuid(doctor_id, "doctor_id")
    if err:
        return bad_request(err)

    try:
        _assert_doctor_owns(doctor_id)
    except _PermissionError:
        return forbidden()

    try:
        res = (
            get_supabase()
            .table("profiles")
            .select("*")
            .eq("role", "patient")
            .eq("assigned_doctor_id", doctor_id)
            .execute()
        )
    except Exception as exc:
        logger.error("get_assigned_patients failed: %s", exc)
        return server_error()

    return success({"patients": [_map_profile(p) for p in (res.data or [])]})


# ------------------------------------------------------------------ #
#  Full patient record                                                 #
# ------------------------------------------------------------------ #

@bp.get("/<doctor_id>/patients/<patient_id>/record")
@require_auth
@require_role("doctor", "admin")
def get_patient_full_record(doctor_id, patient_id):
    for fid, fname in [(doctor_id, "doctor_id"), (patient_id, "patient_id")]:
        err = validate_uuid(fid, fname)
        if err:
            return bad_request(err)

    try:
        _assert_doctor_owns(doctor_id)
    except _PermissionError:
        return forbidden()

    sb = get_supabase()

    # Verify patient is assigned to this doctor
    p_res = (
        sb.table("profiles")
        .select("*")
        .eq("id", patient_id)
        .eq("assigned_doctor_id", doctor_id)
        .single()
        .execute()
    )
    if not p_res.data:
        return forbidden("Not authorised to view this patient.")

    # Parallel fetch all related data
    try:
        records_res = (
            sb.table("medical_records")
            .select("*")
            .eq("patient_id", patient_id)
            .order("date", desc=True)
            .execute()
        )
        reports_res = (
            sb.table("lab_reports")
            .select("*")
            .eq("patient_id", patient_id)
            .order("date", desc=True)
            .execute()
        )
        rx_res = (
            sb.table("prescriptions")
            .select("*")
            .eq("patient_id", patient_id)
            .order("created_at", desc=True)
            .execute()
        )
        appt_res = (
            sb.table("appointments")
            .select("*")
            .eq("patient_id", patient_id)
            .order("date", desc=True)
            .execute()
        )
    except Exception as exc:
        logger.error("get_patient_full_record fetch failed: %s", exc)
        return server_error()

    return success(
        {
            "profile": _map_profile(p_res.data),
            "medicalHistory": [_map_record(r) for r in (records_res.data or [])],
            "reports": [_map_report(r) for r in (reports_res.data or [])],
            "prescriptions": [_map_prescription(r) for r in (rx_res.data or [])],
            "appointments": [_map_appointment_plain(r) for r in (appt_res.data or [])],
        }
    )


# ------------------------------------------------------------------ #
#  Visit notes                                                         #
# ------------------------------------------------------------------ #

@bp.post("/<doctor_id>/visit-notes")
@require_auth
@require_role("doctor")
def add_visit_note(doctor_id):
    err = validate_uuid(doctor_id, "doctor_id")
    if err:
        return bad_request(err)

    try:
        _assert_doctor_owns(doctor_id)
    except _PermissionError:
        return forbidden()

    data = request.get_json(silent=True) or {}
    patient_id = (data.get("patientId") or "").strip()
    record_type = (data.get("type") or "").strip()
    diagnosis = (data.get("diagnosis") or "").strip()
    notes = (data.get("notes") or "").strip()
    record_date = (data.get("date") or "").strip() or date.today().isoformat()
    vitals = data.get("vitals")      # JSON object — validated loosely
    follow_up = (data.get("followUp") or "").strip() or None

    err = collect_errors(
        patient_id=validate_uuid(patient_id, "patientId"),
        type=validate_string(record_type, "Type", max_len=100),
        diagnosis=validate_string(diagnosis, "Diagnosis", max_len=1000),
        notes=validate_string(notes, "Notes", max_len=5000),
        date=validate_date(record_date, "Date"),
        follow_up=validate_date(follow_up, "Follow-up date") if follow_up else None,
    )
    if err:
        return bad_request(err)

    # Verify patient is assigned to this doctor
    try:
        _assert_patient_assigned(patient_id, doctor_id)
    except _PermissionError:
        return forbidden("Not authorised to add notes for this patient.")

    # Validate vitals structure (loose — just check it's a dict or None)
    if vitals is not None and not isinstance(vitals, dict):
        return bad_request("Vitals must be a JSON object.")

    try:
        res = (
            get_supabase()
            .table("medical_records")
            .insert(
                {
                    "patient_id": patient_id,
                    "doctor_id": doctor_id,
                    "date": record_date,
                    "type": record_type,
                    "diagnosis": diagnosis,
                    "notes": notes,
                    "vitals": vitals,
                    "follow_up": follow_up,
                }
            )
            .select()
            .single()
            .execute()
        )
    except Exception as exc:
        logger.error("add_visit_note failed: %s", exc)
        return server_error()

    return created(_map_record(res.data))


# ------------------------------------------------------------------ #
#  Prescriptions                                                       #
# ------------------------------------------------------------------ #

@bp.post("/<doctor_id>/prescriptions")
@require_auth
@require_role("doctor")
def issue_prescription(doctor_id):
    err = validate_uuid(doctor_id, "doctor_id")
    if err:
        return bad_request(err)

    try:
        _assert_doctor_owns(doctor_id)
    except _PermissionError:
        return forbidden()

    data = request.get_json(silent=True) or {}
    patient_id = (data.get("patientId") or "").strip()
    medication = (data.get("medication") or "").strip()
    dosage = (data.get("dosage") or "").strip()
    frequency = (data.get("frequency") or "").strip()
    start_date = (data.get("startDate") or "").strip()
    end_date = (data.get("endDate") or "").strip()
    instructions = (data.get("instructions") or "").strip() or None
    refills = data.get("refillsRemaining", 0)

    err = collect_errors(
        patient_id=validate_uuid(patient_id, "patientId"),
        medication=validate_string(medication, "Medication", max_len=200),
        dosage=validate_string(dosage, "Dosage", max_len=100),
        frequency=validate_string(frequency, "Frequency", max_len=100),
        start_date=validate_date(start_date, "Start date"),
        end_date=validate_date(end_date, "End date"),
    )
    if err:
        return bad_request(err)

    from utils.validators import validate_integer
    err = validate_integer(refills, "Refills remaining", min_val=0, max_val=99)
    if err:
        return bad_request(err)

    try:
        _assert_patient_assigned(patient_id, doctor_id)
    except _PermissionError:
        return forbidden("Not authorised to prescribe for this patient.")

    try:
        res = (
            get_supabase()
            .table("prescriptions")
            .insert(
                {
                    "patient_id": patient_id,
                    "doctor_id": doctor_id,
                    "medication": medication,
                    "dosage": dosage,
                    "frequency": frequency,
                    "start_date": start_date,
                    "end_date": end_date,
                    "status": "active",
                    "instructions": instructions,
                    "refills_remaining": refills,
                }
            )
            .select()
            .single()
            .execute()
        )
    except Exception as exc:
        logger.error("issue_prescription failed: %s", exc)
        return server_error()

    return created(_map_prescription(res.data))


# ------------------------------------------------------------------ #
#  Appointments                                                        #
# ------------------------------------------------------------------ #

@bp.get("/<doctor_id>/appointments")
@require_auth
@require_role("doctor", "admin")
def get_doctor_appointments(doctor_id):
    err = validate_uuid(doctor_id, "doctor_id")
    if err:
        return bad_request(err)

    try:
        _assert_doctor_owns(doctor_id)
    except _PermissionError:
        return forbidden()

    try:
        res = (
            get_supabase()
            .table("appointments")
            .select(
                "*, patient:profiles!appointments_patient_id_fkey(first_name, last_name)"
            )
            .eq("doctor_id", doctor_id)
            .order("date", desc=True)
            .execute()
        )
    except Exception as exc:
        logger.error("get_doctor_appointments failed: %s", exc)
        return server_error()

    rows = res.data or []
    return success(
        {
            "appointments": [
                {
                    "id": r.get("id"),
                    "patientId": r.get("patient_id"),
                    "doctorId": r.get("doctor_id"),
                    "patientName": (
                        f"{(r.get('patient') or {}).get('first_name', '')} "
                        f"{(r.get('patient') or {}).get('last_name', '')}".strip()
                        or "Unknown"
                    ),
                    "date": r.get("date"),
                    "time": r.get("time"),
                    "duration": r.get("duration"),
                    "type": r.get("type"),
                    "status": r.get("status"),
                    "notes": r.get("notes"),
                    "location": r.get("location"),
                }
                for r in rows
            ]
        }
    )


# ------------------------------------------------------------------ #
#  Internal guards                                                     #
# ------------------------------------------------------------------ #

def _assert_doctor_owns(doctor_id: str):
    """Doctors can only operate as themselves. Admins are unrestricted."""
    if g.user_role == "admin":
        return
    if g.user_id != doctor_id:
        raise _PermissionError()


def _assert_patient_assigned(patient_id: str, doctor_id: str):
    res = (
        get_supabase()
        .table("profiles")
        .select("assigned_doctor_id")
        .eq("id", patient_id)
        .single()
        .execute()
    )
    if not res.data or res.data.get("assigned_doctor_id") != doctor_id:
        raise _PermissionError()


class _PermissionError(Exception):
    pass


# Register a Flask error handler in app.py for _PermissionError if needed.
# For now, routes explicitly handle the guard calls.


# ------------------------------------------------------------------ #
#  Mappers (mirrors patientService.js shapes)                          #
# ------------------------------------------------------------------ #

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
        "specialty": p.get("specialty"),
        "licenseNumber": p.get("license_number"),
        "department": p.get("department"),
        "isApproved": p.get("is_approved"),
        "isActive": p.get("is_active"),
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


def _map_appointment_plain(r: dict) -> dict:
    return {
        "id": r.get("id"),
        "patientId": r.get("patient_id"),
        "doctorId": r.get("doctor_id"),
        "date": r.get("date"),
        "time": r.get("time"),
        "duration": r.get("duration"),
        "type": r.get("type"),
        "status": r.get("status"),
        "notes": r.get("notes"),
        "location": r.get("location"),
    }
