"""
/api/slots and /api/appointments  — scheduling helpers.
"""
import logging

from flask import Blueprint, g, request
from middleware.auth import require_auth
from services.supabase_client import get_supabase
from utils.responses import bad_request, forbidden, not_found, server_error, success
from utils.validators import validate_uuid

bp = Blueprint("slots", __name__, url_prefix="/api")
logger = logging.getLogger(__name__)


@bp.get("/slots/<doctor_id>")
@require_auth
def get_available_slots(doctor_id):
    err = validate_uuid(doctor_id, "doctor_id")
    if err:
        return bad_request(err)

    from datetime import date
    today = date.today().isoformat()

    try:
        res = (
            get_supabase()
            .table("available_slots")
            .select("*")
            .eq("doctor_id", doctor_id)
            .gte("date", today)
            .order("date")
            .execute()
        )
    except Exception as exc:
        logger.error("available_slots fetch failed: %s", exc)
        return server_error()

    slots = [
        {
            "doctorId": r.get("doctor_id"),
            "date": r.get("date"),
            "times": r.get("times") or [],
        }
        for r in (res.data or [])
    ]
    return success({"slots": slots})


@bp.patch("/appointments/<appointment_id>/cancel")
@require_auth
def cancel_appointment(appointment_id):
    err = validate_uuid(appointment_id, "appointment_id")
    if err:
        return bad_request(err)

    sb = get_supabase()

    # Fetch the appointment to verify ownership
    try:
        res = (
            sb.table("appointments")
            .select("id, patient_id, doctor_id, status")
            .eq("id", appointment_id)
            .single()
            .execute()
        )
    except Exception:
        return server_error()

    if not res.data:
        return not_found("Appointment not found.")

    appt = res.data

    # Only the patient who owns it, their assigned doctor, or an admin may cancel
    allowed = (
        g.user_role == "admin"
        or g.user_id == appt.get("patient_id")
        or g.user_id == appt.get("doctor_id")
    )
    if not allowed:
        return forbidden()

    if appt.get("status") == "cancelled":
        return bad_request("Appointment is already cancelled.")

    try:
        sb.table("appointments").update({"status": "cancelled"}).eq("id", appointment_id).execute()
    except Exception as exc:
        logger.error("cancel_appointment failed: %s", exc)
        return server_error()

    return success(message="Appointment cancelled successfully.")
