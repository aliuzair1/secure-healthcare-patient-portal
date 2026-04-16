"""
/api/messages  — secure messaging endpoints.

Users can only read/send messages in conversations they belong to.
Real-time delivery still uses Supabase subscriptions on the frontend;
these HTTP endpoints handle the initial load, send, and read-receipt.
"""
import logging

from flask import Blueprint, g, request
from middleware.auth import require_auth
from services.supabase_client import get_supabase
from utils.responses import bad_request, server_error, success
from utils.validators import validate_list_of_strings, validate_string, validate_uuid

bp = Blueprint("messages", __name__, url_prefix="/api/messages")
logger = logging.getLogger(__name__)


# ------------------------------------------------------------------ #
#  GET /api/messages/conversations                                     #
# ------------------------------------------------------------------ #

@bp.get("/conversations")
@require_auth
def get_conversations():
    user_id = g.user_id
    sb = get_supabase()

    try:
        msg_res = (
            sb.table("messages")
            .select("*")
            .or_(f"sender_id.eq.{user_id},receiver_id.eq.{user_id}")
            .order("created_at")
            .execute()
        )
    except Exception as exc:
        logger.error("get_conversations messages fetch failed: %s", exc)
        return server_error()

    all_messages = msg_res.data or []

    if not all_messages:
        return success({"conversations": []})

    # Unique contact IDs
    contact_ids = list(
        {
            m["receiver_id"] if m["sender_id"] == user_id else m["sender_id"]
            for m in all_messages
        }
    )

    try:
        contacts_res = (
            sb.table("profiles")
            .select("id, role, first_name, last_name")
            .in_("id", contact_ids)
            .execute()
        )
    except Exception as exc:
        logger.error("get_conversations contacts fetch failed: %s", exc)
        return server_error()

    contact_map = {c["id"]: c for c in (contacts_res.data or [])}

    conversations = []
    for contact_id in contact_ids:
        contact = contact_map.get(contact_id, {})
        thread = [
            m
            for m in all_messages
            if (m["sender_id"] == user_id and m["receiver_id"] == contact_id)
            or (m["sender_id"] == contact_id and m["receiver_id"] == user_id)
        ]
        last_msg = thread[-1] if thread else {}
        unread = sum(
            1
            for m in thread
            if m.get("receiver_id") == user_id and m.get("status") != "read"
        )
        role = contact.get("role", "")
        name = (
            f"Dr. {contact.get('first_name')} {contact.get('last_name')}"
            if role == "doctor"
            else f"{contact.get('first_name', '')} {contact.get('last_name', '')}".strip()
            or "Unknown"
        )
        conversations.append(
            {
                "contactId": contact_id,
                "contactName": name,
                "contactRole": role,
                "lastMessage": last_msg.get("content", ""),
                "lastTimestamp": last_msg.get("created_at", ""),
                "unreadCount": unread,
                "messages": [_map_message(m) for m in thread],
            }
        )

    return success({"conversations": conversations})


# ------------------------------------------------------------------ #
#  POST /api/messages                                                  #
# ------------------------------------------------------------------ #

@bp.post("")
@require_auth
def send_message():
    data = request.get_json(silent=True) or {}
    receiver_id = (data.get("receiverId") or "").strip()
    content = (data.get("content") or "").strip()

    err = validate_uuid(receiver_id, "receiverId")
    if err:
        return bad_request(err)

    err = validate_string(content, "Message content", min_len=1, max_len=4000)
    if err:
        return bad_request(err)

    # Sender must not message themselves
    if receiver_id == g.user_id:
        return bad_request("Cannot send a message to yourself.")

    # Verify the receiver exists and is active
    sb = get_supabase()
    try:
        recv_res = (
            sb.table("profiles")
            .select("id, is_active")
            .eq("id", receiver_id)
            .single()
            .execute()
        )
    except Exception:
        return bad_request("Recipient not found.")

    if not recv_res.data or not recv_res.data.get("is_active"):
        return bad_request("Recipient not found.")

    try:
        res = (
            sb.table("messages")
            .insert(
                {
                    "sender_id": g.user_id,
                    "receiver_id": receiver_id,
                    "content": content,
                    "status": "sent",
                    "encrypted": True,
                }
            )
            .select()
            .single()
            .execute()
        )
    except Exception as exc:
        logger.error("send_message failed: %s", exc)
        return server_error()

    return success(_map_message(res.data), status=201)


# ------------------------------------------------------------------ #
#  PATCH /api/messages/read                                            #
# ------------------------------------------------------------------ #

@bp.patch("/read")
@require_auth
def mark_as_read():
    data = request.get_json(silent=True) or {}
    message_ids = data.get("messageIds")

    if not message_ids:
        return success(message="No messages to update.")

    err = validate_list_of_strings(message_ids, "messageIds", max_items=500, item_max_len=36)
    if err:
        return bad_request(err)

    # Validate all are UUIDs
    for mid in message_ids:
        e = validate_uuid(mid, "messageId")
        if e:
            return bad_request(e)

    # Only mark messages addressed to the current user
    try:
        get_supabase().table("messages").update({"status": "read"}).in_("id", message_ids).eq("receiver_id", g.user_id).execute()
    except Exception as exc:
        logger.error("mark_as_read failed: %s", exc)
        return server_error()

    return success(message="Messages marked as read.")


# ------------------------------------------------------------------ #
#  Helpers                                                             #
# ------------------------------------------------------------------ #

def _map_message(m: dict) -> dict:
    return {
        "id": m.get("id"),
        "senderId": m.get("sender_id"),
        "receiverId": m.get("receiver_id"),
        "content": m.get("content"),
        "timestamp": m.get("created_at"),
        "status": m.get("status"),
        "encrypted": m.get("encrypted"),
    }
