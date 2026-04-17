"""
response.py — Response Handler (Pipeline Step 6)

Translates a WAFDecision into a Flask Response.

Security note
-------------
Block / challenge responses are deliberately vague. They never expose:
  - WAF rule IDs or rule names
  - Risk scores or matched patterns
  - Internal module names or stack traces

This prevents attackers from fingerprinting the WAF and crafting evasions.
Internal details are written only to the attack log.
"""

from __future__ import annotations

from typing import Optional

from flask import Response, jsonify

from decision import Action, WAFDecision


# ---------------------------------------------------------------------------
# Generic response bodies  —  intentionally uninformative
# ---------------------------------------------------------------------------

_BLOCK_BODY = {
    "error":   "forbidden",
    "message": "Request blocked by security policy.",
    "code":    403,
}

_RATE_LIMIT_BODY = {
    "error":   "too_many_requests",
    "message": "Rate limit exceeded. Please retry after the indicated delay.",
    "code":    429,
}

_CHALLENGE_BODY = {
    "error":         "challenge_required",
    "message":       "Security verification required.",
    "challenge_url": "/waf/challenge",   # wire to your CAPTCHA provider
    "code":          403,
}


# ---------------------------------------------------------------------------
# Public function
# ---------------------------------------------------------------------------

def build_response(decision: WAFDecision) -> Optional[Response]:
    """
    Return a Flask Response for blocking decisions, or None for ALLOW / LOG_ONLY.

    None means the request passes through to the backend unchanged.
    """
    if decision.action in (Action.ALLOW, Action.LOG_ONLY):
        return None

    if decision.action == Action.BLOCK:
        resp = jsonify(_BLOCK_BODY)
        resp.status_code = 403
        _harden(resp)
        return resp

    if decision.action == Action.RATE_LIMIT:
        resp = jsonify(_RATE_LIMIT_BODY)
        resp.status_code = 429
        resp.headers["Retry-After"] = str(decision.retry_after_seconds or 30)
        _harden(resp)
        return resp

    if decision.action == Action.CHALLENGE:
        body = dict(_CHALLENGE_BODY)
        body["request_id"] = decision.request_id   # safe to expose for UX
        resp = jsonify(body)
        resp.status_code = 403
        _harden(resp)
        return resp

    return None   # fallback safety


def _harden(resp: Response) -> None:
    """Add security headers to all WAF-generated responses."""
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"]        = "DENY"
    resp.headers["Cache-Control"]          = "no-store, no-cache, must-revalidate"
    resp.headers["Pragma"]                 = "no-cache"
    resp.headers.pop("Server",        None)
    resp.headers.pop("X-Powered-By",  None)
