"""response.py — Response Handler"""
from __future__ import annotations
from typing import Optional
from flask import Response, jsonify
from decision import Action, WAFDecision

_BLOCK = {"error":"forbidden","message":"Request blocked by security policy.","code":403}
_RATE  = {"error":"too_many_requests","message":"Rate limit exceeded. Please wait before retrying.","code":429}
_CHAL  = {"error":"challenge_required","message":"Security challenge required.","code":403,"challenge_url":"/waf/challenge"}

def _headers(resp):
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate"
    resp.headers.pop("Server",None); resp.headers.pop("X-Powered-By",None)

def build_response(decision: WAFDecision) -> Optional[Response]:
    if decision.action in (Action.ALLOW, Action.LOG_ONLY): return None
    if decision.action == Action.BLOCK:
        r = jsonify(_BLOCK); r.status_code = 403; _headers(r); return r
    if decision.action == Action.RATE_LIMIT:
        r = jsonify(_RATE); r.status_code = 429
        r.headers["Retry-After"] = str(decision.retry_after_seconds or 30); _headers(r); return r
    if decision.action == Action.CHALLENGE:
        b = dict(_CHAL); b["request_id"] = decision.request_id
        r = jsonify(b); r.status_code = 403; _headers(r); return r
    return None
