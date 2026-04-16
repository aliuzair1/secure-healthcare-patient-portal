"""
app.py — Flask Application Entry Point

This file:
  1. Bootstraps the WAFEngine as a before_request hook
  2. Exposes the WAF admin REST API (rule management, stats, logs)
  3. Provides a /waf/health endpoint for NGINX upstream health checks
  4. Shows exactly how to integrate the WAF with a Flask backend

When you build your backend:
  - Either merge your blueprints into this app
  - Or mount this WAF app as a WSGI middleware in front of your backend
  - See the "Flask Backend Integration" section at the bottom

Admin API endpoints:
  GET  /waf/health              — liveness probe
  GET  /waf/admin/status        — engine status
  GET  /waf/admin/ip/<ip>       — IP state from behavioral engine
  POST /waf/admin/blocklist     — add IP to blocklist
  POST /waf/admin/allowlist     — add IP to allowlist
  POST /waf/admin/override      — set path/IP policy override
  DELETE /waf/admin/override    — remove override
  GET  /waf/admin/overrides     — list all overrides
  POST /waf/admin/reload        — hot-reload IP lists
"""

from __future__ import annotations

import os
from functools import wraps
from typing import Callable

from flask import Flask, jsonify, request, g

from config import config
from decision import policy_overrides, Action
from detection.behavioral import get_ip_stats
from waf_engine import WAFEngine
from logger import get_logger, init_logging

# ---------------------------------------------------------------------------
# App initialisation
# ---------------------------------------------------------------------------

init_logging()
logger = get_logger("app")

app = Flask(__name__)
waf = WAFEngine()


# ---------------------------------------------------------------------------
# WAF before_request hook — runs on EVERY request
# ---------------------------------------------------------------------------

@app.before_request
def run_waf():
    """
    The WAF gate.  Any blocking response returned here short-circuits
    the rest of Flask's request handling — the backend never sees the request.
    """
    # Store request start time + client IP for after_request
    g.waf_start_ip = request.environ.get("REMOTE_ADDR", "")
    blocking = waf.process(request)
    if blocking is not None:
        return blocking   # Flask returns this immediately


@app.after_request
def waf_feedback(response):
    """
    After the backend responds, feed the status code back into the
    behavioral engine (404 → path-scan counter, 401/403 → auth-fail counter).
    """
    ip = getattr(g, "waf_start_ip", "")
    waf.on_response(
        request_id=request.environ.get("HTTP_X_REQUEST_ID", ""),
        client_ip=ip,
        http_status=response.status_code,
    )
    # Remove server fingerprinting headers
    response.headers.pop("Server", None)
    response.headers.pop("X-Powered-By", None)
    return response


# ---------------------------------------------------------------------------
# Admin API key guard
# ---------------------------------------------------------------------------

def require_admin_key(f: Callable) -> Callable:
    """Decorator: require X-WAF-Admin-Key header matching config.admin_api_key."""
    @wraps(f)
    def decorated(*args, **kwargs):
        key = request.headers.get("X-WAF-Admin-Key", "")
        if not key or key != config.admin_api_key:
            return jsonify({"error": "unauthorised", "code": 401}), 401
        return f(*args, **kwargs)
    return decorated


# ---------------------------------------------------------------------------
# Health endpoint (no auth — used by NGINX upstream health checks)
# ---------------------------------------------------------------------------

@app.route("/waf/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "service": "AI-WAF-IDS"}), 200


# ---------------------------------------------------------------------------
# Admin API
# ---------------------------------------------------------------------------

@app.route("/waf/admin/status", methods=["GET"])
@require_admin_key
def admin_status():
    return jsonify(waf.get_engine_status()), 200


@app.route("/waf/admin/ip/<client_ip>", methods=["GET"])
@require_admin_key
def admin_ip_state(client_ip: str):
    stats = get_ip_stats(client_ip)
    if not stats:
        return jsonify({"error": "not_found", "ip": client_ip}), 404
    return jsonify(stats), 200


@app.route("/waf/admin/blocklist", methods=["POST"])
@require_admin_key
def admin_add_blocklist():
    """
    Add an IP to the in-memory blocklist for this session.
    For persistence, also write to config.reputation.blocklist_file.
    """
    data = request.get_json(silent=True) or {}
    ip = data.get("ip", "")
    if not ip:
        return jsonify({"error": "ip required"}), 400
    # Force-override the decision to BLOCK for this IP
    policy_overrides.set_ip_override(ip, Action.BLOCK)
    logger.warning("Admin API: IP %s added to blocklist", ip)
    return jsonify({"status": "ok", "ip": ip, "action": "BLOCK"}), 200


@app.route("/waf/admin/allowlist", methods=["POST"])
@require_admin_key
def admin_add_allowlist():
    data = request.get_json(silent=True) or {}
    ip = data.get("ip", "")
    if not ip:
        return jsonify({"error": "ip required"}), 400
    policy_overrides.set_ip_override(ip, Action.ALLOW)
    logger.info("Admin API: IP %s added to allowlist", ip)
    return jsonify({"status": "ok", "ip": ip, "action": "ALLOW"}), 200


@app.route("/waf/admin/override", methods=["POST"])
@require_admin_key
def admin_set_override():
    """
    Set a path or IP policy override.
    Body: {"type": "path"|"ip", "target": "/path/or/ip", "action": "ALLOW"|"BLOCK"|...}
    """
    data = request.get_json(silent=True) or {}
    override_type = data.get("type", "")
    target = data.get("target", "")
    action_str = data.get("action", "").upper()

    if not all([override_type, target, action_str]):
        return jsonify({"error": "type, target, and action required"}), 400

    try:
        action = Action(action_str)
    except ValueError:
        return jsonify({"error": f"Unknown action: {action_str}"}), 400

    if override_type == "path":
        policy_overrides.set_path_override(target, action)
    elif override_type == "ip":
        policy_overrides.set_ip_override(target, action)
    else:
        return jsonify({"error": "type must be 'path' or 'ip'"}), 400

    return jsonify({"status": "ok", "type": override_type, "target": target, "action": action.value}), 200


@app.route("/waf/admin/override", methods=["DELETE"])
@require_admin_key
def admin_remove_override():
    data = request.get_json(silent=True) or {}
    override_type = data.get("type", "")
    target = data.get("target", "")
    if not all([override_type, target]):
        return jsonify({"error": "type and target required"}), 400
    if override_type == "path":
        policy_overrides.remove_path_override(target)
    elif override_type == "ip":
        policy_overrides.remove_ip_override(target)
    return jsonify({"status": "ok", "removed": target}), 200


@app.route("/waf/admin/overrides", methods=["GET"])
@require_admin_key
def admin_list_overrides():
    return jsonify(policy_overrides.list_overrides()), 200


@app.route("/waf/admin/reload", methods=["POST"])
@require_admin_key
def admin_reload():
    result = waf.reload_rules()
    return jsonify(result), 200


# ---------------------------------------------------------------------------
# Challenge endpoint (stub — wire to real CAPTCHA provider)
# ---------------------------------------------------------------------------

@app.route("/waf/challenge", methods=["GET"])
def challenge():
    """
    Placeholder CAPTCHA / JS challenge endpoint.
    Replace with reCAPTCHA v3 / hCaptcha / Cloudflare Turnstile integration.
    """
    return jsonify({
        "message": "Security verification required.",
        "challenge_type": "captcha",
        "provider": "configure_me",
    }), 200


# ---------------------------------------------------------------------------
# ─────────────────────────────────────────────────────────────────────
# FLASK BACKEND INTEGRATION GUIDE
# ─────────────────────────────────────────────────────────────────────
#
# Option A — Single app (WAF + backend in same Flask process):
#
#   from app import app
#   from your_backend.routes import blueprint
#   app.register_blueprint(blueprint, url_prefix="/api")
#   app.run(...)
#
# Option B — WAF as WSGI middleware in front of separate backend:
#
#   from app import app as waf_app
#   from your_backend.wsgi import backend_app
#   from werkzeug.middleware.dispatcher import DispatcherMiddleware
#
#   application = DispatcherMiddleware(waf_app, {
#       "/api": backend_app,
#   })
#
# Option C — Forward allowed requests to backend via proxy (future):
#
#   In waf_engine.process(), after decision == ALLOW, use requests.Session()
#   to forward the request to http://backend:5001 and return its response.
#   This turns the WAF into a transparent inline proxy.
#
# ─────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    debug = config.debug
    port = int(os.getenv("WAF_PORT", "5000"))
    logger.info("Starting AI-WAF-IDS on port %d (debug=%s)", port, debug)
    app.run(
        host="0.0.0.0",
        port=port,
        debug=debug,
        threaded=True,
    )
