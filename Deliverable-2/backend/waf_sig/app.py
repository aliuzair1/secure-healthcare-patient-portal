"""
app.py — Flask Application Entry Point

Bootstraps the WAF and exposes:
  • A before_request hook that runs the WAF pipeline on every request.
  • An after_request hook that strips server-fingerprinting headers.
  • An admin REST API for live rule management and inspection.
  • A /waf/health endpoint for NGINX upstream health checks.
  • A /waf/challenge stub for CAPTCHA integration.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  INTEGRATING YOUR FLASK BACKEND
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Option A — Single process (WAF + backend in one app):

    from app import app
    from your_backend.routes import blueprint
    app.register_blueprint(blueprint, url_prefix="/api")
    # Done. The before_request WAF hook protects every blueprint route.

Option B — Blueprint-per-service:

    from app import app
    from users.routes import users_bp
    from products.routes import products_bp
    app.register_blueprint(users_bp,    url_prefix="/api/users")
    app.register_blueprint(products_bp, url_prefix="/api/products")

Option C — WSGI middleware (WAF in front of a separate backend app):

    from app import app as waf_app
    from your_backend.wsgi import backend_app
    from werkzeug.middleware.dispatcher import DispatcherMiddleware
    application = DispatcherMiddleware(waf_app, {"/api": backend_app})

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Admin API (all endpoints require X-WAF-Admin-Key header)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  GET    /waf/health              — liveness probe (no auth)
  GET    /waf/admin/status        — WAF config and engine info
  POST   /waf/admin/reload        — hot-reload IP lists from disk
  POST   /waf/admin/block-ip      — instantly block an IP
  POST   /waf/admin/allow-ip      — instantly allowlist an IP
  DELETE /waf/admin/block-ip      — remove an IP block
  DELETE /waf/admin/allow-ip      — remove an IP from allowlist
  GET    /waf/admin/overrides     — list all active overrides
  POST   /waf/admin/path-override — set a path-level policy
  DELETE /waf/admin/path-override — remove a path-level policy
  GET    /waf/admin/rules         — list all rules and their enabled state
  PATCH  /waf/admin/rules/<id>    — enable / disable a single rule at runtime
"""

from __future__ import annotations

import os
from functools import wraps
from typing import Callable

from flask import Flask, g, jsonify, request

from config import config
from decision import Action, policy_overrides
from detection.rule_engine import RULES
from logger import get_logger, init_logging
from waf_engine import WAFEngine

# ---------------------------------------------------------------------------
# App bootstrap
# ---------------------------------------------------------------------------

init_logging()
logger = get_logger("app")

app = Flask(__name__)
waf = WAFEngine()


# ---------------------------------------------------------------------------
# WAF hooks — run on every request
# ---------------------------------------------------------------------------

@app.before_request
def waf_gate():
    """
    Run the WAF pipeline before every request.
    A non-None return value from waf.process() short-circuits Flask —
    the backend handler and all other before_request hooks are skipped.
    """
    g._waf_start = __import__("time").perf_counter()
    blocking = waf.process(request)
    if blocking is not None:
        return blocking


@app.after_request
def security_headers(response):
    """Strip server-fingerprinting headers from every response."""
    response.headers.pop("Server",       None)
    response.headers.pop("X-Powered-By", None)
    # Add HSTS for production (NGINX already does this, but belt-and-suspenders)
    if config.environment == "production":
        response.headers.setdefault(
            "Strict-Transport-Security",
            "max-age=63072000; includeSubDomains; preload",
        )
    return response


# ---------------------------------------------------------------------------
# Admin API key guard
# ---------------------------------------------------------------------------

def require_admin(f: Callable) -> Callable:
    """Decorator: validate X-WAF-Admin-Key header."""
    @wraps(f)
    def decorated(*args, **kwargs):
        key = request.headers.get("X-WAF-Admin-Key", "")
        if not key or key != config.admin_api_key:
            return jsonify({"error": "unauthorised", "code": 401}), 401
        return f(*args, **kwargs)
    return decorated


# ---------------------------------------------------------------------------
# Health endpoint  (no auth — used by NGINX upstream checks)
# ---------------------------------------------------------------------------

@app.route("/waf/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "service": "signature-waf"}), 200


# ---------------------------------------------------------------------------
# Admin: status & reload
# ---------------------------------------------------------------------------

@app.route("/waf/admin/status", methods=["GET"])
@require_admin
def admin_status():
    return jsonify(waf.status()), 200


@app.route("/waf/admin/reload", methods=["POST"])
@require_admin
def admin_reload():
    return jsonify(waf.reload()), 200


# ---------------------------------------------------------------------------
# Admin: IP management
# ---------------------------------------------------------------------------

@app.route("/waf/admin/block-ip", methods=["POST"])
@require_admin
def admin_block_ip():
    ip = (request.get_json(silent=True) or {}).get("ip", "")
    if not ip:
        return jsonify({"error": "ip required"}), 400
    policy_overrides.set_ip(ip, Action.BLOCK)
    logger.warning("Admin: blocked IP %s", ip)
    return jsonify({"status": "ok", "ip": ip, "action": "BLOCK"}), 200


@app.route("/waf/admin/block-ip", methods=["DELETE"])
@require_admin
def admin_unblock_ip():
    ip = (request.get_json(silent=True) or {}).get("ip", "")
    if not ip:
        return jsonify({"error": "ip required"}), 400
    policy_overrides.remove_ip(ip)
    logger.info("Admin: removed IP block for %s", ip)
    return jsonify({"status": "ok", "ip": ip}), 200


@app.route("/waf/admin/allow-ip", methods=["POST"])
@require_admin
def admin_allow_ip():
    ip = (request.get_json(silent=True) or {}).get("ip", "")
    if not ip:
        return jsonify({"error": "ip required"}), 400
    policy_overrides.set_ip(ip, Action.ALLOW)
    logger.info("Admin: allowlisted IP %s", ip)
    return jsonify({"status": "ok", "ip": ip, "action": "ALLOW"}), 200


@app.route("/waf/admin/allow-ip", methods=["DELETE"])
@require_admin
def admin_remove_allowlist():
    ip = (request.get_json(silent=True) or {}).get("ip", "")
    if not ip:
        return jsonify({"error": "ip required"}), 400
    policy_overrides.remove_ip(ip)
    return jsonify({"status": "ok", "ip": ip}), 200


# ---------------------------------------------------------------------------
# Admin: path-level policy overrides
# ---------------------------------------------------------------------------

@app.route("/waf/admin/path-override", methods=["POST"])
@require_admin
def admin_set_path():
    data       = request.get_json(silent=True) or {}
    path       = data.get("path", "")
    action_str = data.get("action", "").upper()
    if not path or not action_str:
        return jsonify({"error": "path and action required"}), 400
    try:
        action = Action(action_str)
    except ValueError:
        valid = [a.value for a in Action]
        return jsonify({"error": f"Unknown action. Valid: {valid}"}), 400
    policy_overrides.set_path(path, action)
    return jsonify({"status": "ok", "path": path, "action": action.value}), 200


@app.route("/waf/admin/path-override", methods=["DELETE"])
@require_admin
def admin_remove_path():
    path = (request.get_json(silent=True) or {}).get("path", "")
    if not path:
        return jsonify({"error": "path required"}), 400
    policy_overrides.remove_path(path)
    return jsonify({"status": "ok", "removed": path}), 200


@app.route("/waf/admin/overrides", methods=["GET"])
@require_admin
def admin_list_overrides():
    return jsonify(policy_overrides.list_all()), 200


# ---------------------------------------------------------------------------
# Admin: runtime rule management
# ---------------------------------------------------------------------------

@app.route("/waf/admin/rules", methods=["GET"])
@require_admin
def admin_list_rules():
    return jsonify([
        {
            "rule_id":     r.rule_id,
            "description": r.description,
            "category":    r.category.value,
            "score":       r.score,
            "apply_to":    r.apply_to,
            "enabled":     r.enabled,
        }
        for r in RULES
    ]), 200


@app.route("/waf/admin/rules/<rule_id>", methods=["PATCH"])
@require_admin
def admin_toggle_rule(rule_id: str):
    """
    Enable or disable a single rule at runtime without restart.
    Body: {"enabled": true | false}
    """
    data = request.get_json(silent=True) or {}
    if "enabled" not in data:
        return jsonify({"error": "'enabled' field required"}), 400

    rule = next((r for r in RULES if r.rule_id == rule_id), None)
    if rule is None:
        return jsonify({"error": f"Rule {rule_id!r} not found"}), 404

    rule.enabled = bool(data["enabled"])
    logger.info("Admin: rule %s set enabled=%s", rule_id, rule.enabled)
    return jsonify({"rule_id": rule_id, "enabled": rule.enabled}), 200


# ---------------------------------------------------------------------------
# Challenge stub  —  wire to reCAPTCHA / hCaptcha / Turnstile
# ---------------------------------------------------------------------------

@app.route("/waf/challenge", methods=["GET"])
def challenge():
    return jsonify({
        "message":        "Security verification required.",
        "challenge_type": "captcha",
        "provider":       "configure_in_app.py",
    }), 200


# ---------------------------------------------------------------------------
# Dev server entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    port  = int(os.getenv("WAF_PORT", "5000"))
    debug = config.debug
    logger.info("Starting Signature WAF on :%d  debug=%s", port, debug)
    app.run(host="0.0.0.0", port=port, debug=debug, threaded=True)
