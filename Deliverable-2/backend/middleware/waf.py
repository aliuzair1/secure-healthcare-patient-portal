"""
middleware/waf.py — Flask WAF Integration

Bridges the Signature-WAF (backend/waf_sig/) with the Flask backend.

Key responsibilities:
  1. Add backend/waf_sig/ to sys.path so WAF modules can import each other
     using bare names (from config import config, from logger import …).
  2. Patch WAF config's relative file paths to absolute paths before any
     WAF module calls reload_ip_lists() or init_logging() at module level.
  3. Expose a WAF(app) Flask extension that wires before_request /
     after_request hooks.
  4. Expose create_waf_blueprint() for the WAF admin REST API.

Import conflict:  both backend/config.py and backend/waf_sig/config.py are
named "config".  This module temporarily removes the Flask config from
sys.modules, loads the WAF config under that name (so all WAF inter-module
imports work), then re-injects Flask's get_config / Config classes into the
WAF config module so "from config import get_config" continues to work
everywhere.

CORS safety:
  OPTIONS preflight requests are bypassed before WAF scanning. Flask-CORS
  adds Access-Control-* headers in after_request, which still runs on WAF-
  blocked responses, so blocked requests remain readable by the browser.

Security headers:
  All responses (allowed, blocked, or challenged) receive a hardened header
  set applied in after_request.
"""
from __future__ import annotations

import sys
from functools import wraps
from pathlib import Path
from typing import Any, Callable, Optional

# ---------------------------------------------------------------------------
# Path constants
# ---------------------------------------------------------------------------
_WAF_DIR = Path(__file__).resolve().parent.parent / "waf_sig"


# ---------------------------------------------------------------------------
# Bootstrap: set up sys.path and sys.modules before importing WAFEngine
# ---------------------------------------------------------------------------

def _bootstrap_waf() -> Any:
    """
    Load the WAFEngine class with all its dependencies correctly wired.
    Returns the WAFEngine class (not an instance).
    """
    waf_dir_str = str(_WAF_DIR)

    # ── Step 1: ensure required directories / stub files exist ──────────────
    (_WAF_DIR / "rules").mkdir(parents=True, exist_ok=True)
    (_WAF_DIR / "logs").mkdir(parents=True, exist_ok=True)
    for _fname in ("ip_blocklist.txt", "ip_allowlist.txt"):
        _fpath = _WAF_DIR / "rules" / _fname
        if not _fpath.exists():
            _fpath.write_text("# One IP or CIDR per line\n")

    # ── Step 2: temporarily remove Flask's 'config' from sys.modules ────────
    #    Flask's config.py was loaded first by app.py; if left in sys.modules,
    #    WAF modules doing "from config import config" would hit Flask's module
    #    and raise ImportError (Flask config has no 'config' attribute).
    _flask_config_mod = sys.modules.pop("config", None)

    # ── Step 3: put WAF dir at the front of sys.path ─────────────────────────
    if waf_dir_str in sys.path:
        sys.path.remove(waf_dir_str)
    sys.path.insert(0, waf_dir_str)

    try:
        # ── Step 4: import WAF config and patch relative → absolute paths ────
        import config as _waf_cfg  # noqa: E402  (this is waf_sig/config.py now)

        _waf_cfg.config.reputation.blocklist_file = str(
            _WAF_DIR / "rules" / "ip_blocklist.txt"
        )
        _waf_cfg.config.reputation.allowlist_file = str(
            _WAF_DIR / "rules" / "ip_allowlist.txt"
        )
        _waf_cfg.config.logging.log_dir    = str(_WAF_DIR / "logs")
        _waf_cfg.config.logging.access_log = str(_WAF_DIR / "logs" / "access.log")
        _waf_cfg.config.logging.attack_log = str(_WAF_DIR / "logs" / "attack.log")
        _waf_cfg.config.logging.error_log  = str(_WAF_DIR / "logs" / "error.log")

        # ── Step 5: import WAFEngine (triggers all WAF sub-module imports) ────
        #    ingress.py calls reload_ip_lists() at module level — it will now
        #    use the patched absolute paths.
        from waf_engine import WAFEngine as _WAFEngine  # noqa: E402

        # ── Step 5b: add backend-specific path overrides ─────────────────────
        #    The WAF ships with /health, /healthz, /ready, /ping whitelisted.
        #    Add the paths specific to this backend so they are never blocked.
        from decision import policy_overrides as _overrides, Action as _Action  # noqa: E402
        _overrides.set_path("/api/health",  _Action.ALLOW)  # backend liveness probe
        _overrides.set_path("/waf/health",  _Action.ALLOW)  # WAF's own health probe
        _overrides.set_path("/waf/challenge", _Action.ALLOW)  # CAPTCHA challenge page

        # ── Step 6: re-inject Flask config symbols into the WAF config module ─
        #    After this, "from config import get_config" works anywhere in Flask,
        #    and WAF's "from config import config" still resolves correctly
        #    (sys.modules['config'] remains the WAF module, which has 'config').
        if _flask_config_mod is not None:
            for _attr in ("get_config", "Config", "DevelopmentConfig",
                          "ProductionConfig", "_config_map"):
                if hasattr(_flask_config_mod, _attr):
                    setattr(_waf_cfg, _attr, getattr(_flask_config_mod, _attr))

    finally:
        # ── Step 7: move WAF dir from front to end of sys.path ───────────────
        #    WAF modules are now cached in sys.modules; keeping waf_sig/ at the
        #    front would cause new Flask imports to pick up WAF modules
        #    (e.g., a future "import logger" would get waf_sig/logger.py).
        if waf_dir_str in sys.path:
            sys.path.remove(waf_dir_str)
        sys.path.append(waf_dir_str)

    return _WAFEngine


# Run bootstrap at import time and cache the class reference
_WAFEngineClass = _bootstrap_waf()

# Module-level singleton — WAFEngine is thread-safe after __init__
_engine: Optional[Any] = None


def _get_engine():
    global _engine
    if _engine is None:
        _engine = _WAFEngineClass()
    return _engine


# ---------------------------------------------------------------------------
# Flask extension
# ---------------------------------------------------------------------------

class WAF:
    """
    Flask extension that wires the Signature-WAF pipeline as
    before_request / after_request hooks.

    Application factory usage:
        waf = WAF()
        waf.init_app(app)

    Immediate usage:
        WAF(app)
    """

    def __init__(self, app=None):
        if app is not None:
            self.init_app(app)

    def init_app(self, app):
        from flask import request as _req

        engine = _get_engine()

        @app.before_request
        def _waf_gate():
            # CORS preflight: browsers send OPTIONS before every cross-origin
            # request. These carry no body and no attack payload — scanning them
            # wastes cycles and risks false-positive blocks that silently break
            # all authenticated API calls from the frontend. Flask-CORS handles
            # OPTIONS in after_request (adds Access-Control-* headers), which
            # still fires even when we return early here.
            if _req.method == "OPTIONS":
                return None

            blocking = engine.process(_req)
            if blocking is not None:
                return blocking  # short-circuits route handling

        @app.after_request
        def _waf_security_headers(response):
            # ── Strip server fingerprinting ──────────────────────────────────
            response.headers.pop("Server",       None)
            response.headers.pop("X-Powered-By", None)

            # ── Defence-in-depth security headers ────────────────────────────
            # Use setdefault so route handlers can override if genuinely needed.
            response.headers.setdefault("X-Content-Type-Options", "nosniff")
            response.headers.setdefault("X-Frame-Options",        "DENY")
            response.headers.setdefault(
                "Referrer-Policy", "strict-origin-when-cross-origin"
            )
            response.headers.setdefault(
                "Permissions-Policy",
                "geolocation=(), microphone=(), camera=(), payment=()",
            )
            # Pure JSON API — deny all resource loading from browser context.
            response.headers.setdefault(
                "Content-Security-Policy", "default-src 'none'"
            )

            # HSTS — NGINX sets this too, but belt-and-suspenders in case
            # traffic reaches Flask directly (dev tunnels, container-to-container).
            try:
                from config import config as _waf_cfg  # WAF config (in sys.modules)
                if _waf_cfg.environment == "production":
                    response.headers.setdefault(
                        "Strict-Transport-Security",
                        "max-age=63072000; includeSubDomains; preload",
                    )
            except Exception:
                pass

            return response


# ---------------------------------------------------------------------------
# WAF admin Blueprint factory
# ---------------------------------------------------------------------------

def create_waf_blueprint():
    """
    Build and return a Flask Blueprint that exposes the WAF admin REST API.

    All /waf/admin/* endpoints require the X-WAF-Admin-Key header.
    /waf/health and /waf/challenge are public (no auth).

    Endpoints:
        GET    /waf/health
        GET    /waf/admin/status
        POST   /waf/admin/reload
        POST   /waf/admin/block-ip
        DELETE /waf/admin/block-ip
        POST   /waf/admin/allow-ip
        DELETE /waf/admin/allow-ip
        GET    /waf/admin/overrides
        POST   /waf/admin/path-override
        DELETE /waf/admin/path-override
        GET    /waf/admin/rules
        PATCH  /waf/admin/rules/<rule_id>
        GET    /waf/challenge
    """
    from flask import Blueprint, jsonify, request as _req

    # These WAF modules are already in sys.modules (loaded during bootstrap)
    from decision import policy_overrides, Action          # noqa: E402
    from detection.rule_engine import RULES                # noqa: E402

    bp = Blueprint("waf_admin", __name__, url_prefix="/waf")

    def _require_admin_key(f: Callable) -> Callable:
        """Decorator: require X-WAF-Admin-Key header on every admin endpoint."""
        @wraps(f)
        def _guarded(*args, **kwargs):
            from config import config as _waf_cfg  # WAF config
            key = _req.headers.get("X-WAF-Admin-Key", "")
            if not key or key != _waf_cfg.admin_api_key:
                return jsonify({"error": "unauthorised", "code": 401}), 401
            return f(*args, **kwargs)
        return _guarded

    # ── Health (no auth — load-balancer / NGINX upstream health checks) ──────
    @bp.get("/health")
    def waf_health():
        return jsonify({"status": "ok", "service": "signature-waf"}), 200

    # ── Status ───────────────────────────────────────────────────────────────
    @bp.get("/admin/status")
    @_require_admin_key
    def waf_status():
        return jsonify(_get_engine().status()), 200

    # ── Hot reload ───────────────────────────────────────────────────────────
    @bp.post("/admin/reload")
    @_require_admin_key
    def waf_reload():
        return jsonify(_get_engine().reload()), 200

    # ── Block / unblock IP ───────────────────────────────────────────────────
    @bp.post("/admin/block-ip")
    @_require_admin_key
    def waf_block_ip():
        ip = (_req.get_json(silent=True) or {}).get("ip", "")
        if not ip:
            return jsonify({"error": "ip required"}), 400
        policy_overrides.set_ip(ip, Action.BLOCK)
        return jsonify({"status": "ok", "ip": ip, "action": "BLOCK"}), 200

    @bp.delete("/admin/block-ip")
    @_require_admin_key
    def waf_unblock_ip():
        ip = (_req.get_json(silent=True) or {}).get("ip", "")
        if not ip:
            return jsonify({"error": "ip required"}), 400
        policy_overrides.remove_ip(ip)
        return jsonify({"status": "ok", "ip": ip}), 200

    # ── Allow / remove allowlist IP ───────────────────────────────────────────
    @bp.post("/admin/allow-ip")
    @_require_admin_key
    def waf_allow_ip():
        ip = (_req.get_json(silent=True) or {}).get("ip", "")
        if not ip:
            return jsonify({"error": "ip required"}), 400
        policy_overrides.set_ip(ip, Action.ALLOW)
        return jsonify({"status": "ok", "ip": ip, "action": "ALLOW"}), 200

    @bp.delete("/admin/allow-ip")
    @_require_admin_key
    def waf_remove_allowlist():
        ip = (_req.get_json(silent=True) or {}).get("ip", "")
        if not ip:
            return jsonify({"error": "ip required"}), 400
        policy_overrides.remove_ip(ip)
        return jsonify({"status": "ok", "ip": ip}), 200

    # ── Path-level policy overrides ───────────────────────────────────────────
    @bp.post("/admin/path-override")
    @_require_admin_key
    def waf_set_path_override():
        data       = _req.get_json(silent=True) or {}
        path       = data.get("path", "")
        action_str = data.get("action", "").upper()
        if not path or not action_str:
            return jsonify({"error": "path and action required"}), 400
        try:
            action = Action(action_str)
        except ValueError:
            return jsonify({"error": f"Unknown action. Valid: {[a.value for a in Action]}"}), 400
        policy_overrides.set_path(path, action)
        return jsonify({"status": "ok", "path": path, "action": action.value}), 200

    @bp.delete("/admin/path-override")
    @_require_admin_key
    def waf_remove_path_override():
        path = (_req.get_json(silent=True) or {}).get("path", "")
        if not path:
            return jsonify({"error": "path required"}), 400
        policy_overrides.remove_path(path)
        return jsonify({"status": "ok", "removed": path}), 200

    # ── List all active overrides ─────────────────────────────────────────────
    @bp.get("/admin/overrides")
    @_require_admin_key
    def waf_list_overrides():
        return jsonify(policy_overrides.list_all()), 200

    # ── Runtime rule management ───────────────────────────────────────────────
    @bp.get("/admin/rules")
    @_require_admin_key
    def waf_list_rules():
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

    @bp.patch("/admin/rules/<rule_id>")
    @_require_admin_key
    def waf_toggle_rule(rule_id: str):
        """Enable or disable a single rule at runtime without restart."""
        data = _req.get_json(silent=True) or {}
        if "enabled" not in data:
            return jsonify({"error": "'enabled' field required"}), 400
        rule = next((r for r in RULES if r.rule_id == rule_id), None)
        if rule is None:
            return jsonify({"error": f"Rule {rule_id!r} not found"}), 404
        rule.enabled = bool(data["enabled"])
        return jsonify({"rule_id": rule_id, "enabled": rule.enabled}), 200

    # ── Challenge stub ────────────────────────────────────────────────────────
    @bp.get("/challenge")
    def waf_challenge():
        return jsonify({
            "message":        "Security verification required.",
            "challenge_type": "captcha",
        }), 200

    return bp
