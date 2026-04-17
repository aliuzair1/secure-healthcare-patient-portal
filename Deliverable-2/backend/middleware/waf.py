"""
middleware/waf.py — Flask WAF Integration

Bridges the AI-WAF-IDS (backend/waf/) with the Flask backend.

Key responsibilities:
  1. Add backend/waf/ to sys.path so WAF modules can import each other
     using bare names (from config import config, from logger import …).
  2. Patch WAF config's relative file paths to absolute paths before any
     WAF module calls reload_ip_lists() or init_logging() at module level.
  3. Expose a WAF(app) Flask extension that wires before_request /
     after_request hooks.
  4. Expose create_waf_blueprint() for the WAF admin REST API.

Import conflict:  both backend/config.py and backend/waf/config.py are named
"config".  This module temporarily removes the Flask config from sys.modules,
loads the WAF config under that name (so all WAF inter-module imports work),
then re-injects Flask's get_config / Config classes into the WAF config module
so "from config import get_config" continues to work everywhere.
"""
from __future__ import annotations

import sys
from functools import wraps
from pathlib import Path
from typing import Any, Callable, Optional

# ---------------------------------------------------------------------------
# Path constants
# ---------------------------------------------------------------------------
_WAF_DIR = Path(__file__).resolve().parent.parent / "waf"


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
        import config as _waf_cfg  # noqa: E402  (this is waf/config.py now)

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
        #    WAF modules are now cached in sys.modules; keeping waf/ at the
        #    front would cause new Flask imports to pick up WAF modules
        #    (e.g., a future "import logger" would get waf/logger.py).
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
    Flask extension that wires the AI-WAF-IDS pipeline as
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
        from flask import g, request as _req

        engine = _get_engine()

        @app.before_request
        def _waf_gate():
            # Store client IP for the post-response feedback hook
            g._waf_client_ip = _req.environ.get("REMOTE_ADDR", "")
            blocking = engine.process(_req)
            if blocking is not None:
                return blocking  # short-circuits route handling

        @app.after_request
        def _waf_feedback(response):
            ip = getattr(g, "_waf_client_ip", "")
            engine.on_response(
                request_id=_req.environ.get("HTTP_X_REQUEST_ID", ""),
                client_ip=ip,
                http_status=response.status_code,
            )
            # Strip server fingerprinting headers
            response.headers.pop("Server", None)
            response.headers.pop("X-Powered-By", None)
            return response


# ---------------------------------------------------------------------------
# WAF admin Blueprint factory
# ---------------------------------------------------------------------------

def create_waf_blueprint():
    """
    Build and return a Flask Blueprint that exposes the WAF admin REST API.

    Endpoints:
        GET  /waf/health
        GET  /waf/admin/status
        GET  /waf/admin/ip/<ip>
        POST /waf/admin/blocklist
        POST /waf/admin/allowlist
        POST /waf/admin/override
        DELETE /waf/admin/override
        GET  /waf/admin/overrides
        POST /waf/admin/reload
        GET  /waf/challenge

    Authentication: X-WAF-Admin-Key header (value from WAF_ADMIN_KEY env var).
    """
    from flask import Blueprint, jsonify, request as _req

    # These WAF modules are already in sys.modules (loaded during bootstrap)
    from decision import policy_overrides, Action          # noqa: E402
    from detection.behavioral import get_ip_stats          # noqa: E402

    bp = Blueprint("waf_admin", __name__, url_prefix="/waf")

    def _require_admin_key(f: Callable) -> Callable:
        """Decorator: require X-WAF-Admin-Key header."""
        @wraps(f)
        def _guarded(*args, **kwargs):
            from config import config as _waf_cfg  # noqa: E402  (WAF config)
            key = _req.headers.get("X-WAF-Admin-Key", "")
            if not key or key != _waf_cfg.admin_api_key:
                return jsonify({"error": "unauthorised", "code": 401}), 401
            return f(*args, **kwargs)
        return _guarded

    # ── Health (no auth — used by load-balancer health checks) ──────────────
    @bp.get("/health")
    def waf_health():
        return jsonify({"status": "ok", "service": "AI-WAF-IDS"}), 200

    # ── Status ───────────────────────────────────────────────────────────────
    @bp.get("/admin/status")
    @_require_admin_key
    def waf_status():
        return jsonify(_get_engine().get_engine_status()), 200

    # ── IP state ─────────────────────────────────────────────────────────────
    @bp.get("/admin/ip/<client_ip>")
    @_require_admin_key
    def waf_ip_state(client_ip: str):
        stats = get_ip_stats(client_ip)
        if not stats:
            return jsonify({"error": "not_found", "ip": client_ip}), 404
        return jsonify(stats), 200

    # ── Blocklist / Allowlist ────────────────────────────────────────────────
    @bp.post("/admin/blocklist")
    @_require_admin_key
    def waf_blocklist():
        data = _req.get_json(silent=True) or {}
        ip = data.get("ip", "")
        if not ip:
            return jsonify({"error": "ip required"}), 400
        policy_overrides.set_ip_override(ip, Action.BLOCK)
        return jsonify({"status": "ok", "ip": ip, "action": "BLOCK"}), 200

    @bp.post("/admin/allowlist")
    @_require_admin_key
    def waf_allowlist():
        data = _req.get_json(silent=True) or {}
        ip = data.get("ip", "")
        if not ip:
            return jsonify({"error": "ip required"}), 400
        policy_overrides.set_ip_override(ip, Action.ALLOW)
        return jsonify({"status": "ok", "ip": ip, "action": "ALLOW"}), 200

    # ── Policy overrides ─────────────────────────────────────────────────────
    @bp.route("/admin/override", methods=["POST"])
    @_require_admin_key
    def waf_set_override():
        data = _req.get_json(silent=True) or {}
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
        return jsonify({
            "status": "ok", "type": override_type,
            "target": target, "action": action.value,
        }), 200

    @bp.route("/admin/override", methods=["DELETE"])
    @_require_admin_key
    def waf_remove_override():
        data = _req.get_json(silent=True) or {}
        override_type = data.get("type", "")
        target = data.get("target", "")
        if not all([override_type, target]):
            return jsonify({"error": "type and target required"}), 400
        if override_type == "path":
            policy_overrides.remove_path_override(target)
        elif override_type == "ip":
            policy_overrides.remove_ip_override(target)
        return jsonify({"status": "ok", "removed": target}), 200

    @bp.get("/admin/overrides")
    @_require_admin_key
    def waf_list_overrides():
        return jsonify(policy_overrides.list_overrides()), 200

    # ── Hot reload ───────────────────────────────────────────────────────────
    @bp.post("/admin/reload")
    @_require_admin_key
    def waf_reload():
        result = _get_engine().reload_rules()
        return jsonify(result), 200

    # ── Challenge stub ───────────────────────────────────────────────────────
    @bp.get("/challenge")
    def waf_challenge():
        return jsonify({
            "message": "Security verification required.",
            "challenge_type": "captcha",
        }), 200

    return bp
