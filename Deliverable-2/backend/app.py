"""
Flask application factory.

All requests flow through:
  Nginx (reverse proxy)
    → WAF middleware (request inspection + security headers)
    → Rate limiter
    → Auth middleware (per-route JWT validation)
    → Route handler
    → Supabase (service-role client)
"""
import json
import logging
import logging.handlers
import os
from datetime import datetime, timezone

from dotenv import load_dotenv
from flask import Flask, jsonify
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

from config import get_config

load_dotenv()

# ------------------------------------------------------------------ #
#  Rate-limiter (shared across the app)                                #
# ------------------------------------------------------------------ #
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["200 per minute", "20 per second"],
    storage_uri=os.environ.get("RATELIMIT_STORAGE_URI", "redis-10429.c212.ap-south-1-1.ec2.cloud.redislabs.com:10429"),
)


class _JSONFormatter(logging.Formatter):
    """Emit each log record as a single JSON line for SIEM ingestion."""

    _SKIP = frozenset([
        "name", "msg", "args", "levelname", "levelno", "pathname",
        "filename", "module", "exc_info", "exc_text", "stack_info",
        "lineno", "funcName", "created", "msecs", "relativeCreated",
        "thread", "threadName", "processName", "process", "message",
        "taskName",
    ])

    def format(self, record: logging.LogRecord) -> str:
        obj = {
            "timestamp": datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        for k, v in record.__dict__.items():
            if k in self._SKIP:
                continue
            try:
                json.dumps(v)
                obj[k] = v
            except (TypeError, ValueError):
                obj[k] = str(v)
        if record.exc_info:
            obj["exception"] = self.formatException(record.exc_info)
        return json.dumps(obj, default=str)


def _setup_logging(debug: bool) -> None:
    log_dir = os.path.join(os.path.dirname(__file__), "logs")
    os.makedirs(log_dir, exist_ok=True)

    root = logging.getLogger()
    root.setLevel(logging.DEBUG if debug else logging.INFO)

    # Plain-text console handler (developer convenience)
    console = logging.StreamHandler()
    console.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
    root.addHandler(console)

    # JSON rotating file handler — read by Wazuh agent
    file_handler = logging.handlers.RotatingFileHandler(
        os.path.join(log_dir, "app.log"),
        maxBytes=10 * 1024 * 1024,
        backupCount=5,
        encoding="utf-8",
    )
    file_handler.setFormatter(_JSONFormatter())
    root.addHandler(file_handler)


def create_app():
    app = Flask(__name__)
    app.config.from_object(get_config())

    # ---- Logging ------------------------------------------------- #
    _setup_logging(app.debug)

    # ---- CORS ---------------------------------------------------- #
    # Only the configured frontend origin(s) may make cross-origin requests.
    CORS(
        app,
        resources={r"/api/*": {"origins": app.config["CORS_ORIGINS"]}},
        supports_credentials=True,
        allow_headers=["Content-Type", "Authorization", "X-Requested-With"],
        methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
        max_age=600,
    )

    # ---- WAF ----------------------------------------------------- #
    from middleware.waf import WAF, create_waf_blueprint
    WAF(app)
    app.register_blueprint(create_waf_blueprint())

    # ---- Rate limiter -------------------------------------------- #
    limiter.init_app(app)

    # ---- Blueprints ---------------------------------------------- #
    from routes.auth import bp as auth_bp
    from routes.patient import bp as patient_bp
    from routes.doctor import bp as doctor_bp
    from routes.admin import bp as admin_bp
    from routes.messages import bp as messages_bp
    from routes.slots import bp as slots_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(patient_bp)
    app.register_blueprint(doctor_bp)
    app.register_blueprint(admin_bp)
    app.register_blueprint(messages_bp)
    app.register_blueprint(slots_bp)

    # ---- Tighter rate limits on auth endpoints ------------------- #
    limiter.limit("10 per minute")(auth_bp)

    # ---- Health probe -------------------------------------------- #
    @app.get("/api/health")
    def health():
        return jsonify({"status": "ok"}), 200

    # ---- Global error handlers ----------------------------------- #
    @app.errorhandler(400)
    def bad_request(_e):
        return jsonify({"message": "Invalid request."}), 400

    @app.errorhandler(401)
    def unauthorized(_e):
        return jsonify({"message": "Authentication required."}), 401

    @app.errorhandler(403)
    def forbidden(_e):
        return jsonify({"message": "You do not have permission to perform this action."}), 403

    @app.errorhandler(404)
    def not_found(_e):
        return jsonify({"message": "The requested resource was not found."}), 404

    @app.errorhandler(405)
    def method_not_allowed(_e):
        return jsonify({"message": "Method not allowed."}), 405

    @app.errorhandler(413)
    def request_too_large(_e):
        return jsonify({"message": "Request body too large."}), 413

    @app.errorhandler(429)
    def rate_limited(_e):
        return jsonify({"message": "Too many requests. Please wait before trying again."}), 429

    @app.errorhandler(500)
    def internal_error(_e):
        app.logger.exception("Unhandled 500")
        return jsonify({"message": "An unexpected error occurred. Please try again later."}), 500

    return app


if __name__ == "__main__":
    application = create_app()
    application.run(host="0.0.0.0", port=5000, debug=os.environ.get("FLASK_ENV") == "development")
