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
import logging
import os

from dotenv import load_dotenv
from flask import Flask, jsonify
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

from config import get_config

load_dotenv()
"""
# ------------------------------------------------------------------ #
#  Rate-limiter (shared across the app)                                #
# ------------------------------------------------------------------ #
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["200 per minute", "20 per second"],
    storage_uri=os.environ.get("RATELIMIT_STORAGE_URI", "memory://"),
)
"""

def create_app():
    app = Flask(__name__)
    app.config.from_object(get_config())

    # ---- Logging ------------------------------------------------- #
    logging.basicConfig(
        level=logging.INFO if not app.debug else logging.DEBUG,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

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
#WAF(app)

    # ---- Rate limiter -------------------------------------------- #
    #limiter.init_app(app)

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
    #limiter.limit("10 per minute")(auth_bp)

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
