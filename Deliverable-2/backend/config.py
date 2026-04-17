import os


class Config:
    DEBUG = False
    TESTING = False

    SECRET_KEY = os.environ.get("FLASK_SECRET_KEY", "change-me")

    # Supabase
    SUPABASE_URL = os.environ.get("SUPABASE_URL", "")
    SUPABASE_SERVICE_ROLE_KEY = os.environ.get("SUPABASE_SERVICE_ROLE_KEY", "")
    SUPABASE_JWT_SECRET = os.environ.get("SUPABASE_JWT_SECRET", "")

    # CORS — restrict to known frontend origins
    CORS_ORIGINS = [
        o.strip()
        for o in os.environ.get("CORS_ORIGINS", "https://secure-healthcare-patient-portal.vercel.app").split(",")
        if o.strip()
    ]

    # Rate limiting
    RATELIMIT_STORAGE_URI = os.environ.get("RATELIMIT_STORAGE_URI", "memory://")
    RATELIMIT_HEADERS_ENABLED = True

    # Max upload / request body: 10 MB
    MAX_CONTENT_LENGTH = 10 * 1024 * 1024

    APP_URL = os.environ.get("APP_URL", "https://secure-healthcare-patient-portal.vercel.app")


class DevelopmentConfig(Config):
    DEBUG = True


class ProductionConfig(Config):
    DEBUG = False


_config_map = {
    "development": DevelopmentConfig,
    "production": ProductionConfig,
    "default": DevelopmentConfig,
}


def get_config():
    env = os.environ.get("FLASK_ENV", "development")
    return _config_map.get(env, DevelopmentConfig)
