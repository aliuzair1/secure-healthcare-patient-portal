"""
WSGI entry point — used by Gunicorn in production.
  gunicorn "wsgi:application" --workers 4 --bind 0.0.0.0:5000
"""
from app import create_app

application = create_app()

if __name__ == "__main__":
    application.run()
