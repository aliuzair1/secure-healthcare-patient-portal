"""
Supabase service-role client — bypasses RLS intentionally.
Access control is enforced by our own middleware (middleware/auth.py).

Never expose the service-role key to the frontend.
"""
from functools import lru_cache
from flask import current_app
from supabase import create_client, Client


@lru_cache(maxsize=1)
def _build_client(url: str, key: str) -> Client:
    """Build and cache a single Supabase client per process."""
    return create_client(url, key)


def get_supabase() -> Client:
    """Return the shared admin Supabase client."""
    url = current_app.config["SUPABASE_URL"]
    key = current_app.config["SUPABASE_SERVICE_ROLE_KEY"]
    if not url or not key:
        raise RuntimeError(
            "SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY must be set."
        )
    return _build_client(url, key)
