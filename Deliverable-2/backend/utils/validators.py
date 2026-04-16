"""
Server-side input validators.
Return None when valid, a human-readable error string when invalid.
All strings are stripped before checks.
"""
import re
from datetime import date, datetime

_EMAIL_RE = re.compile(r"^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$")
_UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    re.IGNORECASE,
)
_PHONE_RE = re.compile(r"^\+?[\d\s\-()\.]{ 7,20}$")
_NAME_RE = re.compile(r"^[a-zA-Z\s'\-]{2,100}$")
_MFA_RE = re.compile(r"^\d{6}$")
_DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
_TIME_RE = re.compile(r"^\d{2}:\d{2}(:\d{2})?$")

# Patterns that indicate injection attempts
_SQL_RE = re.compile(
    r"(?:'(?:--|;)|;--|/\*|\*/|xp_|0x[0-9a-f]+|"
    r"\b(?:union|select|insert|update|delete|drop|truncate|alter|"
    r"exec(?:ute)?|declare|cast|convert|having|waitfor\s+delay|"
    r"information_schema|sys\.)\b)",
    re.IGNORECASE,
)
_XSS_RE = re.compile(
    r"(?:<\s*script|javascript\s*:|vbscript\s*:|on\w+\s*=|"
    r"data\s*:\s*text/html|<\s*iframe|<\s*object|<\s*embed|"
    r"expression\s*\()",
    re.IGNORECASE,
)
_PATH_TRAVERSAL_RE = re.compile(
    r"(?:\.\./|\.\.\\|%2e%2e%2f|%2e%2e/|%252e%252e)", re.IGNORECASE
)


def _is_safe(value: str) -> bool:
    """Return False if the string contains injection or traversal patterns."""
    return not (
        _SQL_RE.search(value)
        or _XSS_RE.search(value)
        or _PATH_TRAVERSAL_RE.search(value)
    )


# ---- Primitive validators ----

def validate_required(value, field="Field"):
    if value is None or (isinstance(value, str) and not value.strip()):
        return f"{field} is required."
    return None


def validate_email(email):
    if not email or not isinstance(email, str):
        return "Email is required."
    email = email.strip()
    if len(email) > 254:
        return "Email address is too long."
    if not _EMAIL_RE.match(email):
        return "Invalid email address."
    if not _is_safe(email):
        return "Email contains invalid characters."
    return None


def validate_password(password):
    if not password or not isinstance(password, str):
        return "Password is required."
    if len(password) < 8:
        return "Password must be at least 8 characters."
    if len(password) > 128:
        return "Password is too long."
    if not re.search(r"[A-Z]", password):
        return "Password must contain at least one uppercase letter."
    if not re.search(r"[a-z]", password):
        return "Password must contain at least one lowercase letter."
    if not re.search(r"\d", password):
        return "Password must contain at least one number."
    if not re.search(r"[!@#$%^&*()\-_=+\[\]{}|;:',.<>/?]", password):
        return "Password must contain at least one special character."
    return None


def validate_uuid(value, field="ID"):
    if not value or not isinstance(value, str):
        return f"{field} is required."
    if not _UUID_RE.match(value.strip()):
        return f"Invalid {field} format."
    return None


def validate_name(value, field="Name"):
    if not value or not isinstance(value, str):
        return f"{field} is required."
    value = value.strip()
    if len(value) < 2 or len(value) > 100:
        return f"{field} must be between 2 and 100 characters."
    if not _NAME_RE.match(value):
        return f"{field} contains invalid characters."
    if not _is_safe(value):
        return f"{field} contains invalid characters."
    return None


def validate_phone(phone):
    if not phone:
        return None  # optional field
    if not isinstance(phone, str):
        return "Invalid phone number."
    phone = phone.strip()
    if not _PHONE_RE.match(phone):
        return "Invalid phone number format."
    return None


def validate_mfa_code(code):
    if not code or not isinstance(code, str):
        return "Verification code is required."
    if not _MFA_RE.match(code.strip()):
        return "Verification code must be exactly 6 digits."
    return None


def validate_date(value, field="Date"):
    if not value:
        return None  # optional
    if not isinstance(value, str) or not _DATE_RE.match(value.strip()):
        return f"{field} must be in YYYY-MM-DD format."
    try:
        datetime.strptime(value.strip(), "%Y-%m-%d")
    except ValueError:
        return f"Invalid {field}."
    return None


def validate_dob(value):
    err = validate_date(value, "Date of birth")
    if err:
        return err
    try:
        dob = datetime.strptime(value.strip(), "%Y-%m-%d").date()
    except (ValueError, AttributeError):
        return "Invalid date of birth."
    if dob > date.today():
        return "Date of birth cannot be in the future."
    if (date.today() - dob).days > 150 * 365:
        return "Invalid date of birth."
    return None


def validate_time(value, field="Time"):
    if not value:
        return None
    if not isinstance(value, str) or not _TIME_RE.match(value.strip()):
        return f"{field} must be in HH:MM format."
    return None


def validate_string(value, field="Field", min_len=1, max_len=500):
    if not value or not isinstance(value, str):
        return f"{field} is required."
    value = value.strip()
    if len(value) < min_len:
        return f"{field} must be at least {min_len} characters."
    if len(value) > max_len:
        return f"{field} must be at most {max_len} characters."
    if not _is_safe(value):
        return f"{field} contains invalid characters."
    return None


def validate_boolean(value, field="Field"):
    if not isinstance(value, bool):
        return f"{field} must be a boolean."
    return None


def validate_integer(value, field="Field", min_val=None, max_val=None):
    if not isinstance(value, int) or isinstance(value, bool):
        return f"{field} must be an integer."
    if min_val is not None and value < min_val:
        return f"{field} must be at least {min_val}."
    if max_val is not None and value > max_val:
        return f"{field} must be at most {max_val}."
    return None


def validate_list_of_strings(value, field="Field", max_items=50, item_max_len=200):
    if value is None:
        return None  # optional
    if not isinstance(value, list):
        return f"{field} must be a list."
    if len(value) > max_items:
        return f"{field} contains too many items."
    for item in value:
        if not isinstance(item, str):
            return f"Each item in {field} must be a string."
        if len(item) > item_max_len:
            return f"An item in {field} is too long."
        if not _is_safe(item):
            return f"An item in {field} contains invalid characters."
    return None


def collect_errors(**field_validators):
    """
    Run multiple validators and return the first error found, or None.
    Usage: collect_errors(email=validate_email(email), name=validate_name(name))
    """
    for _field, err in field_validators.items():
        if err:
            return err
    return None
