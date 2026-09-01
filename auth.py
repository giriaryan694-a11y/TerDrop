"""
TerDrop Auth Module
Argon2id password hashing, session cookies, CSRF tokens, input sanitization.
"""

import hashlib
import hmac
import html
import os
import re
import secrets
import time
import unicodedata
from functools import wraps

from flask import abort, request, session, redirect, url_for, g
import storage

# ── Argon2id hashing ───────────────────────────────────────────────────────────

try:
    from argon2 import PasswordHasher
    from argon2.exceptions import VerifyMismatchError, VerificationError, InvalidHashError

    # OWASP 2024 recommended params: m=64MB, t=3, p=1
    _ph = PasswordHasher(
        time_cost=3,
        memory_cost=65536,   # 64 MB
        parallelism=1,
        hash_len=32,
        salt_len=16,
    )

    def hash_password(password: str) -> str:
        return _ph.hash(password)

    def verify_password(stored_hash: str, password: str) -> bool:
        try:
            return _ph.verify(stored_hash, password)
        except (VerifyMismatchError, VerificationError, InvalidHashError):
            return False

    def needs_rehash(stored_hash: str) -> bool:
        return _ph.check_needs_rehash(stored_hash)

except ImportError:
    # Fallback if argon2-cffi not installed — WARN loudly
    import hashlib
    print("[!] WARNING: argon2-cffi not installed. Using SHA-256 fallback (insecure).")

    def hash_password(password: str) -> str:
        salt = secrets.token_hex(16)
        h = hashlib.sha256(f"{salt}:{password}".encode()).hexdigest()
        return f"sha256:{salt}:{h}"

    def verify_password(stored_hash: str, password: str) -> bool:
        try:
            _, salt, h = stored_hash.split(":", 2)
            return hmac.compare_digest(
                h, hashlib.sha256(f"{salt}:{password}".encode()).hexdigest()
            )
        except Exception:
            return False

    def needs_rehash(stored_hash: str) -> bool:
        return not stored_hash.startswith("argon2")

# ── CSRF ───────────────────────────────────────────────────────────────────────

CSRF_SESSION_KEY = "_csrf_token"
CSRF_FIELD_NAME  = "csrf_token"
CSRF_HEADER_NAME = "X-CSRF-Token"
CSRF_TTL         = 3600  # 1 hour

def generate_csrf_token() -> str:
    if CSRF_SESSION_KEY not in session or \
       time.time() - session.get("_csrf_ts", 0) > CSRF_TTL:
        session[CSRF_SESSION_KEY] = secrets.token_hex(32)
        session["_csrf_ts"] = time.time()
    return session[CSRF_SESSION_KEY]

def validate_csrf() -> bool:
    """Validate CSRF token from form field or header."""
    expected = session.get(CSRF_SESSION_KEY)
    if not expected:
        return False
    token = (request.form.get(CSRF_FIELD_NAME)
             or request.headers.get(CSRF_HEADER_NAME, ""))
    return hmac.compare_digest(expected, token)

def csrf_protect(f):
    """Decorator: enforce CSRF on state-mutating methods."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if request.method in ("POST", "PUT", "DELETE", "PATCH"):
            if not validate_csrf():
                abort(403)
        return f(*args, **kwargs)
    return decorated

# ── Session / login ────────────────────────────────────────────────────────────

SESSION_COOKIE = "td_session"

def login_user(user: dict, response_obj=None):
    """Store session token in flask session."""
    token = storage.create_session(user["id"], get_client_ip())
    session["token"] = token
    session["uid"] = user["id"]
    session["role"] = user["role"]
    session.permanent = True

def logout_user():
    token = session.get("token")
    if token:
        storage.delete_session(token)
    session.clear()

def current_user() -> dict | None:
    token = session.get("token")
    if not token:
        return None
    sess = storage.get_session(token)
    if not sess:
        return None
    storage.touch_session(token)
    user = storage.get_user_by_id(sess["user_id"])
    if not user or not user.get("active"):
        return None
    if storage.is_user_expired(user):
        return None
    return user

def require_login(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        user = current_user()
        if not user:
            return redirect(url_for("login", next=request.path))
        g.user = user
        return f(*args, **kwargs)
    return decorated

def require_user_only(f):
    """Like require_login, but hard-blocks admin accounts even if an admin
    session token somehow exists. The user-facing app is user-only —
    admins have their own separate panel and should never see this app's
    protected pages, regardless of how they got a session here."""
    @wraps(f)
    def decorated(*args, **kwargs):
        user = current_user()
        if not user or user.get("role") == "admin":
            return redirect(url_for("login", next=request.path))
        g.user = user
        return f(*args, **kwargs)
    return decorated

def require_admin(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        user = current_user()
        if not user or user.get("role") != "admin":
            abort(403)
        g.user = user
        return f(*args, **kwargs)
    return decorated

# ── Input sanitization ─────────────────────────────────────────────────────────

_SAFE_FILENAME = re.compile(r"[^\w\-.]")
_PATH_TRAVERSAL = re.compile(r"\.\.|/|\\|%2e%2e|%2f|%5c", re.IGNORECASE)

def sanitize_html(text: str) -> str:
    """Escape HTML entities — prevent XSS in user-supplied text."""
    if not isinstance(text, str):
        return ""
    return html.escape(unicodedata.normalize("NFC", text), quote=True)

def sanitize_filename(filename: str) -> str:
    """
    Sanitize uploaded filenames:
    - Strip directory components (LFI/path-traversal defense)
    - Replace dangerous characters
    - Enforce max length
    """
    if not filename:
        return "upload"
    # Normalize unicode
    filename = unicodedata.normalize("NFC", filename)
    # Strip path separators (LFI / path traversal)
    if _PATH_TRAVERSAL.search(filename):
        filename = os.path.basename(filename.replace("\\", "/"))
    # Keep only safe chars
    name, _, ext = filename.rpartition(".")
    name = _SAFE_FILENAME.sub("_", name)[:64]
    ext  = _SAFE_FILENAME.sub("", ext)[:10].lower()
    safe = f"{name}.{ext}" if ext else name
    return safe or "upload"

def is_safe_path(base_dir: str, path: str) -> bool:
    """IDOR/LFI guard: ensure resolved path is under base_dir."""
    base = os.path.realpath(base_dir)
    target = os.path.realpath(os.path.join(base, path))
    return target.startswith(base + os.sep) or target == base

# ── Rate limiting helpers ──────────────────────────────────────────────────────

def get_client_ip() -> str:
    """Get real IP, respecting CF/proxy headers."""
    # Cloudflare sends CF-Connecting-IP
    return (request.headers.get("CF-Connecting-IP")
            or request.headers.get("X-Forwarded-For", "").split(",")[0].strip()
            or request.remote_addr
            or "unknown")

# ── Username validation ────────────────────────────────────────────────────────

USERNAME_RE = re.compile(r"^[a-zA-Z0-9_\-]{3,32}$")

def validate_username(username: str) -> str | None:
    """Return error string or None if valid."""
    if not USERNAME_RE.match(username):
        return "Username must be 3–32 chars: letters, digits, _ or -"
    return None

def validate_password(password: str) -> str | None:
    if len(password) < 8:
        return "Password must be at least 8 characters"
    return None
