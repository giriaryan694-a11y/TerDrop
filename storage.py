"""
TerDrop Storage Layer
TXT-file based persistent storage — no SQL, no SQLite.
Each record is a JSON line. Files are locked with threading.Lock for safety.
"""

import json
import os
import threading
import time
import uuid
from pathlib import Path

DATA_DIR = Path(__file__).parent / "data"
DATA_DIR.mkdir(exist_ok=True)

USERS_FILE    = DATA_DIR / "users.txt"
FILES_FILE    = DATA_DIR / "files.txt"
PERMS_FILE    = DATA_DIR / "perms.txt"
CHATS_FILE    = DATA_DIR / "chats.txt"
SESSIONS_FILE = DATA_DIR / "sessions.txt"
ATTEMPTS_FILE = DATA_DIR / "attempts.txt"
SETTINGS_FILE = DATA_DIR / "settings.txt"

_locks = {f: threading.Lock() for f in [
    USERS_FILE, FILES_FILE, PERMS_FILE,
    CHATS_FILE, SESSIONS_FILE, ATTEMPTS_FILE, SETTINGS_FILE
]}

# ── Generic helpers ────────────────────────────────────────────────────────────

def _read(path: Path) -> list[dict]:
    """Read all JSON-line records from a file."""
    if not path.exists():
        return []
    with _locks[path], open(path, "r", encoding="utf-8") as f:
        records = []
        for line in f:
            line = line.strip()
            if line:
                try:
                    records.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
        return records

def _write_all(path: Path, records: list[dict]):
    """Overwrite file with records list."""
    with _locks[path], open(path, "w", encoding="utf-8") as f:
        for r in records:
            f.write(json.dumps(r) + "\n")

def _append(path: Path, record: dict):
    """Append single record."""
    with _locks[path], open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(record) + "\n")

# ── Users ──────────────────────────────────────────────────────────────────────

def get_user(username: str) -> dict | None:
    for u in _read(USERS_FILE):
        if u.get("username") == username:
            return u
    return None

def get_user_by_id(uid: str) -> dict | None:
    for u in _read(USERS_FILE):
        if u.get("id") == uid:
            return u
    return None

def create_user(username: str, password_hash: str, role: str = "user",
                expire_minutes: int | None = None) -> dict:
    uid = str(uuid.uuid4())
    now = time.time()
    expires_at = now + (expire_minutes * 60) if expire_minutes else None
    record = {
        "id": uid,
        "username": username,
        "password_hash": password_hash,
        "role": role,          # "admin" | "user"
        "created_at": now,
        "expires_at": expires_at,
        "active": True,
        "storage_quota_mb": 100,
        "notifications_enabled": True,
    }
    _append(USERS_FILE, record)
    return record

def update_user(uid: str, **fields):
    records = _read(USERS_FILE)
    for r in records:
        if r.get("id") == uid:
            r.update(fields)
    _write_all(USERS_FILE, records)

def delete_user(uid: str):
    records = [r for r in _read(USERS_FILE) if r.get("id") != uid]
    _write_all(USERS_FILE, records)
    # cascade: remove perms
    perms = [p for p in _read(PERMS_FILE) if p.get("user_id") != uid]
    _write_all(PERMS_FILE, perms)
    # cascade: remove sessions
    sessions = [s for s in _read(SESSIONS_FILE) if s.get("user_id") != uid]
    _write_all(SESSIONS_FILE, sessions)

def list_users() -> list[dict]:
    return _read(USERS_FILE)

def is_user_expired(user: dict) -> bool:
    if user.get("expires_at") is None:
        return False
    return time.time() > user["expires_at"]

# ── Files ──────────────────────────────────────────────────────────────────────

def add_file(owner_id: str, filename: str, stored_name: str,
             size_bytes: int, mime_type: str,
             encrypted: bool = False, iv: str | None = None,
             wrapped_key: str | None = None,
             plaintext_size: int | None = None) -> dict:
    """
    encrypted:      whether file bytes on disk are AES-GCM ciphertext
    iv:             base64 AES-GCM IV (only if encrypted)
    wrapped_key:    base64 RSA-OAEP-wrapped AES key (only if encrypted)
    plaintext_size: original file size before encryption, for display
    """
    record = {
        "id": str(uuid.uuid4()),
        "owner_id": owner_id,
        "filename": filename,       # original name shown to user
        "stored_name": stored_name, # UUID-based name on disk
        "size_bytes": size_bytes,   # size of what's actually stored on disk
        "plaintext_size": plaintext_size if plaintext_size is not None else size_bytes,
        "mime_type": mime_type,
        "uploaded_at": time.time(),
        "active": True,
        "encrypted": encrypted,
        "iv": iv,
        "wrapped_key": wrapped_key,
    }
    _append(FILES_FILE, record)
    return record

def get_file(file_id: str) -> dict | None:
    for f in _read(FILES_FILE):
        if f.get("id") == file_id and f.get("active"):
            return f
    return None

def list_files(owner_id: str | None = None) -> list[dict]:
    records = [f for f in _read(FILES_FILE) if f.get("active")]
    if owner_id:
        records = [f for f in records if f.get("owner_id") == owner_id]
    return records

def delete_file(file_id: str):
    records = _read(FILES_FILE)
    for r in records:
        if r.get("id") == file_id:
            r["active"] = False
    _write_all(FILES_FILE, records)
    # cascade: remove perms
    perms = [p for p in _read(PERMS_FILE) if p.get("file_id") != file_id]
    _write_all(PERMS_FILE, perms)

def list_all_files() -> list[dict]:
    return [f for f in _read(FILES_FILE) if f.get("active")]

# ── Permissions ────────────────────────────────────────────────────────────────
# A permission grant is simply "this user can see and download this file."
# There is no separate view-only mode — if you can see a file's contents,
# withholding download serves no real purpose, so both are granted together.

def grant_permission(user_id: str, file_id: str,
                     expire_minutes: int | None = None):
    # Remove existing perm first
    revoke_permission(user_id, file_id)
    now = time.time()
    expires_at = now + (expire_minutes * 60) if expire_minutes else None
    record = {
        "id": str(uuid.uuid4()),
        "user_id": user_id,
        "file_id": file_id,
        "can_access": True,
        "granted_at": now,
        "expires_at": expires_at,
    }
    _append(PERMS_FILE, record)
    return record

def grant_permission_multi(user_ids: list[str], file_id: str,
                           expire_minutes: int | None = None) -> list[dict]:
    """Grant the same file to several users in one call."""
    return [grant_permission(uid, file_id, expire_minutes) for uid in user_ids]

def revoke_permission(user_id: str, file_id: str):
    perms = [p for p in _read(PERMS_FILE)
             if not (p.get("user_id") == user_id and p.get("file_id") == file_id)]
    _write_all(PERMS_FILE, perms)

def get_permission(user_id: str, file_id: str) -> dict | None:
    for p in _read(PERMS_FILE):
        if p.get("user_id") == user_id and p.get("file_id") == file_id:
            # Check perm expiry
            if p.get("expires_at") and time.time() > p["expires_at"]:
                return None
            return p
    return None

def has_access(user_id: str, file_id: str) -> bool:
    perm = get_permission(user_id, file_id)
    return bool(perm and perm.get("can_access"))

def list_file_perms(file_id: str) -> list[dict]:
    now = time.time()
    return [p for p in _read(PERMS_FILE)
            if p.get("file_id") == file_id
            and (not p.get("expires_at") or now < p["expires_at"])]

def list_user_perms(user_id: str) -> list[dict]:
    now = time.time()
    return [p for p in _read(PERMS_FILE)
            if p.get("user_id") == user_id
            and (not p.get("expires_at") or now < p["expires_at"])]

# ── Chat messages ──────────────────────────────────────────────────────────────

def add_message(sender_id: str, sender_role: str, content: str,
                thread_user_id: str) -> dict:
    """thread_user_id: the non-admin participant of the conversation."""
    record = {
        "id": str(uuid.uuid4()),
        "sender_id": sender_id,
        "sender_role": sender_role,  # "admin" | "user"
        "content": content,
        "thread_user_id": thread_user_id,
        "timestamp": time.time(),
        "read": False,
    }
    _append(CHATS_FILE, record)
    return record

def get_thread(thread_user_id: str) -> list[dict]:
    msgs = [m for m in _read(CHATS_FILE)
            if m.get("thread_user_id") == thread_user_id]
    return sorted(msgs, key=lambda m: m["timestamp"])

def get_new_user_messages(since: float) -> list[dict]:
    """All messages sent BY users (not the admin) across every thread,
    newer than `since`. Used by the admin's global notification poller so
    a reply on any thread surfaces a notification, not just the one
    currently open."""
    msgs = [m for m in _read(CHATS_FILE)
            if m.get("sender_role") == "user" and m.get("timestamp", 0) > since]
    return sorted(msgs, key=lambda m: m["timestamp"])

def mark_thread_read(thread_user_id: str, reader_role: str):
    records = _read(CHATS_FILE)
    for r in records:
        if r.get("thread_user_id") == thread_user_id and r.get("sender_role") != reader_role:
            r["read"] = True
    _write_all(CHATS_FILE, records)

def unread_count_for_admin() -> int:
    return sum(1 for m in _read(CHATS_FILE)
               if not m.get("read") and m.get("sender_role") == "user")

def unread_count_for_user(uid: str) -> int:
    return sum(1 for m in _read(CHATS_FILE)
               if not m.get("read")
               and m.get("thread_user_id") == uid
               and m.get("sender_role") == "admin")

# ── Sessions ───────────────────────────────────────────────────────────────────

SESSION_TTL = 3600 * 8  # 8-hour session lifetime

def create_session(user_id: str, ip: str) -> str:
    token = str(uuid.uuid4()) + str(uuid.uuid4())
    record = {
        "token": token,
        "user_id": user_id,
        "ip": ip,
        "created_at": time.time(),
        "last_seen": time.time(),
    }
    _append(SESSIONS_FILE, record)
    return token

def get_session(token: str) -> dict | None:
    for s in _read(SESSIONS_FILE):
        if s.get("token") == token:
            if time.time() - s.get("last_seen", 0) > SESSION_TTL:
                delete_session(token)
                return None
            return s
    return None

def touch_session(token: str):
    records = _read(SESSIONS_FILE)
    for r in records:
        if r.get("token") == token:
            r["last_seen"] = time.time()
    _write_all(SESSIONS_FILE, records)

def delete_session(token: str):
    records = [r for r in _read(SESSIONS_FILE) if r.get("token") != token]
    _write_all(SESSIONS_FILE, records)

def delete_user_sessions(user_id: str):
    records = [r for r in _read(SESSIONS_FILE) if r.get("user_id") != user_id]
    _write_all(SESSIONS_FILE, records)

# ── Brute-force tracking ───────────────────────────────────────────────────────
# Keyed on username alone — NOT IP. Behind the Cloudflare tunnel, every remote
# visitor's request reaches this Flask app via cloudflared's local connection,
# so request.remote_addr is 127.0.0.1 for everyone. An IP-keyed lockout would
# mean 5 failed attempts against ANY account, from ANY visitor, locks out
# login for the ENTIRE site. Keying on username only protects each account
# from being brute-forced without that shared-fate blast radius.

ATTEMPT_WINDOW  = 600   # 10 minutes
MAX_ATTEMPTS    = 5

def record_attempt(username: str):
    _append(ATTEMPTS_FILE, {
        "username": username,
        "ts": time.time(),
    })

def clear_attempts(username: str):
    records = [r for r in _read(ATTEMPTS_FILE) if r.get("username") != username]
    _write_all(ATTEMPTS_FILE, records)

def is_locked_out(username: str) -> bool:
    cutoff = time.time() - ATTEMPT_WINDOW
    count = sum(
        1 for r in _read(ATTEMPTS_FILE)
        if r.get("username") == username
        and r.get("ts", 0) > cutoff
    )
    return count >= MAX_ATTEMPTS

def lockout_remaining(username: str) -> int:
    """Seconds until lockout expires."""
    cutoff = time.time() - ATTEMPT_WINDOW
    recent = [r for r in _read(ATTEMPTS_FILE)
              if r.get("username") == username
              and r.get("ts", 0) > cutoff]
    if len(recent) < MAX_ATTEMPTS:
        return 0
    oldest = min(r["ts"] for r in recent)
    remaining = int((oldest + ATTEMPT_WINDOW) - time.time())
    return max(0, remaining)

def cleanup_old_attempts():
    """Prune attempts older than window — call periodically."""
    cutoff = time.time() - ATTEMPT_WINDOW
    records = [r for r in _read(ATTEMPTS_FILE) if r.get("ts", 0) > cutoff]
    _write_all(ATTEMPTS_FILE, records)

# ── Settings (single-record key-value store) ────────────────────────────────────

_DEFAULT_SETTINGS = {
    "encryption_enabled": True,
    "admin_notifications_enabled": True,
}

def get_settings() -> dict:
    records = _read(SETTINGS_FILE)
    if not records:
        _write_all(SETTINGS_FILE, [_DEFAULT_SETTINGS])
        return dict(_DEFAULT_SETTINGS)
    merged = dict(_DEFAULT_SETTINGS)
    merged.update(records[0])
    return merged

def update_settings(**fields):
    current = get_settings()
    current.update(fields)
    _write_all(SETTINGS_FILE, [current])
    return current

def is_encryption_enabled() -> bool:
    return bool(get_settings().get("encryption_enabled", True))

