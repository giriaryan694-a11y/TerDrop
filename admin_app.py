"""
TerDrop — Admin Control Panel
Runs on 127.0.0.1:7777 ONLY — never exposed via Cloudflare tunnel.
Handles: user management, file management, permissions, chat replies, tunnel control.
"""

import os
import time

from flask import (Flask, abort, g, jsonify, redirect,
                   render_template, request, session, url_for,
                   send_file, make_response)

import auth
import storage
import tunnel
import crypto_manager
import notify
import fileconf

UPLOAD_DIR = fileconf.UPLOAD_DIR

def _stable_secret(env_var, filename):
    """Persist secret to disk so it survives process restarts."""
    if os.environ.get(env_var):
        return os.environ[env_var]
    from pathlib import Path as _P
    f = _P(__file__).parent / "data" / filename
    f.parent.mkdir(exist_ok=True)
    if f.exists():
        return f.read_text().strip()
    s = os.urandom(32).hex()
    f.write_text(s)
    return s

admin_app = Flask(
    __name__,
    template_folder="templates/admin",
    static_folder="static",
    static_url_path="/static",
)
admin_app.secret_key = _stable_secret("TERDROP_ADMIN_SECRET", ".admin_secret")
admin_app.config["SESSION_COOKIE_NAME"]     = "td_admin_sess"  # no clash with user app cookie
admin_app.config["SESSION_COOKIE_HTTPONLY"] = True
admin_app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
admin_app.config["SESSION_COOKIE_SECURE"]   = False
admin_app.config["WTF_CSRF_TIME_LIMIT"]     = None   # disable WTF token expiry
admin_app.config["PERMANENT_SESSION_LIFETIME"] = 28800
admin_app.config["MAX_CONTENT_LENGTH"] = fileconf.MAX_UPLOAD_MB * 1024 * 1024


# ── Localhost-only guard ───────────────────────────────────────────────────────

@admin_app.before_request
def enforce_localhost():
    """Reject any request not from 127.0.0.1 — extra hard guard."""
    allowed = {"127.0.0.1", "::1", "localhost"}
    remote = request.remote_addr
    if remote not in allowed:
        abort(403)

# ── Security headers ───────────────────────────────────────────────────────────

@admin_app.after_request
def set_admin_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate"
    response.headers["Pragma"] = "no-cache"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com; "
        "img-src 'self' data:;"
    )
    return response

# ── Context processor ──────────────────────────────────────────────────────────

@admin_app.context_processor
def inject_admin_globals():
    user = _admin_current_user()
    unread = storage.unread_count_for_admin()
    tun = tunnel.get_status()
    return dict(
        current_user=user,
        unread_count=unread,
        csrf_token=auth.generate_csrf_token,
        tunnel_status=tun,
        encryption_enabled=storage.is_encryption_enabled(),
    )

# ── Admin session helpers ──────────────────────────────────────────────────────

def _admin_current_user() -> dict | None:
    token = session.get("admin_token")
    if not token:
        return None
    sess = storage.get_session(token)
    if not sess:
        return None
    storage.touch_session(token)
    user = storage.get_user_by_id(sess["user_id"])
    if not user or user.get("role") != "admin":
        return None
    return user

def _require_admin_login(f):
    from functools import wraps
    @wraps(f)
    def decorated(*args, **kwargs):
        user = _admin_current_user()
        if not user:
            return redirect(url_for("admin_login"))
        g.user = user
        return f(*args, **kwargs)
    return decorated

# ── Login ──────────────────────────────────────────────────────────────────────

@admin_app.route("/", methods=["GET"])
def admin_root():
    user = _admin_current_user()
    return redirect(url_for("admin_dashboard") if user else url_for("admin_login"))

@admin_app.route("/login", methods=["GET", "POST"])
@auth.csrf_protect
def admin_login():
    if _admin_current_user():
        return redirect(url_for("admin_dashboard"))

    error = None
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        lockout_key = f"admin:{username}"

        if storage.is_locked_out(lockout_key):
            remaining = storage.lockout_remaining(lockout_key)
            error = f"Too many attempts. Wait {remaining}s."
        else:
            user = storage.get_user(username)
            if user and user.get("role") == "admin" and \
               auth.verify_password(user["password_hash"], password):
                storage.clear_attempts(lockout_key)
                token = storage.create_session(user["id"], "127.0.0.1")
                session.permanent = True
                session["admin_token"] = token
                return redirect(url_for("admin_dashboard"))
            else:
                storage.record_attempt(lockout_key)
                error = "Invalid credentials."

    return render_template("admin_login.html", error=error)

@admin_app.route("/logout", methods=["POST"])
@auth.csrf_protect
def admin_logout():
    token = session.get("admin_token")
    if token:
        storage.delete_session(token)
    session.clear()
    return redirect(url_for("admin_login"))

# ── Dashboard ──────────────────────────────────────────────────────────────────

@admin_app.route("/dashboard")
@_require_admin_login
def admin_dashboard():
    users = storage.list_users()
    files = storage.list_all_files()
    tun   = tunnel.get_status()
    stats = {
        "users": len(users),
        "files": len(files),
        "total_size": sum(f.get("size_bytes", 0) for f in files),
        "unread_msgs": storage.unread_count_for_admin(),
    }
    return render_template("admin_dashboard.html", stats=stats,
                           tunnel_status=tun, tun_log=tunnel.get_log()[-10:])

# ── User management ────────────────────────────────────────────────────────────

@admin_app.route("/users")
@_require_admin_login
def admin_users():
    users = storage.list_users()
    now = time.time()
    for u in users:
        u["_expired"] = storage.is_user_expired(u)
        u["_expires_in"] = None
        if u.get("expires_at"):
            rem = int(u["expires_at"] - now)
            u["_expires_in"] = max(0, rem)
    return render_template("admin_users.html", users=users)

@admin_app.route("/users/create", methods=["GET", "POST"])
@auth.csrf_protect
@_require_admin_login
def admin_create_user():
    error = None
    success = None
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        expire_m = request.form.get("expire_minutes", "").strip()

        err = auth.validate_username(username)
        if err:
            error = err
        elif auth.validate_password(password):
            error = auth.validate_password(password)
        elif storage.get_user(username):
            error = f"Username '{username}' already exists."
        else:
            expire_m = int(expire_m) if expire_m.isdigit() else None
            ph = auth.hash_password(password)
            # TerDrop supports exactly one admin — the Termux operator.
            # Accounts created here are always regular users.
            storage.create_user(username, ph, role="user", expire_minutes=expire_m)
            success = f"User '{username}' created."

    return render_template("admin_create_user.html", error=error,
                           success=success)

@admin_app.route("/users/<uid>/edit", methods=["GET", "POST"])
@auth.csrf_protect
@_require_admin_login
def admin_edit_user(uid: str):
    user = storage.get_user_by_id(uid)
    if not user:
        abort(404)

    error = None
    success = None

    if request.method == "POST":
        action = request.form.get("action", "")

        if action == "change_password":
            new_pw = request.form.get("new_password", "")
            err = auth.validate_password(new_pw)
            if err:
                error = err
            else:
                ph = auth.hash_password(new_pw)
                storage.update_user(uid, password_hash=ph)
                storage.delete_user_sessions(uid)
                success = "Password updated. All sessions invalidated."

        elif action == "change_username":
            new_un = request.form.get("new_username", "").strip()
            err = auth.validate_username(new_un)
            if err:
                error = err
            elif storage.get_user(new_un) and new_un != user["username"]:
                error = "Username already taken."
            else:
                storage.update_user(uid, username=new_un)
                success = "Username updated."

        elif action == "set_expiry":
            expire_m = request.form.get("expire_minutes", "").strip()
            expire_m = int(expire_m) if expire_m.isdigit() else None
            expires_at = time.time() + (expire_m * 60) if expire_m else None
            storage.update_user(uid, expires_at=expires_at)
            success = f"Expiry set to {expire_m} minutes." if expire_m else "Expiry removed."

        elif action == "toggle_active":
            new_state = not user.get("active", True)
            storage.update_user(uid, active=new_state)
            if not new_state:
                storage.delete_user_sessions(uid)
            success = "Active" if new_state else "Deactivated"

        elif action == "set_quota":
            quota = request.form.get("quota_mb", "100").strip()
            quota = int(quota) if quota.isdigit() else 100
            storage.update_user(uid, storage_quota_mb=quota)
            success = f"Quota set to {quota} MB."

        # Refresh user
        user = storage.get_user_by_id(uid)

    return render_template("admin_edit_user.html", u=user,
                           error=error, success=success)

@admin_app.route("/users/<uid>/delete", methods=["POST"])
@auth.csrf_protect
@_require_admin_login
def admin_delete_user(uid: str):
    user = storage.get_user_by_id(uid)
    if not user:
        abort(404)
    if user.get("role") == "admin":
        # The admin account (the Termux operator) can never be deleted here.
        return redirect(url_for("admin_users"))
    storage.delete_user(uid)
    return redirect(url_for("admin_users"))

# ── Upload (admin uploads directly here — no redirect to user app) ──────────────

@admin_app.route("/upload", methods=["GET", "POST"])
@auth.csrf_protect
@_require_admin_login
def admin_upload():
    import uuid as _uuid

    admin_user = g.user
    error = None
    success = None

    # Every regular user is a valid share target — the admin always has
    # access to everything regardless, so isn't a meaningful choice here.
    grantable_users = [u for u in storage.list_users() if u.get("role") != "admin"]

    if request.method == "POST":
        if "file" not in request.files:
            error = "No file selected."
        else:
            f = request.files["file"]
            original_filename = request.form.get("original_filename", "").strip() or f.filename

            if not original_filename:
                error = "Empty filename."
            else:
                original_name = auth.sanitize_filename(original_filename)
                ext = original_name.rsplit(".", 1)[-1].lower() if "." in original_name else ""

                if ext not in fileconf.ALLOWED_EXTENSIONS:
                    error = f"File type not allowed: .{ext or 'unknown'}"
                else:
                    is_encrypted = request.form.get("encrypted") == "1"
                    iv_b64          = request.form.get("iv")
                    wrapped_key_b64 = request.form.get("wrapped_key")
                    plaintext_size  = request.form.get("plaintext_size", type=int)

                    stored_name = f"{_uuid.uuid4().hex}.{ext}" if ext else _uuid.uuid4().hex
                    dest = UPLOAD_DIR / stored_name
                    f.save(str(dest))
                    disk_size = dest.stat().st_size

                    stored_mime = "application/octet-stream" if is_encrypted else fileconf.guess_mime(original_name)

                    record = storage.add_file(
                        owner_id=admin_user["id"],
                        filename=original_name,
                        stored_name=stored_name,
                        size_bytes=disk_size,
                        mime_type=stored_mime,
                        encrypted=is_encrypted,
                        iv=iv_b64 if is_encrypted else None,
                        wrapped_key=wrapped_key_b64 if is_encrypted else None,
                        plaintext_size=plaintext_size if is_encrypted else disk_size,
                    )
                    # Admin always has access as owner — nothing extra to grant
                    # for themselves. Optionally share with specific users now.
                    share_ids = [uid for uid in request.form.getlist("share_with") if uid]
                    valid_ids = {u["id"] for u in grantable_users}
                    share_ids = [uid for uid in share_ids if uid in valid_ids]
                    shared_names = []
                    if share_ids:
                        storage.grant_permission_multi(share_ids, record["id"])
                        id_to_name = {u["id"]: u["username"] for u in grantable_users}
                        shared_names = [id_to_name[uid] for uid in share_ids]

                    lock_note = " 🔒 Encrypted end-to-end." if is_encrypted else ""
                    share_note = f" Shared with {', '.join(shared_names)}." if shared_names else " Visible only to you for now."
                    success = f"'{original_name}' uploaded successfully.{lock_note}{share_note}"

    return render_template("admin_upload.html", error=error, success=success,
                           max_mb=fileconf.MAX_UPLOAD_MB,
                           encryption_enabled=storage.is_encryption_enabled(),
                           grantable_users=grantable_users)

@admin_app.route("/api/public-key")
@_require_admin_login
def admin_api_public_key():
    return jsonify({
        "public_key_pem": crypto_manager.get_public_key_pem(),
        "fingerprint": crypto_manager.key_fingerprint(),
        "encryption_enabled": storage.is_encryption_enabled(),
    })

@admin_app.route("/download/<file_id>")
@_require_admin_login
def admin_download(file_id: str):
    if not file_id or len(file_id) > 64 or not file_id.replace("-", "").isalnum():
        abort(400)

    file_rec = storage.get_file(file_id)
    if not file_rec:
        abort(404)

    stored_name = file_rec["stored_name"]
    if not auth.is_safe_path(str(UPLOAD_DIR), stored_name):
        abort(400)

    path = UPLOAD_DIR / stored_name
    if not path.exists():
        abort(404)

    original_mime = fileconf.guess_mime(file_rec["filename"])

    if file_rec.get("encrypted"):
        try:
            ciphertext = path.read_bytes()
            plaintext = crypto_manager.decrypt_file(
                ciphertext, file_rec["iv"], file_rec["wrapped_key"]
            )
        except Exception:
            abort(500)
        response = make_response(plaintext)
        response.headers["Content-Type"] = original_mime
        response.headers["Content-Disposition"] = f'attachment; filename="{file_rec["filename"]}"'
        return response

    return send_file(
        str(path),
        download_name=file_rec["filename"],
        as_attachment=True,
        mimetype=file_rec.get("mime_type", "application/octet-stream"),
    )

# ── File management ────────────────────────────────────────────────────────────

@admin_app.route("/files")
@_require_admin_login
def admin_files():
    files = storage.list_all_files()
    user_map = {u["id"]: u["username"] for u in storage.list_users()}
    for f in files:
        f["_owner_name"] = user_map.get(f["owner_id"], "?")
        f["_perms"] = storage.list_file_perms(f["id"])
        for p in f["_perms"]:
            p["_username"] = user_map.get(p["user_id"], "?")
        # Display MIME reflects the ORIGINAL file type — encrypted files are
        # stored as opaque octet-stream on disk regardless of real type.
        f["_display_mime"] = fileconf.guess_mime(f["filename"])
        f["_display_size"] = f.get("plaintext_size", f.get("size_bytes", 0))
        f["_uploaded_str"] = time.strftime(
            "%b %d, %Y %H:%M", time.localtime(f.get("uploaded_at", 0))
        )
    return render_template("admin_files.html", files=files)

@admin_app.route("/files/<file_id>/delete", methods=["POST"])
@auth.csrf_protect
@_require_admin_login
def admin_delete_file(file_id: str):
    file_rec = storage.get_file(file_id)
    if not file_rec:
        abort(404)
    path = UPLOAD_DIR / file_rec["stored_name"]
    try:
        path.unlink(missing_ok=True)
    except Exception:
        pass
    storage.delete_file(file_id)
    return redirect(url_for("admin_files"))

# ── Permissions ────────────────────────────────────────────────────────────────

@admin_app.route("/files/<file_id>/perms", methods=["GET", "POST"])
@auth.csrf_protect
@_require_admin_login
def admin_file_perms(file_id: str):
    file_rec = storage.get_file(file_id)
    if not file_rec:
        abort(404)

    # Grantable = regular users who don't already own this file (the owner
    # always has access implicitly and doesn't need — or show up in — perms).
    users = [u for u in storage.list_users()
             if u.get("role") == "user" and u["id"] != file_rec["owner_id"]]
    success = error = None

    if request.method == "POST":
        action = request.form.get("action", "")

        if action == "grant":
            uids = [u for u in request.form.getlist("user_ids") if u]
            valid_ids = {u["id"] for u in users}
            uids = [u for u in uids if u in valid_ids]

            if not uids:
                error = "Select at least one user to share with."
            else:
                expire_m = request.form.get("expire_minutes", "").strip()
                expire_m = int(expire_m) if expire_m.isdigit() else None
                storage.grant_permission_multi(uids, file_id, expire_m)
                names = ", ".join(u["username"] for u in users if u["id"] in uids)
                success = f"Shared with {names}."

        elif action == "revoke":
            uid = request.form.get("user_id", "").strip()
            if not uid or not storage.get_user_by_id(uid):
                error = "Please select a valid user."
            else:
                storage.revoke_permission(uid, file_id)
                success = "Access revoked."

    perms = storage.list_file_perms(file_id)
    user_map = {u["id"]: u["username"] for u in storage.list_users()}
    for p in perms:
        p["_username"] = user_map.get(p["user_id"], "?")

    # Don't offer users who already have access again in the grant list
    already_shared = {p["user_id"] for p in perms}
    grantable_users = [u for u in users if u["id"] not in already_shared]

    return render_template("admin_perms.html", file_rec=file_rec,
                           perms=perms, users=grantable_users, success=success,
                           error=error, now=time.time())

# ── Chat ───────────────────────────────────────────────────────────────────────

@admin_app.route("/chat")
@_require_admin_login
def admin_chat_list():
    users = [u for u in storage.list_users() if u.get("role") == "user"]
    for u in users:
        u["_unread"] = storage.unread_count_for_user(u["id"])
        msgs = storage.get_thread(u["id"])
        u["_last_msg"] = msgs[-1]["content"][:60] + "…" if msgs else "No messages"
        u["_last_ts"] = msgs[-1]["timestamp"] if msgs else 0
    users.sort(key=lambda u: u["_last_ts"], reverse=True)
    return render_template("admin_chat_list.html", users=users)

@admin_app.route("/chat/<uid>", methods=["GET", "POST"])
@auth.csrf_protect
@_require_admin_login
def admin_chat_thread(uid: str):
    target = storage.get_user_by_id(uid)
    if not target:
        abort(404)

    admin_user = g.user
    error = None

    if request.method == "POST":
        content = request.form.get("message", "").strip()
        content = auth.sanitize_html(content)
        if content and len(content) <= 2000:
            storage.add_message(
                sender_id=admin_user["id"],
                sender_role="admin",
                content=content,
                thread_user_id=uid,
            )
        else:
            error = "Message must be 1–2000 characters."

    storage.mark_thread_read(uid, "admin")
    messages = storage.get_thread(uid)
    return render_template("admin_chat_thread.html", messages=messages,
                           target=target, error=error)

@admin_app.route("/chat/<uid>/poll")
@_require_admin_login
def admin_chat_poll(uid: str):
    since = float(request.args.get("since", 0))
    messages = [m for m in storage.get_thread(uid) if m["timestamp"] > since]
    return jsonify([{
        "id": m["id"],
        "sender_role": m["sender_role"],
        "content": m["content"],
        "timestamp": m["timestamp"],
    } for m in messages])

@admin_app.route("/chat/poll-all")
@_require_admin_login
def admin_chat_poll_all():
    """Global poller — surfaces new messages from ANY user thread, for the
    admin's browser notification popup regardless of which page is open."""
    since = float(request.args.get("since", 0))
    messages = storage.get_new_user_messages(since)
    user_map = {u["id"]: u["username"] for u in storage.list_users()}
    return jsonify([{
        "id": m["id"],
        "sender_role": m["sender_role"],
        "sender_name": user_map.get(m["sender_id"], "User"),
        "content": m["content"],
        "timestamp": m["timestamp"],
    } for m in messages])

@admin_app.route("/notifications", methods=["GET", "POST"])
@auth.csrf_protect
@_require_admin_login
def admin_notifications():
    success = None
    if request.method == "POST":
        enabled = request.form.get("admin_notifications_enabled") == "on"
        storage.update_settings(admin_notifications_enabled=enabled)
        success = "Preferences saved."

    settings = storage.get_settings()
    return render_template("admin_notifications.html",
                           settings=settings,
                           success=success,
                           termux_available=notify.is_available())

# ── Tunnel control ─────────────────────────────────────────────────────────────

@admin_app.route("/tunnel")
@_require_admin_login
def admin_tunnel():
    status = tunnel.get_status()
    log    = tunnel.get_log()
    return render_template("admin_tunnel.html", status=status,
                           log=log)

@admin_app.route("/tunnel/start", methods=["POST"])
@auth.csrf_protect
@_require_admin_login
def admin_tunnel_start():
    ok = tunnel.start(port=5000)
    return jsonify({"ok": ok, "status": tunnel.get_status()})

@admin_app.route("/tunnel/stop", methods=["POST"])
@auth.csrf_protect
@_require_admin_login
def admin_tunnel_stop():
    tunnel.stop()
    return jsonify({"ok": True, "status": tunnel.get_status()})

@admin_app.route("/tunnel/restart", methods=["POST"])
@auth.csrf_protect
@_require_admin_login
def admin_tunnel_restart():
    ok = tunnel.restart(port=5000)
    return jsonify({"ok": ok, "status": tunnel.get_status()})

@admin_app.route("/tunnel/status")
@_require_admin_login
def admin_tunnel_status():
    return jsonify(tunnel.get_status())

# ── Encryption control ──────────────────────────────────────────────────────────

@admin_app.route("/encryption")
@_require_admin_login
def admin_encryption():
    settings = storage.get_settings()
    fingerprint = crypto_manager.key_fingerprint()
    encrypted_count = sum(1 for f in storage.list_all_files() if f.get("encrypted"))
    plain_count = sum(1 for f in storage.list_all_files() if not f.get("encrypted"))
    return render_template("admin_encryption.html",
                           settings=settings,
                           fingerprint=fingerprint,
                           encrypted_count=encrypted_count,
                           plain_count=plain_count)

@admin_app.route("/encryption/toggle", methods=["POST"])
@auth.csrf_protect
@_require_admin_login
def admin_encryption_toggle():
    current = storage.is_encryption_enabled()
    storage.update_settings(encryption_enabled=not current)
    return redirect(url_for("admin_encryption"))

@admin_app.route("/encryption/rotate", methods=["POST"])
@auth.csrf_protect
@_require_admin_login
def admin_encryption_rotate():
    """Generate a fresh RSA keypair. WARNING: any files encrypted under the
    old key become permanently undecryptable — the template warns before
    this is called."""
    crypto_manager.rotate_keypair()
    return redirect(url_for("admin_encryption"))

# ── Error handlers ─────────────────────────────────────────────────────────────

@admin_app.errorhandler(403)
def admin_forbidden(e):
    return "<h1>403 Forbidden</h1><p>Admin portal is localhost-only.</p>", 403

@admin_app.errorhandler(404)
def admin_not_found(e):
    return render_template("admin_error.html", code=404, msg="Not found."), 404

# ── Run ────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    admin_app.run(host="127.0.0.1", port=7777, debug=False, threaded=True)
