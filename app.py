"""
TerDrop — Main User App
Runs on 127.0.0.1:5000 — reachable ONLY through the Cloudflare tunnel,
never directly from the local network or internet.
Handles: login, file upload, file browser, download, chat with admin.
"""

import os
import time
import uuid

from flask import (Flask, abort, g, jsonify, redirect,
                   render_template, request, send_file,
                   session, url_for, make_response)

import auth
import storage
import tunnel
import crypto_manager
import notify
import fileconf

# ── App setup ──────────────────────────────────────────────────────────────────

UPLOAD_DIR = fileconf.UPLOAD_DIR
MAX_UPLOAD_MB = fileconf.MAX_UPLOAD_MB
ALLOWED_EXTENSIONS = fileconf.ALLOWED_EXTENSIONS
_guess_mime = fileconf.guess_mime

app = Flask(__name__, template_folder="templates", static_folder="static")
def _stable_secret(env_var, filename):
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

app.secret_key = _stable_secret("TERDROP_SECRET", ".user_secret")
app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD_MB * 1024 * 1024
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"]  = "Lax"
app.config["SESSION_COOKIE_SECURE"]    = False   # set True if HTTPS termination
app.config["WTF_CSRF_TIME_LIMIT"]      = None   # unused — custom CSRF system in auth.py
app.config["PERMANENT_SESSION_LIFETIME"] = 28800  # 8 h


# ── Security headers ───────────────────────────────────────────────────────────

@app.after_request
def set_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com; "
        "img-src 'self' data:; "
        "connect-src 'self';"
    )
    return response

# ── Context processor ──────────────────────────────────────────────────────────

@app.context_processor
def inject_globals():
    user = auth.current_user()
    unread = storage.unread_count_for_user(user["id"]) if user else 0
    return dict(
        current_user=user,
        unread_count=unread,
        csrf_token=auth.generate_csrf_token,
        tunnel_url=tunnel.get_url(),
    )

# ── Auth routes ────────────────────────────────────────────────────────────────

@app.route("/", methods=["GET"])
def index():
    user = auth.current_user()
    if user:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))

@app.route("/login", methods=["GET", "POST"])
@auth.csrf_protect
def login():
    def safe_next():
        """Only ever redirect to a relative in-app path — never an absolute
        or protocol-relative URL, which would be an open-redirect vector."""
        n = request.values.get("next", "")
        if n.startswith("/") and not n.startswith("//"):
            return n
        return url_for("dashboard")

    if auth.current_user():
        return redirect(safe_next())

    error = None
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        if storage.is_locked_out(username):
            remaining = storage.lockout_remaining(username)
            error = f"Too many failed attempts. Try again in {remaining}s."
        else:
            user = storage.get_user(username)
            if user and auth.verify_password(user["password_hash"], password):
                if user.get("role") == "admin":
                    # This app is user-only. Admin accounts sign in at the
                    # separate admin panel (port 7777) — never here, even
                    # with correct credentials.
                    storage.clear_attempts(username)
                    error = "Admin accounts sign in at the admin panel, not here."
                elif not user.get("active"):
                    error = "Account disabled."
                elif storage.is_user_expired(user):
                    error = "Account has expired."
                else:
                    storage.clear_attempts(username)
                    auth.login_user(user)
                    return redirect(safe_next())
            else:
                storage.record_attempt(username)
                remaining_tries = storage.MAX_ATTEMPTS - sum(
                    1 for r in storage._read(storage.ATTEMPTS_FILE)
                    if r.get("username") == username
                    and r.get("ts", 0) > time.time() - storage.ATTEMPT_WINDOW
                )
                if remaining_tries > 0:
                    error = f"Invalid credentials. {remaining_tries} attempt(s) remaining."
                else:
                    error = "Too many failed attempts. Account locked temporarily."

    return render_template("login.html", error=error)

@app.route("/logout", methods=["POST"])
@auth.csrf_protect
def logout():
    auth.logout_user()
    return redirect(url_for("login"))

# ── Dashboard ──────────────────────────────────────────────────────────────────

@app.route("/dashboard")
@auth.require_user_only
def dashboard():
    user = g.user

    # This app is user-only — admins never reach this route (blocked at
    # login and by require_user_only), so this always shows the logged-in
    # user's own uploads.
    files = storage.list_files(owner_id=user["id"])

    user_map = {u["id"]: u["username"] for u in storage.list_users()}
    for f in files:
        f["_owner_name"] = user_map.get(f["owner_id"], "?")
        # Display MIME must reflect the ORIGINAL file type, not what's on disk —
        # encrypted files are stored as opaque octet-stream regardless of type.
        f["_display_mime"] = _guess_mime(f["filename"])
        f["_display_size"] = f.get("plaintext_size", f.get("size_bytes", 0))
        f["_uploaded_str"] = time.strftime(
            "%b %d, %Y %H:%M", time.localtime(f.get("uploaded_at", 0))
        )

    return render_template("dashboard.html", files=files, user=user)

# ── Downloads (files shared TO you by the admin) ────────────────────────────────

@app.route("/downloads")
@auth.require_user_only
def downloads():
    user = g.user

    perms = storage.list_user_perms(user["id"])
    file_ids = {p["file_id"] for p in perms if p.get("can_access")}
    files = [storage.get_file(fid) for fid in file_ids]
    files = [f for f in files if f]

    user_map = {u["id"]: u["username"] for u in storage.list_users()}
    for f in files:
        f["_owner_name"] = user_map.get(f["owner_id"], "?")
        f["_display_mime"] = _guess_mime(f["filename"])
        f["_display_size"] = f.get("plaintext_size", f.get("size_bytes", 0))
        f["_uploaded_str"] = time.strftime(
            "%b %d, %Y %H:%M", time.localtime(f.get("uploaded_at", 0))
        )

    return render_template("downloads.html", files=files, user=user)

# ── User settings (notification preference) ─────────────────────────────────────

@app.route("/settings", methods=["GET", "POST"])
@auth.require_user_only
@auth.csrf_protect
def settings_page():
    user = g.user
    success = None

    if request.method == "POST":
        enabled = request.form.get("notifications_enabled") == "on"
        storage.update_user(user["id"], notifications_enabled=enabled)
        user = storage.get_user_by_id(user["id"])
        success = "Preferences saved."

    return render_template("settings.html", user=user, success=success)

# ── File upload ────────────────────────────────────────────────────────────────

@app.route("/upload", methods=["GET", "POST"])
@auth.require_user_only
@auth.csrf_protect
def upload():
    user = g.user
    error = None
    success = None

    # Anyone the uploader could choose to share with right away — everyone
    # except themselves. Regular users can share with each other too; the
    # admin always has access regardless, so isn't listed as a choice.
    grantable_users = [u for u in storage.list_users()
                       if u["id"] != user["id"] and u.get("role") != "admin"]

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

                if ext not in ALLOWED_EXTENSIONS:
                    error = f"File type not allowed: .{ext or 'unknown'}"
                else:
                    is_encrypted = request.form.get("encrypted") == "1"
                    iv_b64          = request.form.get("iv")
                    wrapped_key_b64 = request.form.get("wrapped_key")
                    plaintext_size  = request.form.get("plaintext_size", type=int)

                    stored_name = f"{uuid.uuid4().hex}.{ext}" if ext else uuid.uuid4().hex
                    dest = UPLOAD_DIR / stored_name
                    f.save(str(dest))
                    disk_size = dest.stat().st_size

                    # Stored MIME type reflects what's actually on disk:
                    # ciphertext is always opaque bytes regardless of original type.
                    stored_mime = "application/octet-stream" if is_encrypted else _guess_mime(original_name)

                    record = storage.add_file(
                        owner_id=user["id"],
                        filename=original_name,
                        stored_name=stored_name,
                        size_bytes=disk_size,
                        mime_type=stored_mime,
                        encrypted=is_encrypted,
                        iv=iv_b64 if is_encrypted else None,
                        wrapped_key=wrapped_key_b64 if is_encrypted else None,
                        plaintext_size=plaintext_size if is_encrypted else disk_size,
                    )
                    # The uploader always has access. By default nobody else
                    # does — the admin can always see everything regardless
                    # of any grant (handled in the permission-check routes).
                    storage.grant_permission(user["id"], record["id"])

                    # Optional: share with specific users right at upload time.
                    share_ids = [uid for uid in request.form.getlist("share_with") if uid]
                    valid_ids = {u["id"] for u in grantable_users}
                    share_ids = [uid for uid in share_ids if uid in valid_ids]
                    shared_names = []
                    if share_ids:
                        storage.grant_permission_multi(share_ids, record["id"])
                        id_to_name = {u["id"]: u["username"] for u in grantable_users}
                        shared_names = [id_to_name[uid] for uid in share_ids]

                    lock_note = " 🔒 Encrypted end-to-end." if is_encrypted else ""
                    share_note = f" Shared with {', '.join(shared_names)}." if shared_names else ""
                    success = f"'{original_name}' uploaded successfully.{lock_note}{share_note}"

    return render_template("upload.html", error=error, success=success,
                           max_mb=MAX_UPLOAD_MB,
                           encryption_enabled=storage.is_encryption_enabled(),
                           grantable_users=grantable_users)

# ── Public key endpoint (for client-side encryption) ────────────────────────────

@app.route("/api/public-key")
@auth.require_user_only
def api_public_key():
    return jsonify({
        "public_key_pem": crypto_manager.get_public_key_pem(),
        "fingerprint": crypto_manager.key_fingerprint(),
        "encryption_enabled": storage.is_encryption_enabled(),
    })

@app.route("/api/tunnel-url")
@auth.require_user_only
def api_tunnel_url():
    """Polled by the dashboard to keep the share QR code in sync whenever
    the admin restarts the tunnel (new URL) or stops/starts it."""
    status = tunnel.get_status()
    return jsonify({
        "url": status.get("url"),
        "running": status.get("running", False),
    })

# ── File download ──────────────────────────────────────────────────────────────

@app.route("/download/<file_id>")
@auth.require_user_only
def download(file_id: str):
    user = g.user
    # IDOR guard — validate file_id is a uuid-like string
    if not file_id or len(file_id) > 64 or not file_id.replace("-", "").isalnum():
        abort(400)

    file_rec = storage.get_file(file_id)
    if not file_rec:
        abort(404)

    # This app is user-only — admin never reaches here, so ownership or an
    # explicit grant are the only two ways in.
    is_owner = file_rec["owner_id"] == user["id"]
    if not is_owner and not storage.has_access(user["id"], file_id):
        abort(403)

    # LFI guard — verify stored_name is safe
    stored_name = file_rec["stored_name"]
    if not auth.is_safe_path(str(UPLOAD_DIR), stored_name):
        abort(400)

    path = UPLOAD_DIR / stored_name
    if not path.exists():
        abort(404)

    original_mime = _guess_mime(file_rec["filename"])

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
        response.headers["Content-Disposition"] = (
            f'attachment; filename="{file_rec["filename"]}"'
        )
        return response

    return send_file(
        str(path),
        download_name=file_rec["filename"],
        as_attachment=True,
        mimetype=file_rec.get("mime_type", "application/octet-stream"),
    )

# ── File view (inline for images/pdf) ─────────────────────────────────────────

@app.route("/view/<file_id>")
@auth.require_user_only
def view_file(file_id: str):
    user = g.user
    if not file_id or len(file_id) > 64 or not file_id.replace("-", "").isalnum():
        abort(400)

    file_rec = storage.get_file(file_id)
    if not file_rec:
        abort(404)

    is_owner = file_rec["owner_id"] == user["id"]
    if not is_owner and not storage.has_access(user["id"], file_id):
        abort(403)

    stored_name = file_rec["stored_name"]
    if not auth.is_safe_path(str(UPLOAD_DIR), stored_name):
        abort(400)

    path = UPLOAD_DIR / stored_name
    if not path.exists():
        abort(404)

    original_mime = _guess_mime(file_rec["filename"])

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
        return response

    return send_file(
        str(path),
        mimetype=file_rec.get("mime_type", "application/octet-stream"),
        as_attachment=False,
    )


# ── Chat ───────────────────────────────────────────────────────────────────────

@app.route("/chat", methods=["GET", "POST"])
@auth.require_user_only
@auth.csrf_protect
def chat():
    user = g.user
    error = None

    if request.method == "POST":
        content = request.form.get("message", "").strip()
        content = auth.sanitize_html(content)
        if content and len(content) <= 2000:
            storage.add_message(
                sender_id=user["id"],
                sender_role=user["role"],
                content=content,
                thread_user_id=user["id"],
            )
            notify.notify_admin_new_message(user["username"], content)
        else:
            error = "Message must be 1–2000 characters."

    storage.mark_thread_read(user["id"], "user")
    messages = storage.get_thread(user["id"])
    return render_template("chat.html", messages=messages,
                           user=user, error=error)

# ── Chat polling (AJAX) ────────────────────────────────────────────────────────

@app.route("/chat/poll")
@auth.require_user_only
def chat_poll():
    user = g.user
    since = float(request.args.get("since", 0))
    messages = [m for m in storage.get_thread(user["id"]) if m["timestamp"] > since]
    return jsonify([{
        "id": m["id"],
        "sender_role": m["sender_role"],
        "content": m["content"],
        "timestamp": m["timestamp"],
    } for m in messages])

# ── Error handlers ─────────────────────────────────────────────────────────────

@app.errorhandler(403)
def forbidden(e):
    return render_template("error.html", code=403,
                           msg="Access Forbidden — you don't have permission."), 403

@app.errorhandler(404)
def not_found(e):
    return render_template("error.html", code=404,
                           msg="File or page not found."), 404

@app.errorhandler(413)
def too_large(e):
    return render_template("error.html", code=413,
                           msg=f"File too large. Maximum size: {MAX_UPLOAD_MB} MB"), 413

@app.errorhandler(500)
def server_error(e):
    return render_template("error.html", code=500,
                           msg="Internal server error. Please try again."), 500

# ── Run ────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False, threaded=True)
