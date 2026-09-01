# 📦 TerDrop

> **Privacy-first, end-to-end encrypted file sharing — built for Termux.**
> Locally deployable, Cloudflare-tunneled, no SQL, no cloud accounts.

**Made by Aryan Giri · [giriaryan694-a11y](https://github.com/giriaryan694-a11y)**

---

## What is TerDrop?

TerDrop is a self-hosted file sharing and messaging tool that runs entirely on your Android device via Termux. You share files securely with specific people through a temporary Cloudflare public URL — no third-party storage, no accounts on external services, no data leaving your device unencrypted.

Files are **encrypted in the user's browser before upload** using AES-256-GCM + RSA-OAEP hybrid encryption. Even Cloudflare only ever sees ciphertext.

---

## Why TerDrop? Real situations it solves

Most file sharing involves one of these awkward moments:

- "Send me your number so I can WhatsApp it to you"
- "Download this app first" ← they won't, and now you both feel weird
- "Just email it to me" ← it's 400 MB
- "I'll AirDrop it" ← you're on Android, they're on Android
- Uploading to Google Drive and fiddling with share permissions for 5 minutes in front of someone

TerDrop solves all of these with a QR code scan.

### 📚 College / university

You want to share notes, assignments, lab reports, or project files with a classmate. You don't want to share your phone number with someone you barely know. You definitely don't want to ask them to install a new app — that conversation is awkward and often just doesn't happen. You open TerDrop, upload the file, they scan the QR code on your screen with their phone camera, open the link in a browser, done. **No app install. No account creation on their side. No phone number exchanged. No suspicion.**

Works in the opposite direction too — they want to send you something. You create them a temporary account (expires in 20 minutes), they scan the QR, log in, upload. The file lands on your device, encrypted.

### 🏢 Office / workplace

Sharing files with a colleague from a different department or company network, where emailing large files gets blocked by IT, cloud storage isn't approved, USB drives aren't allowed, and you don't want to use personal accounts. TerDrop runs on your phone's mobile data — completely outside the corporate network — and the recipient just needs a browser.

### 🎓 Exam season / group projects

Your study group needs to exchange handwritten notes scanned as PDFs, diagrams, or code files. Passing a USB around a library is conspicuous. WhatsApp compresses images. TerDrop gives everyone in the group their own account, they upload their contributions, everyone can download what they need. Encrypted in transit so the library Wi-Fi can't sniff anything.

### 🛡️ When you just don't trust the middle

WhatsApp, Google Drive, WeTransfer, Telegram — every one of these is a company with servers, subpoenas, and privacy policies. TerDrop's server is **your phone in your pocket**. The only people who can read the files are people you explicitly granted access to, using an encryption key that never leaves your device.

### 🚀 Zero setup for the other person

This is the key point: **the recipient needs nothing except a browser.** No app install. No account on a third-party service. No asking them to sign up for anything. You send them a link (or show them a QR code), they open it, they log in with the credentials you give them, and they're done. That's as frictionless as file sharing gets without giving up privacy.

---

## Quick Start (Termux)

```bash
# 1. Install dependencies
pkg update && pkg upgrade -y
pkg install python cloudflared -y
pip install flask flask-wtf argon2-cffi cryptography

# 2. git clone
git clone https://github.com/giriaryan694-a11y/TerDrop
cd TerDrop

# 3. Run
python run.py
```

On **first run** a default admin account is created and an RSA keypair is generated:

```
╔══════════════════════════════════════════════════╗
║              TerDrop — First Run                  ║
╠══════════════════════════════════════════════════╣
║  Default admin created:                           ║
║    Username : admin                                ║
║    Password : ChangeMe123!                         ║
║  Encryption keypair generated (RSA-3072)          ║
╚══════════════════════════════════════════════════╝
```

> ⚠️ **Change the default password immediately** via the admin panel.

---

## Accessing TerDrop

| Interface | URL | Who can reach it |
|---|---|---|
| **User app** | `http://127.0.0.1:5000` | Only through the Cloudflare tunnel (public URL shown in terminal) |
| **Admin panel** | `http://127.0.0.1:7777` | Localhost only — your Termux device |

The terminal shows the public Cloudflare URL on startup. Share that with users.

---

## CLI Options

```bash
# Skip Cloudflare tunnel (offline/LAN only mode)
python run.py --no-tunnel

# Custom ports
python run.py --port 8080 --admin-port 8888

# Override default credentials via environment
ADMIN_USER=myname ADMIN_PASS=MyPass123 python run.py

# Set a persistent session secret (sessions survive restarts)
TERDROP_SECRET=your-long-random-secret python run.py
```

---

## Features

### Security
| Feature | Detail |
|---|---|
| **End-to-end encryption** | AES-256-GCM (file) + RSA-OAEP 3072-bit (key wrapping). Encryption happens in the browser — server stores only ciphertext |
| **Argon2id passwords** | OWASP-recommended params: 64 MB RAM, 3 iterations. Hashes stored in `data/users.txt` |
| **CSRF protection** | Custom per-session tokens on every state-changing form |
| **Brute-force protection** | Per-username lockout (5 attempts / 10 min). Does NOT key on IP — behind the Cloudflare tunnel, every visitor shares the same apparent IP (`127.0.0.1`), so IP-based lockout would lock out the entire site |
| **XSS protection** | HTML escaping on all user content + Content-Security-Policy headers |
| **LFI / path traversal** | Filenames sanitized, `realpath()` guard before every file serve |
| **IDOR protection** | Permission freshly checked on every download/view request |
| **Security headers** | X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy |
| **Admin isolation** | Admin panel (`before_request`) hard-rejects any non-localhost request |

### File Sharing
- Upload files up to 100 MB (images, video, audio, PDF, ZIP, docs)
- Files you upload are **only visible to you and the admin** by default — nobody else can see or download them until the admin explicitly shares
- Admin grants access per-file to one or more users, optionally with an expiry timer
- **My Files** page — your own uploads
- **Downloads** page — files the admin has shared with you
- Server-side decryption on download — authorized users always receive the original plaintext regardless of encryption state

### Admin Panel (`:7777`)
- **Users** — create (role: user always), edit (password, username, expiry, quota, enable/disable), delete
- **Files** — see all uploads, manage permissions (multi-user grant), delete files
- **Chat** — reply to user threads; unread badge in sidebar
- **Tunnel Control** — start, stop, restart cloudflared (generates a new public URL on restart). Live log output. QR code that updates automatically
- **Encryption** — toggle encryption on/off globally, view RSA key fingerprint, rotate keypair (⚠️ destroys access to existing encrypted files)
- **Notifications** — toggle Termux native notifications for new chat messages

### User Features
- Upload files (encrypted automatically when encryption is enabled)
- Download / view files shared by admin
- Chat with admin; real-time browser notifications via service worker (works on mobile Chrome/Android — uses `ServiceWorkerRegistration.showNotification()`, not the broken `new Notification()` constructor)
- Settings page — grant browser notification permission
- QR code on dashboard showing the current public URL, updates live
- **PWA installable** — "Add to Home Screen" on Android Chrome gives a standalone app experience

---

## How Encryption Works

```
Browser                              Server (your Termux device)
───────────────────────────────────────────────────────────────
1. Fetch RSA public key  ──────────► /api/public-key
                          ◄────────── PEM string

2. Generate random AES-256-GCM key (in browser memory only)

3. Encrypt file bytes with AES key + random 12-byte IV
   → ciphertext blob

4. Wrap AES key with RSA-OAEP public key
   → wrapped_key (base64)

5. Upload: ciphertext + iv + wrapped_key ──────────────────────►
                                           Stored as-is on disk
                                           (server sees no plaintext)

Download:
◄─────── Server unwraps AES key with RSA PRIVATE key,
         decrypts file, streams plaintext to authorized user
```

- **Cloudflare sees only ciphertext** — even if Cloudflare were to inspect tunnel traffic, no file contents are readable
- The RSA private key never leaves `keys/private_key.pem` on your device
- Key fingerprint is shown on first run and in the admin Encryption page for verification

---

## Data Storage (No SQL)

All data is stored as JSON-line `.txt` files in `data/`. One record per line.

```
data/
├── users.txt       # accounts (Argon2id hashes, expiry, quota)
├── files.txt       # file metadata (name, size, encrypted flag, IV, wrapped key)
├── perms.txt       # who has access to which file (+ optional expiry)
├── chats.txt       # chat messages per user thread
├── sessions.txt    # active login sessions (UUID tokens, 8h TTL)
├── attempts.txt    # failed login attempts for brute-force tracking
└── settings.txt    # global settings (encryption on/off, notifications)
```

---

## Project Structure

```
ghostdrop/
├── run.py              # Launcher — starts both apps + tunnel
├── app.py              # User-facing Flask app (port 5000)
├── admin_app.py        # Admin Flask app (port 7777, localhost-only)
├── auth.py             # Argon2id, CSRF, session, sanitizers
├── storage.py          # TXT-file database layer
├── tunnel.py           # cloudflared subprocess manager
├── crypto_manager.py   # RSA keypair generation + server-side decryption
├── notify.py           # Termux notification wrapper (best-effort)
├── requirements.txt
│
├── data/               # Auto-created on first run (git-ignored)
├── uploads/            # Stored files — UUID-named (git-ignored)
├── keys/               # RSA private + public key PEM files (git-ignored)
│
├── static/
│   ├── css/style.css         # Full design system (dark/light/eye-saver themes)
│   ├── js/app.js             # Theme, sidebar, tunnel QR, chat notifier, SW bridge
│   ├── js/crypto.js          # Web Crypto API: AES-GCM + RSA-OAEP hybrid encryption
│   ├── js/qrcode.min.js      # Vendored QR library (local — CSP blocks CDN)
│   ├── manifest.json         # PWA manifest
│   ├── sw.js                 # Service worker (installability + notifications)
│   └── icons/                # PWA icons (192px, 512px, 512px maskable)
│
└── templates/
    ├── base.html / login.html / dashboard.html
    ├── downloads.html / upload.html / chat.html / settings.html / error.html
    └── admin/
        ├── admin_base.html / admin_login.html / admin_dashboard.html
        ├── admin_users.html / admin_create_user.html / admin_edit_user.html
        ├── admin_files.html / admin_perms.html
        ├── admin_chat_list.html / admin_chat_thread.html
        ├── admin_tunnel.html / admin_encryption.html
        └── admin_notifications.html / admin_error.html
```
---

## Themes

Click the theme buttons in the top-right of any page:

| 🌙 Dark | ☀️ Light | 🍯 Eye-Saver |
|---|---|---|
| Dark navy (default) | Clean white | Warm amber — easy on eyes at night |

Theme is saved in `localStorage` and persists across sessions.

---

## Notifications

### Admin (Termux native notifications)
Requires the **Termux:API** app + package:

```bash
pkg install termux-api
# Then grant notification permission to Termux:API in Android settings
```

Toggle in admin panel → **Notifications**. Fires a native Android notification whenever a user sends a chat message, even while Termux is backgrounded.

### Users (browser notifications)
Users enable browser notifications from their **Settings** page. A permission prompt appears in the browser. Once granted, they receive a notification when the admin replies to their chat, even while browsing other pages in the app.

> **Technical note:** Uses `ServiceWorkerRegistration.showNotification()` instead of `new Notification()`. The constructor throws `Illegal constructor` on virtually all mobile browsers (Chrome/Android especially) — the service worker bridge is the only reliable path on mobile.

---

## Admin Workflow

### Share a file with users

1. Open **Upload a File** from the admin dashboard (opens the user app in a new tab — sign in once with your admin credentials, you'll land straight on the upload page)
2. Upload the file (encrypted automatically if encryption is on)
3. Come back to the admin panel → **Files** → click **🔐 Perms** next to the file
4. Check the users you want to share with, set an optional expiry, click **Share Selected**

### Create a temporary access account

1. Admin panel → **Users** → **➕ New User**
2. Set username, password, and **Account Expires In** (e.g. `20` for 20 minutes)
3. Share the public URL (from QR code or terminal) + credentials with the person
4. Their account auto-expires — no manual cleanup needed

### Change your admin password

1. Open `http://127.0.0.1:7777` → **Users** → **✏️ Edit** next to your admin account
2. **Change Password** → enter new password → **Update Password**

Or from the command line (if locked out):

```bash
python3 -c "
import storage, auth
u = storage.get_user('admin')
storage.update_user(u['id'], password_hash=auth.hash_password('NewPassword123!'))
storage.delete_user_sessions(u['id'])
print('Done')
"
```

---

## Limitations

- **Single-device**: designed to run on one Termux session. No horizontal scaling.
- **No persistent Cloudflare domain**: quick tunnels get a random URL each session. Restart the tunnel → new URL → re-share with users. Use a named tunnel with a custom domain for a stable URL (requires a Cloudflare account).
- **Memory-bounded decryption**: server decrypts the full file into RAM before streaming. Files near the 100 MB limit may be slow on low-memory devices.
- **TXT-file database**: works well for personal/small-team use. Not designed for hundreds of concurrent writes.

---

## License

MIT — use freely, attribution appreciated.

**TerDrop · Made by Aryan Giri · [github.com/giriaryan694-a11y](https://github.com/giriaryan694-a11y)**
