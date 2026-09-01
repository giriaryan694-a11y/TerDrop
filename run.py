"""
TerDrop Launcher
Starts:
  - User app  → 127.0.0.1:5000  (reachable ONLY via the Cloudflare tunnel —
                                  never exposed on the local network directly)
  - Admin app → 127.0.0.1:7777  (local only, NEVER tunneled)
  - Cloudflare tunnel → tunnels port 5000 only

Usage:
  python run.py [--no-tunnel] [--port 5000] [--admin-port 7777]
"""

import argparse
import os
import sys
import threading
import time

# ── Bootstrap default admin + encryption keys ───────────────────────────────────

def bootstrap():
    """Create default admin account and RSA keypair if they don't exist yet."""
    import storage, auth, crypto_manager

    # RSA keypair for client-side hybrid encryption (generated once, reused forever)
    keys_were_missing = not crypto_manager.keys_exist()
    if keys_were_missing:
        crypto_manager.generate_keypair()

    admins = [u for u in storage.list_users() if u.get("role") == "admin"]
    admin_was_missing = not admins

    if admin_was_missing:
        default_user = os.environ.get("ADMIN_USER", "admin")
        default_pass = os.environ.get("ADMIN_PASS", "ChangeMe123!")
        ph = auth.hash_password(default_pass)
        storage.create_user(default_user, ph, role="admin")

    if admin_was_missing or keys_were_missing:
        print("""
╔══════════════════════════════════════════════════╗
║              TerDrop — First Run                  ║
╠══════════════════════════════════════════════════╣""")
        if admin_was_missing:
            print(f"""║  Default admin created:                           ║
║    Username : {default_user:<37}║
║    Password : {default_pass:<37}║
║                                                    ║
║  ⚠  CHANGE THIS PASSWORD IMMEDIATELY               ║""")
        if keys_were_missing:
            fp = crypto_manager.key_fingerprint()
            print(f"""║  Encryption keypair generated (RSA-3072):         ║
║    Fingerprint : {fp:<34}║
║    Private key never leaves this device.          ║""")
        print("""╠══════════════════════════════════════════════════╣
║  Made by Aryan Giri · giriaryan694-a11y            ║
╚══════════════════════════════════════════════════╝
""")

# ── Cleanup thread ─────────────────────────────────────────────────────────────

def cleanup_loop():
    import storage
    while True:
        try:
            storage.cleanup_old_attempts()
        except Exception:
            pass
        time.sleep(300)  # every 5 min

# ── Main ───────────────────────────────────────────────────────────────────────

BANNER = r"""
  ████████╗███████╗██████╗ ██████╗ ██████╗  ██████╗ ██████╗
  ╚══██╔══╝██╔════╝██╔══██╗██╔══██╗██╔══██╗██╔═══██╗██╔══██╗
     ██║   █████╗  ██████╔╝██║  ██║██████╔╝██║   ██║██████╔╝
     ██║   ██╔══╝  ██╔══██╗██║  ██║██╔══██╗██║   ██║██╔═══╝
     ██║   ███████╗██║  ██║██████╔╝██║  ██║╚██████╔╝██║
     ╚═╝   ╚══════╝╚═╝  ╚═╝╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚═╝

  Privacy-first secure file sharing — locally deployable, Cloudflare-tunneled
  Made by Aryan Giri  |  github.com/giriaryan694-a11y
  ─────────────────────────────────────────────────────────────────────────────
"""

def main():
    print(BANNER)
    parser = argparse.ArgumentParser(description="TerDrop File Sharing")
    parser.add_argument("--no-tunnel", action="store_true", help="Skip Cloudflare tunnel")
    parser.add_argument("--port",       type=int, default=5000)
    parser.add_argument("--admin-port", type=int, default=7777)
    args = parser.parse_args()

    bootstrap()

    # Start background cleanup
    t_clean = threading.Thread(target=cleanup_loop, daemon=True)
    t_clean.start()

    # Start Cloudflare tunnel (non-blocking)
    if not args.no_tunnel:
        import tunnel
        print("[*] Starting Cloudflare tunnel…")
        t_tun = threading.Thread(
            target=tunnel.start, kwargs={"port": args.port}, daemon=True
        )
        t_tun.start()

    # Start admin app in background thread
    import admin_app
    def run_admin():
        admin_app.admin_app.run(
            host="127.0.0.1",
            port=args.admin_port,
            debug=False,
            threaded=True,
            use_reloader=False,
        )
    t_admin = threading.Thread(target=run_admin, daemon=True)
    t_admin.start()

    import storage
    enc_state = "ON 🔒" if storage.is_encryption_enabled() else "OFF 🔓"

    print(f"  [*] Admin panel  → http://127.0.0.1:{args.admin_port}   (localhost only)")
    print(f"  [*] User app     → http://127.0.0.1:{args.port}   (localhost only — tunnel is the only public path)")
    print(f"  [*] Encryption   → {enc_state}")
    print(f"  [*] Made by Aryan Giri | github.com/giriaryan694-a11y")
    print(f"  {'─' * 55}")

    # Start user app (blocking — main thread)
    import app as user_app
    user_app.app.run(
        host="127.0.0.1",
        port=args.port,
        debug=False,
        threaded=True,
        use_reloader=False,
    )

if __name__ == "__main__":
    main()
