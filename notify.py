"""
TerDrop Notifications
Sends Android notifications via `termux-notification` (part of the
Termux:API app + `termux-api` package). Entirely best-effort: if the
binary isn't installed, or the Termux:API app isn't granted notification
permission, calls silently no-op rather than raising or blocking the
request that triggered them.

This never touches the browser — it's a native Android notification
fired from the Termux process itself, so it works even when no browser
tab is open.
"""

import shutil
import subprocess
import threading

_binary_path = None
_checked = False
_lock = threading.Lock()


def _has_termux_notification() -> bool:
    global _binary_path, _checked
    if _checked:
        return _binary_path is not None
    with _lock:
        if not _checked:
            _binary_path = shutil.which("termux-notification")
            _checked = True
    return _binary_path is not None


def is_available() -> bool:
    """Whether termux-notification is installed and callable."""
    return _has_termux_notification()


def send(title: str, content: str, notif_id: str | None = None,
         priority: str = "default") -> bool:
    """
    Fire a Termux notification. Runs in a background thread so a slow or
    hanging termux-api call never delays the HTTP response that triggered it.

    notif_id: stable id — reusing it updates/replaces the same notification
              instead of stacking duplicates (e.g. one id per chat thread).
    Returns True if the send was dispatched (not a guarantee of delivery —
    Termux:API delivery is fire-and-forget).
    """
    if not _has_termux_notification():
        return False

    def _fire():
        try:
            cmd = ["termux-notification",
                   "--title", title,
                   "--content", content,
                   "--priority", priority]
            if notif_id:
                cmd += ["--id", str(notif_id)]
            subprocess.run(cmd, timeout=5,
                          stdout=subprocess.DEVNULL,
                          stderr=subprocess.DEVNULL)
        except Exception:
            pass  # best-effort — never let a notification failure surface

    threading.Thread(target=_fire, daemon=True).start()
    return True


def notify_admin_new_message(username: str, preview: str):
    """Called when a user sends a chat message — notifies the Termux operator."""
    import storage
    if not storage.get_settings().get("admin_notifications_enabled", True):
        return
    preview = preview[:120]
    send(
        title=f"💬 TerDrop — {username}",
        content=preview,
        notif_id="terdrop_admin_chat",
        priority="high",
    )


def notify_user_new_message(preview: str):
    """
    Called when the admin replies to a user's chat thread.
    NOTE: this only fires meaningfully if the user is themselves running
    this on their own Termux session (e.g. a self-hosted client) — for a
    typical remote user connecting via the tunneled web UI, browser-side
    notifications (see notify.js) are what actually reaches them. This
    hook exists for symmetry and for same-device admin+user setups.
    """
    preview = preview[:120]
    send(
        title="💬 New message from Admin",
        content=preview,
        notif_id="terdrop_user_chat",
        priority="high",
    )
