"""
TerDrop Tunnel Manager
Manages the cloudflared quick-tunnel subprocess.
Parses the public URL from stdout and allows hot-restart from the admin panel.
"""

import re
import shutil
import subprocess
import threading
import time
import os
from pathlib import Path

_proc: subprocess.Popen | None = None
_url:  str | None = None
_lock  = threading.Lock()
_log_lines: list[str] = []
_MAX_LOG = 200

URL_RE = re.compile(r"https://[a-z0-9\-]+\.trycloudflare\.com", re.IGNORECASE)
STATUS = {"running": False, "url": None, "started_at": None, "pid": None}


def _reader(proc: subprocess.Popen):
    """Background thread: read cloudflared output and extract URL."""
    global _url
    for raw in proc.stderr:
        line = raw.strip()
        if line:
            _log_lines.append(line)
            if len(_log_lines) > _MAX_LOG:
                _log_lines.pop(0)
        match = URL_RE.search(line)
        if match:
            with _lock:
                _url = match.group(0)
                STATUS["url"] = _url
            print(f"[tunnel] Public URL → {_url}")


def start(port: int = 5000) -> bool:
    """Start cloudflared tunnel to localhost:{port}. Returns True on success."""
    global _proc, _url

    if not shutil.which("cloudflared"):
        print("[tunnel] cloudflared binary not found in PATH")
        STATUS["running"] = False
        STATUS["url"] = None
        return False

    with _lock:
        if _proc and _proc.poll() is None:
            return True   # already running

        _url = None
        STATUS["url"] = None

        try:
            _proc = subprocess.Popen(
                ["cloudflared", "tunnel", "--url", f"http://127.0.0.1:{port}"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
            )
            STATUS["running"] = True
            STATUS["started_at"] = time.time()
            STATUS["pid"] = _proc.pid
        except Exception as e:
            print(f"[tunnel] Failed to start: {e}")
            STATUS["running"] = False
            return False

    # Start reader thread
    t = threading.Thread(target=_reader, args=(_proc,), daemon=True)
    t.start()

    # Wait up to 20s for URL
    deadline = time.time() + 20
    while time.time() < deadline:
        if _url:
            return True
        time.sleep(0.5)

    print("[tunnel] Timed out waiting for URL")
    return _proc and _proc.poll() is None


def stop():
    """Kill the cloudflared process."""
    global _proc, _url
    with _lock:
        if _proc:
            try:
                _proc.terminate()
                _proc.wait(timeout=5)
            except Exception:
                try:
                    _proc.kill()
                except Exception:
                    pass
            _proc = None
        _url = None
        STATUS["running"] = False
        STATUS["url"] = None
        STATUS["pid"] = None


def restart(port: int = 5000) -> bool:
    """Stop current tunnel and start fresh (new URL)."""
    stop()
    time.sleep(1)
    return start(port)


def get_url() -> str | None:
    return STATUS.get("url")


def get_status() -> dict:
    if _proc:
        STATUS["running"] = _proc.poll() is None
        if not STATUS["running"]:
            STATUS["url"] = None
            STATUS["pid"] = None
    return dict(STATUS)


def get_log() -> list[str]:
    return list(_log_lines[-50:])


def is_running() -> bool:
    return bool(_proc and _proc.poll() is None)
