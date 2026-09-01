"""
TerDrop Shared File Config
Constants and helpers used identically by both the user app (app.py) and
the admin app (admin_app.py) for upload/download handling. Kept in one
place so the two apps' file-handling logic can never silently drift apart.
"""

import mimetypes
from pathlib import Path

UPLOAD_DIR = Path(__file__).parent / "uploads"
UPLOAD_DIR.mkdir(exist_ok=True)

MAX_UPLOAD_MB = 100

# Extension-based allowlist. Encrypted uploads arrive as opaque ciphertext
# (always application/octet-stream), so MIME sniffing is unreliable — the
# original filename's extension is the only trustworthy signal available
# either way, encrypted or not.
ALLOWED_EXTENSIONS = {
    # images
    "jpg", "jpeg", "png", "gif", "webp", "svg", "bmp", "heic",
    # video
    "mp4", "mov", "avi", "mkv", "webm",
    # audio
    "mp3", "wav", "ogg", "flac", "m4a",
    # documents
    "pdf", "txt", "md", "csv", "json", "doc", "docx", "xls", "xlsx", "ppt", "pptx",
    # archives
    "zip", "gz", "tar", "7z", "rar",
}


def guess_mime(filename: str) -> str:
    return mimetypes.guess_type(filename)[0] or "application/octet-stream"
