"""
TerDrop Crypto Module
Manages the server's RSA-OAEP keypair used for the hybrid encryption scheme.

Design:
  - Browser generates a random AES-256-GCM key per file upload.
  - Browser encrypts the file bytes with that AES key (AES-GCM, random 12-byte IV).
  - Browser wraps (encrypts) the AES key itself with the server's RSA-OAEP
    PUBLIC key (fetched from /api/public-key). This is the ONLY key ever
    transmitted to the browser — the private key never leaves the server.
  - Server stores: ciphertext, iv, wrapped_key (base64) — never the plaintext
    file or the AES key.
  - Only holders of the RSA PRIVATE key (this server / the admin operating it)
    can unwrap the AES key and decrypt the file. Cloudflare, the tunnel, and
    any network observer see only ciphertext.

Keys are generated once on first run and persisted to disk so encrypted
files remain decryptable across restarts.
"""

import base64
import json
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

KEYS_DIR = Path(__file__).parent / "keys"
KEYS_DIR.mkdir(exist_ok=True)

PRIVATE_KEY_PATH = KEYS_DIR / "private_key.pem"
PUBLIC_KEY_PATH  = KEYS_DIR / "public_key.pem"

RSA_KEY_SIZE = 3072  # OWASP-recommended minimum for long-term security (2024+)


# ── Keypair lifecycle ───────────────────────────────────────────────────────────

def keys_exist() -> bool:
    return PRIVATE_KEY_PATH.exists() and PUBLIC_KEY_PATH.exists()


def generate_keypair(overwrite: bool = False) -> None:
    """Generate a fresh RSA keypair and persist to disk (PEM, unencrypted).

    The private key file is written with 0600 permissions on POSIX systems
    (Termux included) so only the owning user can read it.
    """
    if keys_exist() and not overwrite:
        return

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=RSA_KEY_SIZE,
    )
    public_key = private_key.public_key()

    priv_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    PRIVATE_KEY_PATH.write_bytes(priv_pem)
    PUBLIC_KEY_PATH.write_bytes(pub_pem)

    try:
        os_chmod_600(PRIVATE_KEY_PATH)
    except Exception:
        pass  # best-effort — Windows/Termux edge cases


def os_chmod_600(path: Path):
    import os
    os.chmod(str(path), 0o600)


def get_public_key_pem() -> str:
    """Return the public key as a PEM string, for the browser to fetch."""
    if not keys_exist():
        generate_keypair()
    return PUBLIC_KEY_PATH.read_text()


def _load_private_key():
    if not keys_exist():
        generate_keypair()
    pem = PRIVATE_KEY_PATH.read_bytes()
    return serialization.load_pem_private_key(pem, password=None)


def _load_public_key():
    if not keys_exist():
        generate_keypair()
    pem = PUBLIC_KEY_PATH.read_bytes()
    return serialization.load_pem_public_key(pem)


def rotate_keypair() -> None:
    """Generate a brand-new keypair. Old encrypted files become undecryptable —
    caller should warn the admin before invoking this."""
    generate_keypair(overwrite=True)


# ── Decryption (server / admin side only) ───────────────────────────────────────

def unwrap_aes_key(wrapped_key_b64: str) -> bytes:
    """RSA-OAEP decrypt the wrapped AES key using the server's private key."""
    private_key = _load_private_key()
    wrapped = base64.b64decode(wrapped_key_b64)
    aes_key = private_key.decrypt(
        wrapped,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    return aes_key


def decrypt_file(ciphertext: bytes, iv_b64: str, wrapped_key_b64: str) -> bytes:
    """Full hybrid decryption: unwrap AES key via RSA, then AES-GCM decrypt."""
    aes_key = unwrap_aes_key(wrapped_key_b64)
    iv = base64.b64decode(iv_b64)
    aesgcm = AESGCM(aes_key)
    plaintext = aesgcm.decrypt(iv, ciphertext, None)
    return plaintext


# ── Key fingerprint (for UI display / verification) ──────────────────────────────

def key_fingerprint() -> str:
    """Short SHA-256 fingerprint of the public key, for admin UI display."""
    import hashlib
    if not keys_exist():
        generate_keypair()
    pub_bytes = PUBLIC_KEY_PATH.read_bytes()
    digest = hashlib.sha256(pub_bytes).hexdigest()
    return ":".join(digest[i:i+4] for i in range(0, 16, 4)).upper()
